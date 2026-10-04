//! NyaPassword server library (the binary is a thin CLI around it; the
//! integration tests drive it directly).

pub mod account;
pub mod admin;
pub mod auth;
pub mod backup;
pub mod config;
pub mod db;
pub mod error;
pub mod events;
pub mod items;
pub mod restore;
pub mod state;
pub mod web;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post, put};
use axum::Router;
use tokio::sync::{broadcast, Notify};

use crate::config::Config;
use crate::state::{AppState, Limiter, ServerKeys, Shared};

pub fn open_state(cfg: Config) -> anyhow::Result<Shared> {
    std::fs::create_dir_all(&cfg.data_dir)?;
    std::fs::create_dir_all(cfg.attachments_dir())?;
    std::fs::create_dir_all(cfg.tmp_dir())?;
    let mut conn = db::open(&cfg.db_path())?;
    db::migrate(&mut conn)?;
    let keys = ServerKeys::load_or_create(&cfg.key_path())?;
    let opaque_setup = match db::get_setting(&conn, "opaque_setup")? {
        Some(v) => npw_crypto::unb64(&v).ok_or_else(|| anyhow::anyhow!("corrupt opaque_setup"))?,
        None => {
            let s = npw_crypto::opaque::server_setup_new();
            db::set_setting(&conn, "opaque_setup", &npw_crypto::b64(&s))?;
            s
        }
    };
    let epoch = match db::get_setting(&conn, "epoch")? {
        Some(e) => e,
        None => {
            let e = uuid::Uuid::now_v7().to_string();
            db::set_setting(&conn, "epoch", &e)?;
            e
        }
    };
    if let Ok(pw) = std::env::var("NYAPASSWORD_ADMIN_PASSWORD") {
        if !pw.is_empty() && db::get_setting(&conn, admin::PASSWORD_KEY)?.is_none() {
            admin::set_password(&conn, &pw)?;
        }
    }
    let (events, _) = broadcast::channel(1024);
    Ok(Arc::new(AppState {
        cfg,
        db: db::Db::new(conn),
        keys,
        opaque_setup,
        epoch,
        events,
        limiter: Limiter::default(),
        admin_sessions: Mutex::new(Default::default()),
        started_at: db::now_ms(),
        changed: Arc::new(Notify::new()),
        last_change_at: Mutex::new(0),
        backup_lock: tokio::sync::Mutex::new(()),
    }))
}

pub fn router(st: Shared) -> Router {
    let max_att = (st.cfg.max_attachment_mb as usize) * 1024 * 1024 + 64 * 1024;
    let api = Router::new()
        .route("/v1/server-info", get(auth::server_info))
        .route("/v1/health", get(|| async { "ok" }))
        .route("/v1/auth/register/start", post(auth::register_start))
        .route("/v1/auth/register/finish", post(auth::register_finish))
        .route("/v1/auth/prelogin", post(auth::prelogin))
        .route("/v1/auth/login/start", post(auth::login_start))
        .route("/v1/auth/login/finish", post(auth::login_finish))
        .route("/v1/auth/refresh", post(auth::refresh))
        .route("/v1/auth/logout", post(auth::logout))
        .route("/v1/account", get(account::get_account))
        .route("/v1/account/password/start", post(account::password_start))
        .route(
            "/v1/account/password/finish",
            post(account::password_finish),
        )
        .route("/v1/account/audit", get(account::audit_log))
        .route("/v1/vaults", post(account::create_vault))
        .route("/v1/vaults/{vault}/meta", put(account::update_vault_meta))
        .route("/v1/vaults/{vault}/changes", get(items::changes))
        .route(
            "/v1/vaults/{vault}/items/batch",
            post(items::push).layer(DefaultBodyLimit::max(128 * 1024 * 1024)),
        )
        .route("/v1/vaults/{vault}/digest", get(items::digest))
        .route(
            "/v1/vaults/{vault}/items/{item}/revisions",
            get(items::revisions),
        )
        .route(
            "/v1/vaults/{vault}/items/{item}/revisions/{rev}",
            get(items::revision),
        )
        .route("/v1/vaults/{vault}/purge", post(items::purge))
        .route(
            "/v1/vaults/{vault}/attachments/{att}",
            put(items::put_attachment)
                .get(items::get_attachment)
                .layer(DefaultBodyLimit::max(max_att)),
        )
        .route("/v1/devices", get(account::devices))
        .route("/v1/devices/{device}", delete(account::revoke_device))
        .route("/v1/events", get(events::events))
        .route("/v1/admin/login", post(admin::login))
        .route("/v1/admin/health", get(admin::health))
        .route("/v1/admin/accounts", get(admin::accounts))
        .route("/v1/admin/devices/{device}", delete(admin::revoke_device))
        .route(
            "/v1/admin/invites",
            get(admin::invites).post(admin::new_invite),
        )
        .route("/v1/admin/audit", get(admin::audit))
        .route("/v1/admin/backup", get(admin::backup_status))
        .route("/v1/admin/backup/settings", put(admin::put_settings))
        .route(
            "/v1/admin/backup/targets/{id}",
            put(admin::put_target).delete(admin::delete_target),
        )
        .route(
            "/v1/admin/backup/targets/{id}/test",
            post(admin::test_target),
        )
        .route(
            "/v1/admin/backup/targets/{id}/objects",
            get(admin::target_objects),
        )
        .route("/v1/admin/backup/run", post(admin::run_now))
        .route("/v1/admin/backup/drill", post(admin::drill))
        .route(
            "/v1/admin/backup/manual-drill",
            post(admin::manual_drill_done),
        )
        .route("/v1/admin/notify/test", post(admin::test_notify));
    api.fallback(web::static_handler).with_state(st)
}

pub async fn serve(st: Shared) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(st.cfg.listen).await?;
    serve_on(st, listener, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

/// Serves on an already bound listener until `shutdown` completes.
pub async fn serve_on(
    st: Shared,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let listen = listener.local_addr()?;
    let sched = tokio::spawn(backup::scheduler(st.clone()));
    let app = router(st).layer(tower_http::trace::TraceLayer::new_for_http());
    tracing::info!(
        "NyaPassword server {} listening on {listen}",
        env!("CARGO_PKG_VERSION")
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;
    sched.abort();
    Ok(())
}
