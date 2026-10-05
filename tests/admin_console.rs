//! The admin console's API additions: offline recovery keys with labels,
//! per-channel notification tests, testing a target before saving it, and
//! the admin's own password and TOTP.

mod common;

use common::TestServer;
use nyapassword_server::{admin, backup};
use serde_json::{json, Value};

async fn call(
    url: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (u16, Value) {
    let c = reqwest::Client::new();
    let mut rb = c.request(
        reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
        format!("{url}{path}"),
    );
    if let Some(t) = token {
        rb = rb.bearer_auth(t);
    }
    if let Some(b) = body {
        rb = rb.json(&b);
    }
    let r = rb.send().await.unwrap();
    let status = r.status().as_u16();
    let bytes = r.bytes().await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

const PW: &str = "admin password 123";
const NEW_PW: &str = "a brand new admin password";

async fn admin_login(srv: &TestServer, password: &str, totp: Option<String>) -> (u16, String) {
    let (s, r) = call(
        &srv.url,
        "POST",
        "/v1/admin/login",
        None,
        Some(json!({ "password": password, "totp": totp })),
    )
    .await;
    (s, r["token"].as_str().unwrap_or_default().to_string())
}

async fn start() -> (TestServer, String) {
    let srv = TestServer::start().await;
    srv.state
        .db
        .run_sync(|c| Ok(admin::set_password(c, PW)?))
        .unwrap();
    let (s, token) = admin_login(&srv, PW, None).await;
    assert_eq!(s, 200);
    (srv, token)
}

fn stored_settings(srv: &TestServer) -> npw_api::admin::BackupSettings {
    let st = srv.state.clone();
    srv.state
        .db
        .run_sync(|c| backup::load_settings(c, &st))
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_keys_keep_labels_and_dates() {
    let (srv, t) = start().await;
    let (_, r1) = npw_backup::generate_identity();
    let (_, r2) = npw_backup::generate_identity();

    // a key registered before labels existed (only in `recipients`)
    let st = srv.state.clone();
    let legacy = r1.clone();
    srv.state
        .db
        .run_sync(move |c| {
            let mut s = backup::load_settings(c, &st)?;
            s.recipients = vec![legacy];
            backup::save_settings(c, &st, &s)
        })
        .unwrap();

    let (s, list) = call(
        &srv.url,
        "POST",
        "/v1/admin/backup/recipients",
        Some(&t),
        Some(json!({ "recipient": r2, "label": "保险柜里的纸" })),
    )
    .await;
    assert_eq!(s, 200, "{list}");
    assert_eq!(list.as_array().unwrap().len(), 2);
    assert_eq!(list[0]["recipient"], r1.as_str());
    assert_eq!(list[0]["created_at"], 0, "the legacy key's date is unknown");
    assert_eq!(list[1]["label"], "保险柜里的纸");
    assert!(list[1]["created_at"].as_i64().unwrap() > 0);

    // not a key, or the server's own key
    let own = srv.state.keys.age_recipient();
    for bad in ["age1notakey", own.as_str()] {
        let (s, _) = call(
            &srv.url,
            "POST",
            "/v1/admin/backup/recipients",
            Some(&t),
            Some(json!({ "recipient": bad, "label": "x" })),
        )
        .await;
        assert_eq!(s, 400, "{bad}");
    }

    // the console saves the whole settings object it read: labels and dates stay
    let (_, status) = call(&srv.url, "GET", "/v1/admin/backup", Some(&t), None).await;
    let created = status["settings"]["recipient_info"][1]["created_at"].clone();
    let mut settings = status["settings"].clone();
    settings["debounce_minutes"] = json!(20);
    let (s, _) = call(
        &srv.url,
        "PUT",
        "/v1/admin/backup/settings",
        Some(&t),
        Some(settings),
    )
    .await;
    assert_eq!(s, 200);
    let (_, status) = call(&srv.url, "GET", "/v1/admin/backup", Some(&t), None).await;
    assert_eq!(status["settings"]["debounce_minutes"], 20);
    assert_eq!(
        status["settings"]["recipient_info"][1]["label"],
        "保险柜里的纸"
    );
    assert_eq!(
        status["settings"]["recipient_info"][1]["created_at"],
        created
    );

    // an older console that only sends `recipients` keeps working
    let mut old = status["settings"].clone();
    old.as_object_mut().unwrap().remove("recipient_info");
    let (s, _) = call(
        &srv.url,
        "PUT",
        "/v1/admin/backup/settings",
        Some(&t),
        Some(old),
    )
    .await;
    assert_eq!(s, 200);
    let (_, status) = call(&srv.url, "GET", "/v1/admin/backup", Some(&t), None).await;
    assert_eq!(
        status["settings"]["recipient_info"][1]["label"],
        "保险柜里的纸"
    );

    // removing one
    let (s, list) = call(
        &srv.url,
        "DELETE",
        &format!("/v1/admin/backup/recipients/{r1}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["recipient"], r2.as_str());
    assert_eq!(stored_settings(&srv).recipients, vec![r2.clone()]);

    // both changes are audited
    let (_, audit) = call(&srv.url, "GET", "/v1/admin/audit", Some(&t), None).await;
    let actions: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"admin_recipient_add"));
    assert!(actions.contains(&"admin_recipient_remove"));
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn notification_channels_switch_and_test_one_by_one() {
    let (srv, t) = start().await;
    // one channel, unsaved, pointing at nothing that answers
    let mut n = backup::default_settings().notify;
    n.webhook_url = "http://127.0.0.1:9/hook".into();
    let (s, r) = call(
        &srv.url,
        "POST",
        "/v1/admin/notify/test",
        Some(&t),
        Some(json!({ "channel": "webhook", "notify": n })),
    )
    .await;
    assert_eq!(s, 200);
    let failed = r["failed"].as_array().unwrap();
    assert_eq!(failed.len(), 1);
    assert!(failed[0].as_str().unwrap().starts_with("webhook:"));

    // a channel that is not configured says so; an unknown one is refused
    let (_, r) = call(
        &srv.url,
        "POST",
        "/v1/admin/notify/test",
        Some(&t),
        Some(json!({ "channel": "bark" })),
    )
    .await;
    assert_eq!(r["failed"][0], "bark: not configured");
    let (s, _) = call(
        &srv.url,
        "POST",
        "/v1/admin/notify/test",
        Some(&t),
        Some(json!({ "channel": "pigeon" })),
    )
    .await;
    assert_eq!(s, 400);
    // without a body: every saved channel (none yet)
    let (s, r) = call(&srv.url, "POST", "/v1/admin/notify/test", Some(&t), None).await;
    assert_eq!(s, 200);
    assert_eq!(r["failed"], json!([]));

    // switches and muted events are stored; a switched-off channel is not active
    let mut settings = backup::default_settings();
    settings.notify = n.clone();
    settings.notify.bark_url = "https://bark.example.com/key".into();
    settings.notify.off = vec!["bark".into()];
    settings.notify.muted_events = vec!["stale".into()];
    let (s, _) = call(
        &srv.url,
        "PUT",
        "/v1/admin/backup/settings",
        Some(&t),
        Some(serde_json::to_value(&settings).unwrap()),
    )
    .await;
    assert_eq!(s, 200);
    let stored = stored_settings(&srv);
    assert_eq!(stored.notify.off, vec!["bark".to_string()]);
    assert_eq!(backup::notify::active(&stored.notify), vec!["webhook"]);
    // a muted event sends nothing at all
    assert!(
        backup::notify::send_event(&stored.notify, "stale", "t", "b")
            .await
            .is_empty()
    );
    let mut bad = settings.clone();
    bad.notify.off = vec!["pigeon".into()];
    let (s, _) = call(
        &srv.url,
        "PUT",
        "/v1/admin/backup/settings",
        Some(&t),
        Some(serde_json::to_value(&bad).unwrap()),
    )
    .await;
    assert_eq!(s, 400);
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_target_can_be_tested_before_it_is_saved() {
    let (srv, t) = start().await;
    let dir = tempfile::tempdir().unwrap();
    let target = json!({
        "id": "new-target", "kind": "fs", "name": "NAS", "enabled": true, "protect_mode": false,
        "endpoint": dir.path().to_string_lossy(), "bucket": "", "root": "npw", "username": "", "has_secret": false,
    });
    let (s, r) = call(
        &srv.url,
        "POST",
        "/v1/admin/backup/test-target",
        Some(&t),
        Some(target.clone()),
    )
    .await;
    assert_eq!(s, 200, "{r}");
    let steps = r["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 3);
    assert!(steps.iter().all(|x| x["ok"] == true), "{r}");
    // nothing was saved
    let (_, status) = call(&srv.url, "GET", "/v1/admin/backup", Some(&t), None).await;
    assert_eq!(status["targets"], json!([]));
    // invalid targets are refused the same way as when saving
    let mut bad = target;
    bad["endpoint"] = json!("relative/path");
    let (s, _) = call(
        &srv.url,
        "POST",
        "/v1/admin/backup/test-target",
        Some(&t),
        Some(bad),
    )
    .await;
    assert_eq!(s, 400);
    srv.stop().await;
}

fn totp_now(secret: &str) -> String {
    npw_otp::OtpSpec::parse(secret)
        .unwrap()
        .code((nyapassword_server::db::now_ms() / 1000) as u64)
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_password_and_totp_from_the_console() {
    let (srv, t) = start().await;
    let (_, sec) = call(&srv.url, "GET", "/v1/admin/security", Some(&t), None).await;
    assert_eq!(sec["totp_enabled"], false);

    // a second session, to see that a password change ends it
    let (_, other) = admin_login(&srv, PW, None).await;

    // TOTP: the password is required again, and the first code must match
    let (s, _) = call(
        &srv.url,
        "POST",
        "/v1/admin/totp/setup",
        Some(&t),
        Some(json!({ "password": "wrong" })),
    )
    .await;
    assert_eq!(s, 403);
    let (s, setup) = call(
        &srv.url,
        "POST",
        "/v1/admin/totp/setup",
        Some(&t),
        Some(json!({ "password": PW })),
    )
    .await;
    assert_eq!(s, 200);
    let secret = setup["secret"].as_str().unwrap().to_string();
    assert!(setup["uri"].as_str().unwrap().contains(&secret));
    let (s, _) = call(
        &srv.url,
        "POST",
        "/v1/admin/totp/enable",
        Some(&t),
        Some(json!({ "password": PW, "secret": secret, "code": "12345x" })),
    )
    .await;
    assert_eq!(s, 400);
    let (_, sec) = call(&srv.url, "GET", "/v1/admin/security", Some(&t), None).await;
    assert_eq!(sec["totp_enabled"], false, "a wrong code changes nothing");
    let (s, _) = call(
        &srv.url,
        "POST",
        "/v1/admin/totp/enable",
        Some(&t),
        Some(json!({ "password": PW, "secret": secret, "code": totp_now(&secret) })),
    )
    .await;
    assert_eq!(s, 200);
    let (_, sec) = call(&srv.url, "GET", "/v1/admin/security", Some(&t), None).await;
    assert_eq!(sec["totp_enabled"], true);
    assert_eq!(admin_login(&srv, PW, None).await.0, 401);
    assert_eq!(admin_login(&srv, PW, Some(totp_now(&secret))).await.0, 200);

    // password: the current one is required, at least 12 characters
    for (cur, new, want) in [
        ("wrong", NEW_PW, 403),
        (PW, "short", 400),
        (PW, NEW_PW, 200),
    ] {
        let (s, _) = call(
            &srv.url,
            "POST",
            "/v1/admin/password",
            Some(&t),
            Some(json!({ "current": cur, "new": new })),
        )
        .await;
        assert_eq!(s, want, "{cur} -> {new}");
    }
    // this session continues, the other one ended
    let ok = call(&srv.url, "GET", "/v1/admin/security", Some(&t), None).await;
    assert_eq!(ok.0, 200);
    let ended = call(&srv.url, "GET", "/v1/admin/security", Some(&other), None).await;
    assert_eq!(ended.0, 401);
    assert_eq!(admin_login(&srv, PW, Some(totp_now(&secret))).await.0, 401);

    // TOTP off again (with the new password)
    let (s, _) = call(
        &srv.url,
        "POST",
        "/v1/admin/totp/disable",
        Some(&t),
        Some(json!({ "password": NEW_PW })),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(admin_login(&srv, NEW_PW, None).await.0, 200);
    srv.stop().await;
}
