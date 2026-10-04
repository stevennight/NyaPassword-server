//! Registration, login (OPAQUE), sessions and the authenticated-user extractor.

use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use hmac::{Hmac, Mac};
use npw_api::{self as api, code, LoginMethod};
use npw_crypto::{b64, opaque, unb64};
use rusqlite::{params, OptionalExtension};
use sha2::Sha256;

use crate::db::{self, now_ms};
use crate::error::{AppError, AppResult};
use crate::state::Shared;

const ACCESS_TTL: i64 = 60 * 60 * 1000;
const REFRESH_TTL: i64 = 30 * 24 * 60 * 60 * 1000;
const LOGIN_ATTEMPT_TTL: i64 = 5 * 60 * 1000;

pub fn hash_token(t: &str) -> String {
    npw_crypto::sha256_hex(t.as_bytes())
}

pub fn new_token() -> String {
    b64(&npw_crypto::random_bytes::<32>())
}

pub fn client_ip(
    state: &Shared,
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
) -> String {
    if state.cfg.trust_proxy {
        if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = v.split(',').next() {
                return first.trim().to_string();
            }
        }
    }
    peer.map(|p| p.ip().to_string()).unwrap_or_default()
}

fn d64(s: &str) -> AppResult<Vec<u8>> {
    unb64(s).ok_or_else(|| AppError::invalid("bad base64"))
}

fn uuid_ok(s: &str) -> AppResult<[u8; 16]> {
    uuid::Uuid::parse_str(s)
        .map(|u| *u.as_bytes())
        .map_err(|_| AppError::invalid("bad id"))
}

/// Creates a device (or reuses the caller's existing one) and a session.
fn issue_session(
    c: &rusqlite::Connection,
    account_id: &str,
    device: &api::DeviceInfo,
) -> AppResult<api::Session> {
    let now = now_ms();
    let reuse = match &device.id {
        Some(id) => c
            .query_row(
                "SELECT id FROM devices WHERE id = ?1 AND account_id = ?2 AND revoked_at IS NULL",
                [id, account_id],
                |r| r.get::<_, String>(0),
            )
            .optional()?,
        None => None,
    };
    let device_id = match reuse {
        Some(id) => {
            c.execute(
                "UPDATE devices SET name = ?2, platform = ?3, client_version = ?4, last_seen_at = ?5 WHERE id = ?1",
                params![id, device.name, device.platform, device.client_version, now],
            )?;
            id
        }
        None => {
            let id = uuid::Uuid::now_v7().to_string();
            c.execute(
                "INSERT INTO devices (id, account_id, name, platform, client_version, created_at, last_seen_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                params![id, account_id, truncate(&device.name, 100), truncate(&device.platform, 20), truncate(&device.client_version, 40), now],
            )?;
            id
        }
    };
    new_session(c, account_id, &device_id)
}

fn new_session(
    c: &rusqlite::Connection,
    account_id: &str,
    device_id: &str,
) -> AppResult<api::Session> {
    let now = now_ms();
    let access = new_token();
    let refresh = new_token();
    c.execute(
        "INSERT INTO sessions (token_hash, kind, account_id, device_id, expires_at, created_at) VALUES (?1, 'access', ?2, ?3, ?4, ?5)",
        params![hash_token(&access), account_id, device_id, now + ACCESS_TTL, now],
    )?;
    c.execute(
        "INSERT INTO sessions (token_hash, kind, account_id, device_id, expires_at, created_at) VALUES (?1, 'refresh', ?2, ?3, ?4, ?5)",
        params![hash_token(&refresh), account_id, device_id, now + REFRESH_TTL, now],
    )?;
    c.execute("DELETE FROM sessions WHERE expires_at < ?1", [now])?;
    Ok(api::Session {
        account_id: account_id.into(),
        device_id: device_id.into(),
        access_token: access,
        refresh_token: refresh,
        access_expires_at: now + ACCESS_TTL,
    })
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn valid_login(login: &str) -> bool {
    let l = login.trim();
    !l.is_empty() && l.chars().count() <= 200 && !l.chars().any(char::is_control)
}

// ------------------------------------------------------------------ server info

pub async fn server_info(State(st): State<Shared>) -> AppResult<Json<api::ServerInfo>> {
    let open = st
        .db
        .run(|c| Ok(c.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get::<_, i64>(0))? == 0))
        .await?;
    Ok(Json(api::ServerInfo {
        api: format!("{}.{}", api::API_MAJOR, api::API_MINOR),
        server_version: env!("CARGO_PKG_VERSION").into(),
        features: vec![
            api::feature::EVENTS.into(),
            api::feature::ATTACHMENTS.into(),
            api::feature::REVISIONS.into(),
            api::feature::ATOMIC_BATCH.into(),
        ],
        registration_open: open && st.cfg.open_first_registration,
        time: now_ms(),
        epoch: st.epoch.clone(),
    }))
}

// ------------------------------------------------------------------ registration

fn check_invite(
    c: &rusqlite::Connection,
    st: &Shared,
    invite: Option<&str>,
    consume: bool,
) -> AppResult<()> {
    let accounts: i64 = c.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0))?;
    if accounts == 0 && st.cfg.open_first_registration {
        return Ok(());
    }
    let Some(code) = invite.filter(|s| !s.is_empty()) else {
        return Err(AppError::new(
            StatusCode::FORBIDDEN,
            code::REGISTRATION_CLOSED,
            "registration needs an invite",
        ));
    };
    let h = hash_token(code.trim());
    let ok: Option<i64> = c
        .query_row(
            "SELECT expires_at FROM invites WHERE code_hash = ?1 AND used_at IS NULL",
            [&h],
            |r| r.get(0),
        )
        .optional()?;
    match ok {
        Some(exp) if exp > now_ms() => {
            if consume {
                c.execute(
                    "UPDATE invites SET used_at = ?2 WHERE code_hash = ?1",
                    params![h, now_ms()],
                )?;
            }
            Ok(())
        }
        _ => Err(AppError::new(
            StatusCode::FORBIDDEN,
            code::REGISTRATION_CLOSED,
            "invalid or expired invite",
        )),
    }
}

pub async fn register_start(
    State(st): State<Shared>,
    Json(req): Json<api::RegisterStartReq>,
) -> AppResult<Json<api::OpaqueResp>> {
    if !valid_login(&req.login) {
        return Err(AppError::invalid("invalid login"));
    }
    let acct = uuid_ok(&req.account_id)?;
    let st2 = st.clone();
    let invite = req.invite.clone();
    st.db
        .run(move |c| check_invite(c, &st2, invite.as_deref(), false))
        .await?;
    let resp = opaque::server_register_start(&st.opaque_setup, &d64(&req.opaque_request)?, &acct)?;
    Ok(Json(api::OpaqueResp {
        opaque_response: b64(&resp),
    }))
}

pub async fn register_finish(
    State(st): State<Shared>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<api::RegisterFinishReq>,
) -> AppResult<Json<api::Session>> {
    if !valid_login(&req.login) {
        return Err(AppError::invalid("invalid login"));
    }
    uuid_ok(&req.account_id)?;
    uuid_ok(&req.vault.id)?;
    if !st.cfg.allow_weak_kdf {
        req.kdf.validate()?;
    }
    let record = opaque::server_register_finish(&d64(&req.opaque_upload)?)?;
    for v in [
        &req.account_salt,
        &req.encrypted_account_key,
        &req.public_key,
        &req.encrypted_private_key,
        &req.vault.wrapped_key,
        &req.vault.encrypted_meta,
    ] {
        d64(v)?;
    }
    let ip = client_ip(&st, &headers, Some(peer));
    let st2 = st.clone();
    let session = st
        .db
        .run(move |c| {
            let tx = c.transaction()?;
            check_invite(&tx, &st2, req.invite.as_deref(), true)?;
            let exists: Option<String> = tx.query_row("SELECT id FROM accounts WHERE login = ?1 OR id = ?2", [req.login.trim(), &req.account_id], |r| r.get(0)).optional()?;
            if exists.is_some() {
                return Err(AppError::conflict("this login is already registered"));
            }
            let now = now_ms();
            tx.execute(
                "INSERT INTO accounts (id, login, opaque_record, kdf, account_salt, encrypted_account_key, public_key, encrypted_private_key, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
                params![
                    req.account_id,
                    req.login.trim(),
                    record,
                    serde_json::to_string(&req.kdf).map_err(AppError::internal)?,
                    req.account_salt,
                    req.encrypted_account_key,
                    req.public_key,
                    req.encrypted_private_key,
                    now
                ],
            )?;
            tx.execute(
                "INSERT INTO vaults (id, seq, encrypted_meta, meta_revision, created_by, created_at) VALUES (?1, 0, ?2, 1, ?3, ?4)",
                params![req.vault.id, req.vault.encrypted_meta, req.account_id, now],
            )?;
            tx.execute(
                "INSERT INTO vault_members (vault_id, account_id, role, wrapped_key, created_at) VALUES (?1, ?2, 'owner', ?3, ?4)",
                params![req.vault.id, req.account_id, req.vault.wrapped_key, now],
            )?;
            let s = issue_session(&tx, &req.account_id, &req.device)?;
            db::audit(&tx, Some(&req.account_id), "register", &s.device_id, &ip, &req.device.name)?;
            tx.commit()?;
            Ok(s)
        })
        .await?;
    st.notify_change();
    Ok(Json(session))
}

// ------------------------------------------------------------------ login

/// Answers for unknown logins are derived from a server secret, so they are
/// stable and indistinguishable from real ones.
fn fake_account(st: &Shared, login: &str) -> (String, String) {
    let mut m =
        <Hmac<Sha256> as Mac>::new_from_slice(st.keys.key().as_bytes()).expect("any key length");
    m.update(b"npw/fake-prelogin/v1");
    m.update(login.trim().to_lowercase().as_bytes());
    let out = m.finalize().into_bytes();
    let mut id = [0u8; 16];
    id.copy_from_slice(&out[..16]);
    id[6] = (id[6] & 0x0f) | 0x70; // looks like a v7 UUID
    id[8] = (id[8] & 0x3f) | 0x80;
    (uuid::Uuid::from_bytes(id).to_string(), b64(&out[16..32]))
}

pub async fn prelogin(
    State(st): State<Shared>,
    Json(req): Json<api::PreloginReq>,
) -> AppResult<Json<api::PreloginResp>> {
    let login = req.login.trim().to_string();
    let row = st
        .db
        .run(move |c| {
            Ok(c.query_row(
                "SELECT id, kdf, account_salt FROM accounts WHERE login = ?1",
                [login],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?)
        })
        .await?;
    Ok(Json(match row {
        Some((id, kdf, salt)) => api::PreloginResp {
            account_id: id,
            kdf: serde_json::from_str(&kdf).map_err(AppError::internal)?,
            account_salt: salt,
        },
        None => {
            let (id, salt) = fake_account(&st, &req.login);
            api::PreloginResp {
                account_id: id,
                kdf: npw_api::KdfParams::default(),
                account_salt: salt,
            }
        }
    }))
}

pub async fn login_start(
    State(st): State<Shared>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<api::LoginStartReq>,
) -> AppResult<Json<api::LoginStartResp>> {
    let ip = client_ip(&st, &headers, Some(peer));
    if !st.limiter.hit(&format!("ip:{ip}"), 30, 60_000)
        || !st.limiter.hit(
            &format!("login:{}", req.login.trim().to_lowercase()),
            20,
            3_600_000,
        )
    {
        return Err(AppError::rate_limited());
    }
    let login = req.login.trim().to_string();
    let method = req.method;
    let row = st
        .db
        .run(move |c| {
            Ok(c.query_row(
                "SELECT id, opaque_record, opaque_recovery FROM accounts WHERE login = ?1",
                [login],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .optional()?)
        })
        .await?;
    let (account_id, record) = match row {
        Some((id, rec, recovery)) => {
            let r = match method {
                LoginMethod::Password => Some(rec),
                LoginMethod::RecoveryCode => recovery,
            };
            (Some(id), r)
        }
        None => (None, None),
    };
    let cred_id = match &account_id {
        Some(id) => uuid_ok(id)?,
        None => uuid_ok(&fake_account(&st, &req.login).0)?,
    };
    let (state, resp) = opaque::server_login_start(
        &st.opaque_setup,
        record.as_deref(),
        &d64(&req.opaque_request)?,
        &cred_id,
    )?;
    let login_id = uuid::Uuid::new_v4().to_string();
    let lid = login_id.clone();
    let method_s = if method == LoginMethod::RecoveryCode {
        "recovery"
    } else {
        "password"
    };
    let real = record.is_some();
    st.db
        .run(move |c| {
            c.execute("DELETE FROM login_attempts WHERE expires_at < ?1", [now_ms()])?;
            c.execute(
                "INSERT INTO login_attempts (id, account_id, state, method, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![lid, if real { account_id } else { None }, state, method_s, now_ms() + LOGIN_ATTEMPT_TTL],
            )?;
            Ok(())
        })
        .await?;
    Ok(Json(api::LoginStartResp {
        login_id,
        opaque_response: b64(&resp),
    }))
}

pub async fn login_finish(
    State(st): State<Shared>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<api::LoginFinishReq>,
) -> AppResult<Json<api::Session>> {
    let ip = client_ip(&st, &headers, Some(peer));
    let lid = req.login_id.clone();
    let attempt = st
        .db
        .run(move |c| {
            let row = c
                .query_row(
                    "SELECT account_id, state, expires_at FROM login_attempts WHERE id = ?1",
                    [&lid],
                    |r| {
                        Ok((
                            r.get::<_, Option<String>>(0)?,
                            r.get::<_, Vec<u8>>(1)?,
                            r.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?;
            c.execute("DELETE FROM login_attempts WHERE id = ?1", [&lid])?;
            Ok(row)
        })
        .await?;
    let Some((account_id, state, expires)) = attempt else {
        return Err(AppError::login_failed());
    };
    if expires < now_ms() {
        return Err(AppError::login_failed());
    }
    let verified = opaque::server_login_finish(&state, &d64(&req.opaque_finalization)?).is_ok();
    let ip2 = ip.clone();
    match (verified, account_id) {
        (true, Some(account_id)) => {
            let device = req.device.clone();
            let s = st
                .db
                .run(move |c| {
                    let tx = c.transaction()?;
                    let s = issue_session(&tx, &account_id, &device)?;
                    db::audit(
                        &tx,
                        Some(&account_id),
                        "login",
                        &s.device_id,
                        &ip2,
                        &device.name,
                    )?;
                    tx.commit()?;
                    Ok(s)
                })
                .await?;
            st.limiter.clear(&format!("ip:{ip}"));
            Ok(Json(s))
        }
        (_, account_id) => {
            if let Some(a) = account_id {
                let _ = st
                    .db
                    .run(move |c| Ok(db::audit(c, Some(&a), "login_failed", "", &ip2, "")?))
                    .await;
            }
            Err(AppError::login_failed())
        }
    }
}

pub async fn refresh(
    State(st): State<Shared>,
    Json(req): Json<api::RefreshReq>,
) -> AppResult<Json<api::Session>> {
    let h = hash_token(&req.refresh_token);
    let s = st
        .db
        .run(move |c| {
            let tx = c.transaction()?;
            let row: Option<(String, String, i64)> = tx
                .query_row("SELECT account_id, device_id, expires_at FROM sessions WHERE token_hash = ?1 AND kind = 'refresh'", [&h], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .optional()?;
            let Some((account_id, device_id, exp)) = row else { return Err(AppError::unauthorized()) };
            tx.execute("DELETE FROM sessions WHERE token_hash = ?1", [&h])?;
            if exp < now_ms() {
                tx.commit()?;
                return Err(AppError::unauthorized());
            }
            let revoked: Option<i64> = tx.query_row("SELECT revoked_at FROM devices WHERE id = ?1", [&device_id], |r| r.get(0))?;
            if revoked.is_some() {
                tx.commit()?;
                return Err(AppError::new(StatusCode::UNAUTHORIZED, code::DEVICE_REVOKED, "device removed"));
            }
            let s = new_session(&tx, &account_id, &device_id)?;
            tx.commit()?;
            Ok(s)
        })
        .await?;
    Ok(Json(s))
}

pub async fn logout(
    State(st): State<Shared>,
    user: AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    st.db
        .run(move |c| {
            c.execute(
                "DELETE FROM sessions WHERE device_id = ?1",
                [&user.device_id],
            )?;
            Ok(())
        })
        .await?;
    Ok(Json(serde_json::json!({})))
}

// ------------------------------------------------------------------ extractor

/// The caller of an authenticated request.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub account_id: String,
    pub device_id: String,
    pub ip: String,
}

pub async fn authenticate(st: &Shared, token: &str) -> AppResult<AuthUser> {
    let h = hash_token(token);
    let row = st
        .db
        .run(move |c| {
            let row: Option<(String, String, i64, Option<i64>, i64)> = c
                .query_row(
                    "SELECT s.account_id, s.device_id, s.expires_at, d.revoked_at, d.last_seen_at FROM sessions s JOIN devices d ON d.id = s.device_id
                     WHERE s.token_hash = ?1 AND s.kind = 'access'",
                    [&h],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;
            if let Some((_, dev, exp, None, seen)) = &row {
                let now = now_ms();
                if *exp > now && now - seen > 5 * 60 * 1000 {
                    c.execute("UPDATE devices SET last_seen_at = ?2 WHERE id = ?1", params![dev, now])?;
                }
            }
            Ok(row)
        })
        .await?;
    match row {
        Some((_, _, _, Some(_), _)) => Err(AppError::new(
            StatusCode::UNAUTHORIZED,
            code::DEVICE_REVOKED,
            "device removed",
        )),
        Some((account_id, device_id, exp, None, _)) if exp > now_ms() => Ok(AuthUser {
            account_id,
            device_id,
            ip: String::new(),
        }),
        _ => Err(AppError::unauthorized()),
    }
}

impl FromRequestParts<Shared> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, st: &Shared) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(AppError::unauthorized)?
            .to_string();
        let mut user = authenticate(st, &token).await?;
        let peer = parts
            .extensions
            .get::<ConnectInfo<std::net::SocketAddr>>()
            .map(|c| c.0);
        user.ip = client_ip(st, &parts.headers, peer);
        Ok(user)
    }
}
