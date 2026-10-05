//! The admin API behind the management console: health, accounts and devices,
//! invites, audit log, backup targets / settings / recovery keys / runs /
//! checks, alert channels, and the admin's own password and TOTP.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{ConnectInfo, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use axum::Json;
use npw_api::admin::{self as adm, BackupStatus, TargetStatus};
use npw_api::{self as api};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use crate::auth::{client_ip, hash_token, new_token};
use crate::backup::{self, targets::StoredTarget};
use crate::db::{self, now_ms};
use crate::error::{AppError, AppResult};
use crate::state::Shared;

const SESSION_TTL: i64 = 12 * 3_600_000;
pub const PASSWORD_KEY: &str = "admin_password_hash";
pub const TOTP_KEY: &str = "admin_totp_secret";

pub fn hash_password(pw: &str) -> String {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .expect("argon2 with default parameters")
        .to_string()
}

pub fn set_password(c: &Connection, pw: &str) -> rusqlite::Result<()> {
    db::set_setting(c, PASSWORD_KEY, &hash_password(pw))
}

fn password_matches(hash: &str, password: &str) -> AppResult<bool> {
    let parsed = PasswordHash::new(hash).map_err(AppError::internal)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Accepts the code of the previous, current and next 30-second step.
fn totp_matches(secret: &str, code: &str) -> AppResult<bool> {
    let spec = npw_otp::OtpSpec::parse(secret).map_err(AppError::internal)?;
    let now = (now_ms() / 1000) as u64;
    let code = code.replace(' ', "");
    Ok(!code.is_empty()
        && [now.saturating_sub(30), now, now + 30]
            .iter()
            .any(|t| spec.code(*t) == code))
}

pub fn totp_uri(secret: &str) -> String {
    format!("otpauth://totp/NyaPassword:admin?secret={secret}&issuer=NyaPassword")
}

/// An authenticated admin request; holds the session's token hash.
pub struct Admin {
    token_hash: String,
}

impl FromRequestParts<Shared> for Admin {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, st: &Shared) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(AppError::unauthorized)?;
        let h = hash_token(token);
        let mut s = st.admin_sessions.lock().expect("lock");
        let now = now_ms();
        s.retain(|_, exp| *exp > now);
        if s.contains_key(&h) {
            Ok(Admin { token_hash: h })
        } else {
            Err(AppError::unauthorized())
        }
    }
}

pub async fn login(
    State(st): State<Shared>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<adm::AdminLoginReq>,
) -> AppResult<Json<adm::AdminSession>> {
    let ip = client_ip(&st, &headers, Some(peer));
    if !st.limiter.hit(&format!("admin:{ip}"), 10, 15 * 60_000) {
        return Err(AppError::rate_limited());
    }
    let (hash, totp) = st
        .db
        .run(|c| {
            Ok((
                db::get_setting(c, PASSWORD_KEY)?,
                db::get_setting(c, TOTP_KEY)?,
            ))
        })
        .await?;
    let Some(hash) = hash else {
        return Err(AppError::new(
            axum::http::StatusCode::FORBIDDEN,
            api::code::FORBIDDEN,
            "admin password not set: run `nyapassword-server admin-password`",
        ));
    };
    let pw_ok = password_matches(&hash, &req.password)?;
    let totp_ok = match totp {
        None => true,
        Some(secret) => totp_matches(&secret, req.totp.as_deref().unwrap_or_default())?,
    };
    let ip2 = ip.clone();
    if !(pw_ok && totp_ok) {
        st.db
            .run(move |c| Ok(db::audit(c, None, "admin_login_failed", "", &ip2, "")?))
            .await?;
        return Err(AppError::login_failed());
    }
    st.db
        .run(move |c| Ok(db::audit(c, None, "admin_login", "", &ip2, "")?))
        .await?;
    let token = new_token();
    let expires_at = now_ms() + SESSION_TTL;
    st.admin_sessions
        .lock()
        .expect("lock")
        .insert(hash_token(&token), expires_at);
    Ok(Json(adm::AdminSession { token, expires_at }))
}

pub async fn health(State(st): State<Shared>, _a: Admin) -> AppResult<Json<adm::Health>> {
    let started = st.started_at;
    let db_path = st.cfg.db_path();
    let h = st
        .db
        .run(move |c| {
            let integrity: String = c.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
            let n = crate::items::counts(c)?;
            Ok(adm::Health {
                version: env!("CARGO_PKG_VERSION").into(),
                started_at: started,
                db_ok: integrity == "ok",
                integrity_checked_at: now_ms(),
                accounts: n["accounts"],
                devices: n["devices"],
                items: n["items"],
                revisions: n["revisions"],
                attachments: n["attachments"],
                attachment_bytes: n["attachment_bytes"],
                db_bytes: std::fs::metadata(&db_path)
                    .map(|m| m.len() as i64)
                    .unwrap_or(0),
            })
        })
        .await?;
    Ok(Json(h))
}

pub async fn accounts(
    State(st): State<Shared>,
    _a: Admin,
) -> AppResult<Json<Vec<adm::AdminAccount>>> {
    let r = st
        .db
        .run(|c| {
            let mut s = c.prepare("SELECT id, login, created_at FROM accounts ORDER BY created_at")?;
            let accs: Vec<(String, String, i64)> = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<_>>()?;
            let mut out = vec![];
            for (id, login, created_at) in accs {
                let items: i64 = c.query_row(
                    "SELECT COUNT(*) FROM items i JOIN vault_members m ON m.vault_id = i.vault_id WHERE m.account_id = ?1 AND i.deleted = 0",
                    [&id],
                    |r| r.get(0),
                )?;
                let mut s = c.prepare("SELECT id, name, platform, client_version, created_at, last_seen_at, revoked_at FROM devices WHERE account_id = ?1 ORDER BY last_seen_at DESC")?;
                let devices = s
                    .query_map([&id], |r| {
                        Ok(api::DeviceRecord {
                            id: r.get(0)?,
                            name: r.get(1)?,
                            platform: r.get(2)?,
                            client_version: r.get(3)?,
                            created_at: r.get(4)?,
                            last_seen_at: r.get(5)?,
                            revoked_at: r.get(6)?,
                            current: false,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                out.push(adm::AdminAccount { account_id: id, login, created_at, items, devices });
            }
            Ok(out)
        })
        .await?;
    Ok(Json(r))
}

pub async fn revoke_device(
    State(st): State<Shared>,
    _a: Admin,
    Path(device_id): Path<String>,
) -> AppResult<Json<Value>> {
    let dev = device_id.clone();
    let account = st
        .db
        .run(move |c| {
            let acc: Option<String> = c
                .query_row(
                    "SELECT account_id FROM devices WHERE id = ?1",
                    [&device_id],
                    |r| r.get(0),
                )
                .optional()?;
            // sessions are kept so the device's tokens answer `device_revoked` (see
            // `account::revoke_device`)
            c.execute(
                "UPDATE devices SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
                params![device_id, now_ms()],
            )?;
            db::audit(c, acc.as_deref(), "device_revoke", "", "admin", &device_id)?;
            Ok(acc)
        })
        .await?;
    if let Some(a) = account {
        let _ = st
            .events
            .send((a, api::Event::DeviceRevoked { device_id: dev }));
    }
    Ok(Json(json!({})))
}

pub async fn invites(State(st): State<Shared>, _a: Admin) -> AppResult<Json<Vec<adm::Invite>>> {
    let r = st
        .db
        .run(|c| {
            let mut s = c.prepare(
                "SELECT expires_at, used_at FROM invites ORDER BY created_at DESC LIMIT 50",
            )?;
            let rows = s
                .query_map([], |r| {
                    Ok(adm::Invite {
                        code: String::new(),
                        expires_at: r.get(0)?,
                        used_at: r.get(1)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(r))
}

pub fn create_invite(c: &Connection, hours: u32) -> rusqlite::Result<adm::Invite> {
    let code = npw_otp::base32_encode(&npw_crypto::random_bytes::<10>());
    let code = format!("{}-{}", &code[..8], &code[8..16]);
    let expires_at = now_ms() + hours.clamp(1, 24 * 30) as i64 * 3_600_000;
    c.execute(
        "INSERT INTO invites (code_hash, expires_at, created_at) VALUES (?1, ?2, ?3)",
        params![hash_token(&code), expires_at, now_ms()],
    )?;
    Ok(adm::Invite {
        code,
        expires_at,
        used_at: None,
    })
}

pub async fn new_invite(
    State(st): State<Shared>,
    _a: Admin,
    Json(req): Json<adm::InviteReq>,
) -> AppResult<Json<adm::Invite>> {
    Ok(Json(
        st.db.run(move |c| Ok(create_invite(c, req.hours)?)).await?,
    ))
}

pub async fn audit(State(st): State<Shared>, _a: Admin) -> AppResult<Json<Vec<api::AuditEntry>>> {
    let r = st
        .db
        .run(|c| {
            let mut s = c.prepare("SELECT at, action, device_id, ip, detail, COALESCE(account_id, '') FROM audit ORDER BY id DESC LIMIT 500")?;
            let rows = s
                .query_map([], |r| {
                    let acc: String = r.get(5)?;
                    let detail: String = r.get(4)?;
                    Ok(api::AuditEntry {
                        at: r.get(0)?,
                        action: r.get(1)?,
                        device_id: r.get(2)?,
                        ip: r.get(3)?,
                        detail: if acc.is_empty() { detail } else { format!("{detail} [{}]", &acc[..8.min(acc.len())]) },
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(r))
}

// ------------------------------------------------------------------ backup

pub async fn backup_status(State(st): State<Shared>, _a: Admin) -> AppResult<Json<BackupStatus>> {
    let st2 = st.clone();
    let server_recipient = st.keys.age_recipient();
    let r = st
        .db
        .run(move |c| {
            let mut settings = backup::load_settings(c, &st2)?;
            mask_secrets(&mut settings.notify);
            fill_recipient_info(&mut settings, None);
            let mut targets = vec![];
            for t in backup::load_targets(c)? {
                let state: Option<(Option<i64>, Option<i64>, String)> = c
                    .query_row("SELECT last_success_at, last_attempt_at, last_error FROM backup_target_state WHERE target_id = ?1", [&t.target.id], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                    })
                    .optional()?;
                let (s, a, e) = state.unwrap_or((None, None, String::new()));
                targets.push(TargetStatus { target: t.public(), last_success_at: s, last_attempt_at: a, last_error: e });
            }
            let last_success_at = targets.iter().filter_map(|t| t.last_success_at).max();
            Ok(BackupStatus {
                settings,
                server_recipient,
                targets,
                runs: backup::runs(c, 30)?,
                drills: backup::drills(c, 20)?,
                last_success_at,
                last_manual_drill_at: backup::manual_drill_at(c)?,
                pending_changes: backup::pending_changes(c)?,
            })
        })
        .await?;
    Ok(Json(r))
}

/// Notification secrets are write-only: reads show [`adm::SECRET_MASK`] instead.
fn mask_secrets(n: &mut adm::NotifyConfig) {
    for v in [&mut n.smtp_password, &mut n.telegram_bot_token] {
        if !v.is_empty() {
            *v = adm::SECRET_MASK.into();
        }
    }
}

/// A secret sent back as the mask keeps its stored value.
fn unmask_secrets(n: &mut adm::NotifyConfig, stored: &adm::NotifyConfig) {
    if n.smtp_password == adm::SECRET_MASK {
        n.smtp_password = stored.smtp_password.clone();
    }
    if n.telegram_bot_token == adm::SECRET_MASK {
        n.telegram_bot_token = stored.telegram_bot_token.clone();
    }
}

/// Makes `recipient_info` hold exactly one entry per recipient, in the same
/// order. Labels come from the request when it brings one, else from `known`
/// (the stored settings); times come from `known`, and recipients new to it
/// get the current time.
fn fill_recipient_info(s: &mut adm::BackupSettings, known: Option<&adm::BackupSettings>) {
    let now = now_ms();
    let find =
        |list: &[adm::RecipientInfo], r: &str| list.iter().find(|i| i.recipient == r).cloned();
    s.recipient_info = s
        .recipients
        .iter()
        .map(|r| {
            let given = find(&s.recipient_info, r);
            let stored = known.and_then(|k| find(&k.recipient_info, r));
            let label = given
                .as_ref()
                .map(|g| g.label.trim().to_string())
                .filter(|l| !l.is_empty())
                .or_else(|| stored.as_ref().map(|i| i.label.clone()))
                .unwrap_or_default();
            let created_at = match known {
                // reading: what is stored (0 for keys added before labels existed)
                None => given.map_or(0, |g| g.created_at),
                Some(k) => match stored {
                    Some(i) => i.created_at,
                    None if k.recipients.contains(r) => 0,
                    None => now,
                },
            };
            adm::RecipientInfo {
                recipient: r.clone(),
                label,
                created_at,
            }
        })
        .collect();
}

fn check_recipient(r: &str) -> AppResult<()> {
    if npw_backup::valid_recipient(r) {
        Ok(())
    } else {
        Err(AppError::invalid(format!("not an age recipient: {r}")))
    }
}

/// Saves the settings and audits changes to the recipient list.
fn store_settings(
    c: &Connection,
    st: &Shared,
    mut s: adm::BackupSettings,
    stored: &adm::BackupSettings,
) -> AppResult<()> {
    let mut seen = std::collections::HashSet::new();
    s.recipients = s
        .recipients
        .iter()
        .map(|r| r.trim().to_string())
        .filter(|r| seen.insert(r.clone()))
        .collect();
    fill_recipient_info(&mut s, Some(stored));
    backup::save_settings(c, st, &s)?;
    for r in s
        .recipients
        .iter()
        .filter(|r| !stored.recipients.contains(r))
    {
        db::audit(c, None, "admin_recipient_add", "", "admin", r)?;
    }
    for r in stored
        .recipients
        .iter()
        .filter(|r| !s.recipients.contains(r))
    {
        db::audit(c, None, "admin_recipient_remove", "", "admin", r)?;
    }
    Ok(())
}

pub async fn put_settings(
    State(st): State<Shared>,
    _a: Admin,
    Json(mut s): Json<adm::BackupSettings>,
) -> AppResult<Json<Value>> {
    for r in &s.recipients {
        check_recipient(r.trim())?;
    }
    if s.daily_hour_utc > 23 || s.debounce_minutes > 24 * 60 {
        return Err(AppError::invalid("bad schedule"));
    }
    for v in s.notify.off.iter().chain(&s.notify.muted_events) {
        if !adm::channel::ALL.contains(&v.as_str()) && !adm::alert::ALL.contains(&v.as_str()) {
            return Err(AppError::invalid(format!("unknown channel or event {v}")));
        }
    }
    let st2 = st.clone();
    st.db
        .run(move |c| {
            let stored = backup::load_settings(c, &st2)?;
            unmask_secrets(&mut s.notify, &stored.notify);
            store_settings(c, &st2, s, &stored)
        })
        .await?;
    Ok(Json(json!({})))
}

/// Registers one more offline recovery key (an age recipient) with a label.
pub async fn add_recipient(
    State(st): State<Shared>,
    _a: Admin,
    Json(req): Json<adm::RecipientReq>,
) -> AppResult<Json<Vec<adm::RecipientInfo>>> {
    let r = req.recipient.trim().to_string();
    check_recipient(&r)?;
    if r == st.keys.age_recipient() {
        return Err(AppError::invalid(
            "this is the server's own key, which is always a recipient",
        ));
    }
    let st2 = st.clone();
    let out = st
        .db
        .run(move |c| {
            let stored = backup::load_settings(c, &st2)?;
            let mut s = stored.clone();
            if !s.recipients.contains(&r) {
                s.recipients.push(r.clone());
            }
            s.recipient_info.retain(|i| i.recipient != r);
            s.recipient_info.push(adm::RecipientInfo {
                recipient: r,
                label: req.label,
                created_at: 0,
            });
            store_settings(c, &st2, s, &stored)?;
            Ok(backup::load_settings(c, &st2)?.recipient_info)
        })
        .await?;
    Ok(Json(out))
}

pub async fn remove_recipient(
    State(st): State<Shared>,
    _a: Admin,
    Path(recipient): Path<String>,
) -> AppResult<Json<Vec<adm::RecipientInfo>>> {
    let st2 = st.clone();
    let out = st
        .db
        .run(move |c| {
            let stored = backup::load_settings(c, &st2)?;
            let mut s = stored.clone();
            s.recipients.retain(|r| r != &recipient);
            store_settings(c, &st2, s, &stored)?;
            Ok(backup::load_settings(c, &st2)?.recipient_info)
        })
        .await?;
    Ok(Json(out))
}

fn check_target(t: &adm::BackupTarget) -> AppResult<()> {
    if t.name.trim().is_empty() || t.endpoint.trim().is_empty() {
        return Err(AppError::invalid("name and endpoint are required"));
    }
    if t.kind == adm::TargetKind::Oss && t.bucket.trim().is_empty() {
        return Err(AppError::invalid("bucket is required for OSS"));
    }
    let is_url = t.endpoint.starts_with("https://") || t.endpoint.starts_with("http://");
    if t.kind == adm::TargetKind::Fs {
        if is_url || !std::path::Path::new(&t.endpoint).is_absolute() {
            return Err(AppError::invalid(
                "a directory target needs an absolute path",
            ));
        }
    } else if !is_url {
        return Err(AppError::invalid("endpoint must be an http(s) URL"));
    }
    Ok(())
}

/// The target to store or test: a new secret is sealed, an empty one keeps
/// the stored secret of the target with the same id.
fn seal_target(c: &Connection, st: &Shared, mut t: adm::BackupTarget) -> AppResult<StoredTarget> {
    let existing = backup::load_targets(c)?
        .into_iter()
        .find(|x| x.target.id == t.id);
    let sealed = if !t.secret.is_empty() {
        st.keys.seal(&format!("target:{}", t.id), &t.secret)
    } else {
        existing.map(|e| e.secret_sealed).unwrap_or_default()
    };
    t.secret.clear();
    Ok(StoredTarget {
        target: t,
        secret_sealed: sealed,
    })
}

pub async fn put_target(
    State(st): State<Shared>,
    _a: Admin,
    Path(id): Path<String>,
    Json(mut t): Json<adm::BackupTarget>,
) -> AppResult<Json<adm::BackupTarget>> {
    t.id = id;
    check_target(&t)?;
    let st2 = st.clone();
    let r = st
        .db
        .run(move |c| {
            let stored = seal_target(c, &st2, t)?;
            backup::save_target(c, &stored)?;
            Ok(stored.public())
        })
        .await?;
    Ok(Json(r))
}

pub async fn delete_target(
    State(st): State<Shared>,
    _a: Admin,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    st.db
        .run(move |c| {
            c.execute("DELETE FROM backup_targets WHERE id = ?1", [&id])?;
            c.execute(
                "DELETE FROM backup_target_state WHERE target_id = ?1",
                [&id],
            )?;
            c.execute(
                "DELETE FROM backup_target_blobs WHERE target_id = ?1",
                [&id],
            )?;
            Ok(())
        })
        .await?;
    Ok(Json(json!({})))
}

/// Writes, reads and deletes a small probe object; in protect mode the delete is expected to fail.
async fn probe(st: &Shared, t: &StoredTarget) -> AppResult<Value> {
    let op = t
        .operator(&st.keys)
        .map_err(|e| AppError::invalid(format!("{e:#}")))?;
    let probe = format!("probe/nyapassword-probe-{}.txt", now_ms());
    let mut steps = vec![];
    let write = crate::backup::targets::write(&op, &probe, b"nyapassword probe".to_vec()).await;
    steps.push(json!({ "step": "write", "ok": write.is_ok(), "error": write.as_ref().err().map(|e| format!("{e:#}")) }));
    if write.is_ok() {
        let read = crate::backup::targets::read(&op, &probe).await;
        steps.push(json!({ "step": "read", "ok": read.as_ref().is_ok_and(|d| d == b"nyapassword probe"), "error": read.as_ref().err().map(|e| format!("{e:#}")) }));
        let del = crate::backup::targets::delete(&op, &probe).await;
        steps.push(json!({ "step": "delete", "ok": del.is_ok(), "expected_to_fail": t.target.protect_mode, "error": del.as_ref().err().map(|e| format!("{e:#}")) }));
    }
    Ok(json!({ "steps": steps }))
}

pub async fn test_target(
    State(st): State<Shared>,
    _a: Admin,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let t = st
        .db
        .run(move |c| {
            backup::load_targets(c)?
                .into_iter()
                .find(|t| t.target.id == id)
                .ok_or_else(AppError::not_found)
        })
        .await?;
    Ok(Json(probe(&st, &t).await?))
}

/// Tests a target before it is saved (the "添加目标" wizard). An empty
/// `secret` uses the stored secret of the target with the same id.
pub async fn test_unsaved_target(
    State(st): State<Shared>,
    _a: Admin,
    Json(t): Json<adm::BackupTarget>,
) -> AppResult<Json<Value>> {
    check_target(&t)?;
    let st2 = st.clone();
    let stored = st.db.run(move |c| seal_target(c, &st2, t)).await?;
    Ok(Json(probe(&st, &stored).await?))
}

pub async fn target_objects(
    State(st): State<Shared>,
    _a: Admin,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<adm::BackupObject>>> {
    let t = st
        .db
        .run(move |c| {
            backup::load_targets(c)?
                .into_iter()
                .find(|t| t.target.id == id)
                .ok_or_else(AppError::not_found)
        })
        .await?;
    let op = t
        .operator(&st.keys)
        .map_err(|e| AppError::invalid(format!("{e:#}")))?;
    Ok(Json(
        crate::backup::targets::list_backups(&op)
            .await
            .map_err(|e| AppError::invalid(format!("{e:#}")))?,
    ))
}

pub async fn run_now(State(st): State<Shared>, _a: Admin) -> AppResult<Json<adm::BackupRun>> {
    Ok(Json(backup::run_backup(&st, "manual").await?))
}

#[derive(serde::Deserialize, Default)]
pub struct DrillReq {
    #[serde(default)]
    target_id: Option<String>,
}

pub async fn drill(
    State(st): State<Shared>,
    _a: Admin,
    Json(req): Json<DrillReq>,
) -> AppResult<Json<adm::DrillRun>> {
    Ok(Json(backup::run_drill(&st, req.target_id).await?))
}

pub async fn manual_drill_done(State(st): State<Shared>, _a: Admin) -> AppResult<Json<Value>> {
    st.db.run(|c| Ok(backup::set_manual_drill(c)?)).await?;
    Ok(Json(json!({})))
}

/// Sends a test notification. The optional body ([`adm::NotifyTestReq`])
/// picks one channel and/or brings unsaved settings.
pub async fn test_notify(
    State(st): State<Shared>,
    _a: Admin,
    body: axum::body::Bytes,
) -> AppResult<Json<Value>> {
    let req: adm::NotifyTestReq = if body.iter().all(u8::is_ascii_whitespace) {
        Default::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| AppError::invalid(e.to_string()))?
    };
    if let Some(ch) = &req.channel {
        if !adm::channel::ALL.contains(&ch.as_str()) {
            return Err(AppError::invalid(format!("unknown channel {ch}")));
        }
    }
    let st2 = st.clone();
    let stored = st.db.run(move |c| backup::load_settings(c, &st2)).await?;
    let cfg = match req.notify {
        Some(mut n) => {
            unmask_secrets(&mut n, &stored.notify);
            n
        }
        None => stored.notify,
    };
    let (title, text) = (
        "NyaPassword 测试通知",
        "如果你收到这条消息，告警通道工作正常。",
    );
    let failed = match &req.channel {
        Some(ch) => backup::notify::send_to(&cfg, &[ch.as_str()], title, text).await,
        None => backup::notify::send(&cfg, title, text).await,
    };
    Ok(Json(json!({ "failed": failed })))
}

// ------------------------------------------------------------------ admin account

const MIN_ADMIN_PASSWORD: usize = 12;

/// Checks the admin password again before sensitive changes, so a stolen
/// session token alone cannot lock the admin out.
async fn confirm_password(st: &Shared, password: String) -> AppResult<()> {
    let ok = st
        .db
        .run(move |c| match db::get_setting(c, PASSWORD_KEY)? {
            Some(hash) => password_matches(&hash, &password),
            None => Ok(false),
        })
        .await?;
    if ok {
        Ok(())
    } else {
        Err(AppError::new(
            axum::http::StatusCode::FORBIDDEN,
            api::code::FORBIDDEN,
            "the admin password is wrong",
        ))
    }
}

pub async fn security(State(st): State<Shared>, _a: Admin) -> AppResult<Json<adm::AdminSecurity>> {
    let totp = st.db.run(|c| Ok(db::get_setting(c, TOTP_KEY)?)).await?;
    Ok(Json(adm::AdminSecurity {
        totp_enabled: totp.is_some(),
    }))
}

/// Changes the admin password; every other admin session ends.
pub async fn change_password(
    State(st): State<Shared>,
    a: Admin,
    Json(req): Json<adm::AdminPasswordReq>,
) -> AppResult<Json<Value>> {
    if req.new.chars().count() < MIN_ADMIN_PASSWORD {
        return Err(AppError::invalid(format!(
            "use at least {MIN_ADMIN_PASSWORD} characters"
        )));
    }
    confirm_password(&st, req.current).await?;
    let new = req.new;
    st.db
        .run(move |c| {
            set_password(c, &new)?;
            db::audit(c, None, "admin_password_change", "", "admin", "")?;
            Ok(())
        })
        .await?;
    st.admin_sessions
        .lock()
        .expect("lock")
        .retain(|h, _| h == &a.token_hash);
    Ok(Json(json!({})))
}

/// Proposes a new TOTP secret. Nothing changes until `totp_enable` proves
/// that the authenticator app produces matching codes.
pub async fn totp_setup(
    State(st): State<Shared>,
    _a: Admin,
    Json(req): Json<adm::AdminConfirmReq>,
) -> AppResult<Json<adm::TotpSetup>> {
    confirm_password(&st, req.password).await?;
    let secret = npw_otp::base32_encode(&npw_crypto::random_bytes::<20>());
    Ok(Json(adm::TotpSetup {
        uri: totp_uri(&secret),
        secret,
    }))
}

pub async fn totp_enable(
    State(st): State<Shared>,
    _a: Admin,
    Json(req): Json<adm::TotpEnableReq>,
) -> AppResult<Json<Value>> {
    confirm_password(&st, req.password).await?;
    let secret = req.secret.trim().to_uppercase();
    if secret.len() < 16 || npw_otp::OtpSpec::parse(&secret).is_err() {
        return Err(AppError::invalid("bad TOTP secret"));
    }
    if !totp_matches(&secret, &req.code)? {
        return Err(AppError::invalid(
            "the code does not match: check the authenticator app and the clock",
        ));
    }
    st.db
        .run(move |c| {
            db::set_setting(c, TOTP_KEY, &secret)?;
            db::audit(c, None, "admin_totp_on", "", "admin", "")?;
            Ok(())
        })
        .await?;
    Ok(Json(json!({})))
}

pub async fn totp_disable(
    State(st): State<Shared>,
    _a: Admin,
    Json(req): Json<adm::AdminConfirmReq>,
) -> AppResult<Json<Value>> {
    confirm_password(&st, req.password).await?;
    st.db
        .run(|c| {
            c.execute("DELETE FROM settings WHERE k = ?1", [TOTP_KEY])?;
            db::audit(c, None, "admin_totp_off", "", "admin", "")?;
            Ok(())
        })
        .await?;
    Ok(Json(json!({})))
}
