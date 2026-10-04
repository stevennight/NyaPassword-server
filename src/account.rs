//! Account, vaults, devices, audit log, password change.

use axum::extract::{Path, State};
use axum::Json;
use npw_api as api;
use npw_crypto::{b64, opaque, unb64};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::db::{self, now_ms};
use crate::error::{AppError, AppResult};
use crate::state::Shared;

fn ok() -> Json<Value> {
    Json(json!({}))
}

pub fn is_member(c: &Connection, vault_id: &str, account_id: &str) -> rusqlite::Result<bool> {
    Ok(c.query_row("SELECT 1 FROM vault_members WHERE vault_id = ?1 AND account_id = ?2", [vault_id, account_id], |_| Ok(())).optional()?.is_some())
}

pub fn require_member(c: &Connection, vault_id: &str, account_id: &str) -> AppResult<()> {
    if is_member(c, vault_id, account_id)? {
        Ok(())
    } else {
        Err(AppError::not_found())
    }
}

/// Accounts that can see a vault (for change notifications).
pub fn vault_accounts(c: &Connection, vault_id: &str) -> rusqlite::Result<Vec<String>> {
    let mut s = c.prepare_cached("SELECT account_id FROM vault_members WHERE vault_id = ?1")?;
    let rows = s.query_map([vault_id], |r| r.get(0))?;
    rows.collect()
}

pub async fn get_account(State(st): State<Shared>, user: AuthUser) -> AppResult<Json<api::AccountResp>> {
    let r = st
        .db
        .run(move |c| {
            let (login, kdf, salt, eak, pk, epk, eakr, created): (String, String, String, String, String, String, Option<String>, i64) = c.query_row(
                "SELECT login, kdf, account_salt, encrypted_account_key, public_key, encrypted_private_key, encrypted_account_key_recovery, created_at FROM accounts WHERE id = ?1",
                [&user.account_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
            )?;
            let mut s = c.prepare(
                "SELECT v.id, m.wrapped_key, v.encrypted_meta, v.meta_revision, v.seq, m.role, v.created_at FROM vault_members m JOIN vaults v ON v.id = m.vault_id
                 WHERE m.account_id = ?1 ORDER BY v.created_at",
            )?;
            let vaults = s
                .query_map([&user.account_id], |r| {
                    Ok(api::VaultInfo {
                        id: r.get(0)?,
                        wrapped_key: r.get(1)?,
                        encrypted_meta: r.get(2)?,
                        meta_revision: r.get(3)?,
                        seq: r.get(4)?,
                        role: r.get(5)?,
                        created_at: r.get(6)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(api::AccountResp {
                account_id: user.account_id.clone(),
                login,
                kdf: serde_json::from_str(&kdf).map_err(AppError::internal)?,
                account_salt: salt,
                encrypted_account_key: eak,
                public_key: pk,
                encrypted_private_key: epk,
                encrypted_account_key_recovery: eakr,
                vaults,
                created_at: created,
            })
        })
        .await?;
    Ok(Json(r))
}

pub async fn create_vault(State(st): State<Shared>, user: AuthUser, Json(req): Json<api::CreateVaultReq>) -> AppResult<Json<Value>> {
    uuid::Uuid::parse_str(&req.id).map_err(|_| AppError::invalid("bad vault id"))?;
    for v in [&req.wrapped_key, &req.encrypted_meta] {
        unb64(v).ok_or_else(|| AppError::invalid("bad base64"))?;
    }
    st.db
        .run(move |c| {
            let tx = c.transaction()?;
            if tx.query_row("SELECT 1 FROM vaults WHERE id = ?1", [&req.id], |_| Ok(())).optional()?.is_some() {
                return Err(AppError::conflict("vault exists"));
            }
            let now = now_ms();
            tx.execute("INSERT INTO vaults (id, seq, encrypted_meta, meta_revision, created_by, created_at) VALUES (?1, 0, ?2, 1, ?3, ?4)", params![req.id, req.encrypted_meta, user.account_id, now])?;
            tx.execute(
                "INSERT INTO vault_members (vault_id, account_id, role, wrapped_key, created_at) VALUES (?1, ?2, 'owner', ?3, ?4)",
                params![req.id, user.account_id, req.wrapped_key, now],
            )?;
            db::audit(&tx, Some(&user.account_id), "vault_create", &user.device_id, &user.ip, &req.id)?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    st.notify_change();
    Ok(ok())
}

pub async fn update_vault_meta(State(st): State<Shared>, user: AuthUser, Path(vault_id): Path<String>, Json(req): Json<api::UpdateVaultMetaReq>) -> AppResult<Json<Value>> {
    unb64(&req.encrypted_meta).ok_or_else(|| AppError::invalid("bad base64"))?;
    let account = user.account_id.clone();
    st.db
        .run(move |c| {
            require_member(c, &vault_id, &user.account_id)?;
            let n = c.execute(
                "UPDATE vaults SET encrypted_meta = ?2, meta_revision = meta_revision + 1 WHERE id = ?1 AND meta_revision = ?3",
                params![vault_id, req.encrypted_meta, req.base_revision],
            )?;
            if n == 0 {
                return Err(AppError::conflict("vault metadata changed meanwhile"));
            }
            Ok(())
        })
        .await?;
    let _ = st.events.send((account, api::Event::AccountChanged));
    st.notify_change();
    Ok(ok())
}

pub async fn password_start(State(st): State<Shared>, user: AuthUser, Json(req): Json<api::ReRegisterStartReq>) -> AppResult<Json<api::OpaqueResp>> {
    let id = uuid::Uuid::parse_str(&user.account_id).map_err(AppError::internal)?;
    let resp = opaque::server_register_start(&st.opaque_setup, &unb64(&req.opaque_request).ok_or_else(|| AppError::invalid("bad base64"))?, id.as_bytes())?;
    Ok(Json(api::OpaqueResp { opaque_response: b64(&resp) }))
}

pub async fn password_finish(State(st): State<Shared>, user: AuthUser, Json(req): Json<api::ChangePasswordFinishReq>) -> AppResult<Json<Value>> {
    if !st.cfg.allow_weak_kdf {
        req.kdf.validate()?;
    }
    let record = opaque::server_register_finish(&unb64(&req.opaque_upload).ok_or_else(|| AppError::invalid("bad base64"))?)?;
    st.db
        .run(move |c| {
            let tx = c.transaction()?;
            tx.execute(
                "UPDATE accounts SET opaque_record = ?2, kdf = ?3, account_salt = ?4, encrypted_account_key = ?5, updated_at = ?6 WHERE id = ?1",
                params![user.account_id, record, serde_json::to_string(&req.kdf).map_err(AppError::internal)?, req.account_salt, req.encrypted_account_key, now_ms()],
            )?;
            // other devices must sign in again with the new password
            tx.execute("DELETE FROM sessions WHERE account_id = ?1 AND device_id != ?2", [&user.account_id, &user.device_id])?;
            db::audit(&tx, Some(&user.account_id), "password_change", &user.device_id, &user.ip, "")?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    st.notify_change();
    Ok(ok())
}

pub async fn devices(State(st): State<Shared>, user: AuthUser) -> AppResult<Json<Vec<api::DeviceRecord>>> {
    let r = st
        .db
        .run(move |c| {
            let mut s = c.prepare("SELECT id, name, platform, client_version, created_at, last_seen_at, revoked_at FROM devices WHERE account_id = ?1 ORDER BY last_seen_at DESC")?;
            let rows = s
                .query_map([&user.account_id], |r| {
                    let id: String = r.get(0)?;
                    Ok(api::DeviceRecord {
                        current: id == user.device_id,
                        id,
                        name: r.get(1)?,
                        platform: r.get(2)?,
                        client_version: r.get(3)?,
                        created_at: r.get(4)?,
                        last_seen_at: r.get(5)?,
                        revoked_at: r.get(6)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(r))
}

pub async fn revoke_device(State(st): State<Shared>, user: AuthUser, Path(device_id): Path<String>) -> AppResult<Json<Value>> {
    let account = user.account_id.clone();
    let dev = device_id.clone();
    st.db
        .run(move |c| {
            let tx = c.transaction()?;
            let n = tx.execute("UPDATE devices SET revoked_at = ?3 WHERE id = ?1 AND account_id = ?2 AND revoked_at IS NULL", params![device_id, user.account_id, now_ms()])?;
            if n == 0 {
                return Err(AppError::not_found());
            }
            tx.execute("DELETE FROM sessions WHERE device_id = ?1", [&device_id])?;
            db::audit(&tx, Some(&user.account_id), "device_revoke", &user.device_id, &user.ip, &device_id)?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    let _ = st.events.send((account, api::Event::DeviceRevoked { device_id: dev }));
    Ok(ok())
}

pub async fn audit_log(State(st): State<Shared>, user: AuthUser) -> AppResult<Json<Vec<api::AuditEntry>>> {
    let r = st
        .db
        .run(move |c| {
            let mut s = c.prepare("SELECT at, action, device_id, ip, detail FROM audit WHERE account_id = ?1 ORDER BY id DESC LIMIT 500")?;
            let rows = s
                .query_map([&user.account_id], |r| Ok(api::AuditEntry { at: r.get(0)?, action: r.get(1)?, device_id: r.get(2)?, ip: r.get(3)?, detail: r.get(4)? }))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(r))
}
