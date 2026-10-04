//! Items: changes, writes with optimistic concurrency, digests, revisions,
//! purge, attachments.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;
use npw_api::{self as api, ItemRecord, PushResult, PushStatus};
use npw_crypto::{b64, unb64};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;

use crate::account::{require_member, vault_accounts};
use crate::auth::AuthUser;
use crate::db::{self, now_ms};
use crate::error::{AppError, AppResult};
use crate::state::Shared;

#[derive(Deserialize)]
pub struct ChangesQuery {
    #[serde(default)]
    since: i64,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    500
}

fn record_from_row(r: &rusqlite::Row) -> rusqlite::Result<ItemRecord> {
    let wk: Vec<u8> = r.get(5)?;
    let ct: Vec<u8> = r.get(6)?;
    Ok(ItemRecord {
        item_id: r.get(0)?,
        revision: r.get(1)?,
        seq: r.get(2)?,
        deleted: r.get::<_, i64>(3)? != 0,
        format_major: r.get::<_, i64>(4)? as u16,
        wrapped_key: b64(&wk),
        ciphertext: b64(&ct),
        hash: r.get(7)?,
        updated_at: r.get(8)?,
        device_id: r.get(9)?,
    })
}

const RECORD_COLS: &str = "r.item_id, r.revision, r.seq, r.deleted, r.format_major, r.wrapped_key, r.ciphertext, r.hash, r.created_at, r.device_id";

pub async fn changes(State(st): State<Shared>, user: AuthUser, Path(vault_id): Path<String>, Query(q): Query<ChangesQuery>) -> AppResult<Json<api::ChangesResp>> {
    let limit = q.limit.clamp(1, 1000);
    let r = st
        .db
        .run(move |c| {
            require_member(c, &vault_id, &user.account_id)?;
            let vault_seq: i64 = c.query_row("SELECT seq FROM vaults WHERE id = ?1", [&vault_id], |r| r.get(0))?;
            let sql = format!(
                "SELECT {RECORD_COLS} FROM items i JOIN item_revisions r ON r.vault_id = i.vault_id AND r.item_id = i.item_id AND r.revision = i.revision
                 WHERE i.vault_id = ?1 AND i.seq > ?2 ORDER BY i.seq LIMIT ?3"
            );
            let mut s = c.prepare_cached(&sql)?;
            let items = s.query_map(params![vault_id, q.since, limit], record_from_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
            let has_more = items.len() as i64 == limit;
            let next_seq = items.last().map(|r| r.seq).unwrap_or(q.since.min(vault_seq));
            let purged = if has_more {
                vec![]
            } else {
                let mut s = c.prepare_cached("SELECT item_id FROM purged WHERE vault_id = ?1 AND seq > ?2")?;
                let rows = s.query_map(params![vault_id, q.since], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
                rows
            };
            let next_seq = if has_more { next_seq } else { vault_seq.max(next_seq) };
            Ok(api::ChangesResp { items, next_seq, has_more, vault_seq, purged })
        })
        .await?;
    Ok(Json(r))
}

pub async fn digest(State(st): State<Shared>, user: AuthUser, Path(vault_id): Path<String>) -> AppResult<Json<api::DigestResp>> {
    let r = st
        .db
        .run(move |c| {
            require_member(c, &vault_id, &user.account_id)?;
            let vault_seq: i64 = c.query_row("SELECT seq FROM vaults WHERE id = ?1", [&vault_id], |r| r.get(0))?;
            let mut s = c.prepare_cached("SELECT item_id, revision, deleted, hash FROM items WHERE vault_id = ?1")?;
            let rows: Vec<(String, i64, bool, String)> =
                s.query_map([&vault_id], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0, r.get(3)?)))?.collect::<rusqlite::Result<_>>()?;
            let digest = api::vault_digest(rows.iter().map(|(i, r, d, h)| (i.as_str(), *r, *d, h.as_str())));
            Ok(api::DigestResp { digest, count: rows.len() as i64, vault_seq })
        })
        .await?;
    Ok(Json(r))
}

struct Prepared {
    item: api::PushItem,
    wk: Vec<u8>,
    ct: Vec<u8>,
    hash: String,
}

/// Applies one write inside the caller's transaction.
fn apply_one(c: &Connection, vault_id: &str, device_id: &str, p: &Prepared) -> rusqlite::Result<PushResult> {
    let it = &p.item;
    // idempotent retries
    if let Some((item_id, revision, seq)) =
        c.query_row("SELECT item_id, revision, seq FROM ops WHERE op_id = ?1", [&it.op_id], |r| Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?))).optional()?
    {
        return Ok(PushResult { op_id: it.op_id.clone(), item_id, status: PushStatus::Ok, revision: Some(revision), seq: Some(seq), current_revision: None, reason: None });
    }
    let current: Option<i64> = c.query_row("SELECT revision FROM items WHERE vault_id = ?1 AND item_id = ?2", [vault_id, &it.item_id], |r| r.get(0)).optional()?;
    let cur = current.unwrap_or(0);
    if cur != it.base_revision {
        return Ok(PushResult {
            op_id: it.op_id.clone(),
            item_id: it.item_id.clone(),
            status: PushStatus::Conflict,
            revision: None,
            seq: None,
            current_revision: Some(cur),
            reason: None,
        });
    }
    let revision = cur + 1;
    if cur == 0 {
        // re-created after a purge: the tombstone no longer applies
        c.execute("DELETE FROM purged WHERE vault_id = ?1 AND item_id = ?2", [vault_id, &it.item_id])?;
    }
    let seq: i64 = c.query_row("UPDATE vaults SET seq = seq + 1 WHERE id = ?1 RETURNING seq", [vault_id], |r| r.get(0))?;
    let now = now_ms();
    c.execute(
        "INSERT INTO item_revisions (vault_id, item_id, revision, seq, deleted, format_major, wrapped_key, ciphertext, hash, size, device_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![vault_id, it.item_id, revision, seq, it.deleted as i64, it.format_major as i64, p.wk, p.ct, p.hash, (p.wk.len() + p.ct.len()) as i64, device_id, now],
    )?;
    c.execute(
        "INSERT INTO items (vault_id, item_id, revision, seq, deleted, hash, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(vault_id, item_id) DO UPDATE SET revision = excluded.revision, seq = excluded.seq, deleted = excluded.deleted, hash = excluded.hash, updated_at = excluded.updated_at",
        params![vault_id, it.item_id, revision, seq, it.deleted as i64, p.hash, now],
    )?;
    c.execute("INSERT INTO ops (op_id, vault_id, item_id, revision, seq, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![it.op_id, vault_id, it.item_id, revision, seq, now])?;
    Ok(PushResult { op_id: it.op_id.clone(), item_id: it.item_id.clone(), status: PushStatus::Ok, revision: Some(revision), seq: Some(seq), current_revision: None, reason: None })
}

fn reject(it: &api::PushItem, reason: &str) -> PushResult {
    PushResult { op_id: it.op_id.clone(), item_id: it.item_id.clone(), status: PushStatus::Rejected, revision: None, seq: None, current_revision: None, reason: Some(reason.into()) }
}

pub async fn push(State(st): State<Shared>, user: AuthUser, Path(vault_id): Path<String>, Json(req): Json<api::PushReq>) -> AppResult<Json<api::PushResp>> {
    if req.items.len() > 1000 {
        return Err(AppError::invalid("at most 1000 items per request"));
    }
    let max_item = (st.cfg.max_item_kb * 1024) as usize;
    let mut results: Vec<Option<PushResult>> = vec![None; req.items.len()];
    let mut prepared: Vec<(usize, Prepared)> = vec![];
    let mut seen = std::collections::HashSet::new();
    for (i, it) in req.items.into_iter().enumerate() {
        let check = || -> Result<Prepared, &'static str> {
            uuid::Uuid::parse_str(&it.item_id).map_err(|_| "bad item id")?;
            if it.op_id.is_empty() || it.op_id.len() > 100 {
                return Err("bad op id");
            }
            if it.base_revision < 0 || it.format_major == 0 {
                return Err("bad revision or format");
            }
            let wk = unb64(&it.wrapped_key).ok_or("bad base64")?;
            let ct = unb64(&it.ciphertext).ok_or("bad base64")?;
            if wk.is_empty() || ct.is_empty() {
                return Err("empty ciphertext");
            }
            if wk.len() + ct.len() > max_item {
                return Err("item too large");
            }
            let hash = api::item_hash(&wk, &ct);
            Ok(Prepared { item: it.clone(), wk, ct, hash })
        };
        if !seen.insert(it.item_id.clone()) {
            results[i] = Some(reject(&it, "item appears twice in one request"));
            continue;
        }
        match check() {
            Ok(p) => prepared.push((i, p)),
            Err(reason) => results[i] = Some(reject(&it, reason)),
        }
    }
    let atomic = req.atomic;
    let any_invalid = results.iter().any(|r| r.is_some());
    let vid = vault_id.clone();
    let (results, vault_seq, accounts, wrote) = st
        .db
        .run(move |c| {
            require_member(c, &vid, &user.account_id)?;
            let tx = c.transaction()?;
            let mut out = results;
            let mut wrote = 0;
            if atomic && any_invalid {
                for (i, p) in &prepared {
                    out[*i] = Some(reject(&p.item, "batch aborted"));
                }
            } else {
                for (i, p) in &prepared {
                    let r = apply_one(&tx, &vid, &user.device_id, p)?;
                    if r.status == PushStatus::Ok {
                        wrote += 1;
                    }
                    out[*i] = Some(r);
                }
            }
            let failed = out.iter().any(|r| r.as_ref().is_some_and(|r| r.status != PushStatus::Ok));
            if atomic && failed {
                tx.rollback()?;
                let out: Vec<PushResult> = out
                    .into_iter()
                    .flatten()
                    .map(|r| if r.status == PushStatus::Ok { PushResult { status: PushStatus::Rejected, revision: None, seq: None, reason: Some("batch aborted".into()), ..r } } else { r })
                    .collect();
                let seq: i64 = c.query_row("SELECT seq FROM vaults WHERE id = ?1", [&vid], |r| r.get(0))?;
                return Ok((out, seq, vec![], 0));
            }
            let seq: i64 = tx.query_row("SELECT seq FROM vaults WHERE id = ?1", [&vid], |r| r.get(0))?;
            if wrote > 0 && atomic {
                db::audit(&tx, Some(&user.account_id), "import", &user.device_id, &user.ip, &format!("{wrote} items"))?;
            }
            tx.commit()?;
            let accounts = vault_accounts(c, &vid)?;
            Ok((out.into_iter().flatten().collect(), seq, accounts, wrote))
        })
        .await?;
    if wrote > 0 {
        for a in accounts {
            let _ = st.events.send((a, api::Event::VaultChanged { vault_id: vault_id.clone(), seq: vault_seq }));
        }
        st.notify_change();
    }
    Ok(Json(api::PushResp { results, vault_seq }))
}

pub async fn revisions(State(st): State<Shared>, user: AuthUser, Path((vault_id, item_id)): Path<(String, String)>) -> AppResult<Json<api::RevisionsResp>> {
    let r = st
        .db
        .run(move |c| {
            require_member(c, &vault_id, &user.account_id)?;
            let mut s = c.prepare("SELECT revision, deleted, created_at, device_id, size, hash FROM item_revisions WHERE vault_id = ?1 AND item_id = ?2 ORDER BY revision DESC")?;
            let revisions = s
                .query_map([&vault_id, &item_id], |r| {
                    Ok(api::RevisionInfo { revision: r.get(0)?, deleted: r.get::<_, i64>(1)? != 0, created_at: r.get(2)?, device_id: r.get(3)?, size: r.get(4)?, hash: r.get(5)? })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if revisions.is_empty() {
                return Err(AppError::not_found());
            }
            Ok(api::RevisionsResp { revisions })
        })
        .await?;
    Ok(Json(r))
}

pub async fn revision(State(st): State<Shared>, user: AuthUser, Path((vault_id, item_id, rev)): Path<(String, String, i64)>) -> AppResult<Json<ItemRecord>> {
    let r = st
        .db
        .run(move |c| {
            require_member(c, &vault_id, &user.account_id)?;
            let sql = format!("SELECT {RECORD_COLS} FROM item_revisions r WHERE r.vault_id = ?1 AND r.item_id = ?2 AND r.revision = ?3");
            c.query_row(&sql, params![vault_id, item_id, rev], record_from_row).optional()?.ok_or_else(AppError::not_found)
        })
        .await?;
    Ok(Json(r))
}

pub async fn purge(State(st): State<Shared>, user: AuthUser, Path(vault_id): Path<String>, Json(req): Json<api::PurgeReq>) -> AppResult<Json<api::PurgeResp>> {
    let att_dir = st.cfg.attachments_dir();
    let vid = vault_id.clone();
    let (purged, files) = st
        .db
        .run(move |c| {
            require_member(c, &vid, &user.account_id)?;
            let tx = c.transaction()?;
            let mut purged = vec![];
            let mut files = vec![];
            for id in req.item_ids {
                let deleted: Option<i64> = tx.query_row("SELECT deleted FROM items WHERE vault_id = ?1 AND item_id = ?2", [&vid, &id], |r| r.get(0)).optional()?;
                if deleted != Some(1) {
                    continue; // only items in the trash
                }
                tx.execute("DELETE FROM item_revisions WHERE vault_id = ?1 AND item_id = ?2", [&vid, &id])?;
                tx.execute("DELETE FROM items WHERE vault_id = ?1 AND item_id = ?2", [&vid, &id])?;
                let seq: i64 = tx.query_row("UPDATE vaults SET seq = seq + 1 WHERE id = ?1 RETURNING seq", [&vid], |r| r.get(0))?;
                tx.execute(
                    "INSERT INTO purged (vault_id, item_id, seq, at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(vault_id, item_id) DO UPDATE SET seq = excluded.seq, at = excluded.at",
                    params![vid, id, seq, now_ms()],
                )?;
                let mut s = tx.prepare("SELECT id FROM attachments WHERE vault_id = ?1 AND item_id = ?2")?;
                let atts: Vec<String> = s.query_map([&vid, &id], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
                drop(s);
                tx.execute("DELETE FROM attachments WHERE vault_id = ?1 AND item_id = ?2", [&vid, &id])?;
                files.extend(atts);
                purged.push(id);
            }
            if !purged.is_empty() {
                db::audit(&tx, Some(&user.account_id), "purge", &user.device_id, &user.ip, &format!("{} items", purged.len()))?;
            }
            tx.commit()?;
            Ok((purged, files))
        })
        .await?;
    for f in files {
        let _ = tokio::fs::remove_file(att_dir.join(&f)).await;
    }
    st.notify_change();
    Ok(Json(api::PurgeResp { purged }))
}

#[derive(Deserialize)]
pub struct AttachmentQuery {
    item: String,
}

pub async fn put_attachment(
    State(st): State<Shared>,
    user: AuthUser,
    Path((vault_id, att_id)): Path<(String, String)>,
    Query(q): Query<AttachmentQuery>,
    body: Bytes,
) -> AppResult<Json<api::AttachmentInfo>> {
    uuid::Uuid::parse_str(&att_id).map_err(|_| AppError::invalid("bad attachment id"))?;
    uuid::Uuid::parse_str(&q.item).map_err(|_| AppError::invalid("bad item id"))?;
    if body.is_empty() {
        return Err(AppError::invalid("empty attachment"));
    }
    let sha = npw_crypto::sha256_hex(&body);
    let dir = st.cfg.attachments_dir();
    let (v, a) = (vault_id.clone(), att_id.clone());
    let uid = user.account_id.clone();
    let existing = st
        .db
        .run(move |c| {
            require_member(c, &v, &uid)?;
            Ok(c.query_row("SELECT sha256 FROM attachments WHERE id = ?1", [&a], |r| r.get::<_, String>(0)).optional()?)
        })
        .await?;
    match existing {
        Some(s) if s == sha => return Ok(Json(api::AttachmentInfo { id: att_id, size: body.len() as i64, sha256: sha })),
        Some(_) => return Err(AppError::conflict("attachment exists with different content")),
        None => {}
    }
    tokio::fs::create_dir_all(&dir).await.map_err(AppError::internal)?;
    let tmp = dir.join(format!("{att_id}.part"));
    tokio::fs::write(&tmp, &body).await.map_err(AppError::internal)?;
    tokio::fs::rename(&tmp, dir.join(&att_id)).await.map_err(AppError::internal)?;
    let size = body.len() as i64;
    let (a, s2) = (att_id.clone(), sha.clone());
    st.db
        .run(move |c| {
            c.execute(
                "INSERT INTO attachments (id, vault_id, item_id, size, sha256, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![a, vault_id, q.item, size, s2, now_ms()],
            )?;
            Ok(())
        })
        .await?;
    st.notify_change();
    Ok(Json(api::AttachmentInfo { id: att_id, size, sha256: sha }))
}

pub async fn get_attachment(State(st): State<Shared>, user: AuthUser, Path((vault_id, att_id)): Path<(String, String)>) -> AppResult<impl IntoResponse> {
    let a = att_id.clone();
    st.db
        .run(move |c| {
            require_member(c, &vault_id, &user.account_id)?;
            c.query_row("SELECT 1 FROM attachments WHERE id = ?1 AND vault_id = ?2", [&a, &vault_id], |_| Ok(())).optional()?.ok_or_else(AppError::not_found)
        })
        .await?;
    let data = tokio::fs::read(st.cfg.attachments_dir().join(&att_id)).await.map_err(|_| AppError::not_found())?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], data))
}

/// Counts for health and manifests.
pub fn counts(c: &Connection) -> rusqlite::Result<HashMap<&'static str, i64>> {
    let mut m = HashMap::new();
    for (k, sql) in [
        ("accounts", "SELECT COUNT(*) FROM accounts"),
        ("devices", "SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL"),
        ("items", "SELECT COUNT(*) FROM items"),
        ("revisions", "SELECT COUNT(*) FROM item_revisions"),
        ("attachments", "SELECT COUNT(*) FROM attachments"),
        ("attachment_bytes", "SELECT COALESCE(SUM(size), 0) FROM attachments"),
    ] {
        m.insert(k, c.query_row(sql, [], |r| r.get(0))?);
    }
    Ok(m)
}
