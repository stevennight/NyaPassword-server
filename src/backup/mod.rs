//! Automatic backups (design doc §8): consistent snapshot → age-encrypted
//! archive → every enabled target → read back and compare → retention →
//! alerts; weekly automatic restore drills.

pub mod notify;
pub mod targets;

use std::collections::BTreeMap;

use npw_api::admin::{BackupRun, BackupSettings, DrillRun, Retention, TargetResult};
use rusqlite::{params, Connection, OptionalExtension};

use crate::db::{self, now_ms};
use crate::error::{AppError, AppResult};
use crate::state::Shared;
use targets::StoredTarget;

const SETTINGS_KEY: &str = "backup_settings";
const MARKER_KEY: &str = "backup_marker";
const MANUAL_DRILL_KEY: &str = "manual_drill_at";
const ALERTED_KEY: &str = "backup_alerted_at";

pub fn default_settings() -> BackupSettings {
    BackupSettings { retention: Retention::default(), recipients: vec![], debounce_minutes: 10, daily_hour_utc: 19, notify: Default::default() }
}

pub fn load_settings(c: &Connection, st: &Shared) -> AppResult<BackupSettings> {
    match db::get_setting(c, SETTINGS_KEY)? {
        Some(sealed) => {
            let json = st.keys.open(SETTINGS_KEY, &sealed).ok_or_else(|| AppError::internal("backup settings: cannot decrypt (wrong server.key?)"))?;
            serde_json::from_str(&json).map_err(AppError::internal)
        }
        None => Ok(default_settings()),
    }
}

pub fn save_settings(c: &Connection, st: &Shared, s: &BackupSettings) -> AppResult<()> {
    let json = serde_json::to_string(s).map_err(AppError::internal)?;
    db::set_setting(c, SETTINGS_KEY, &st.keys.seal(SETTINGS_KEY, &json))?;
    Ok(())
}

pub fn load_targets(c: &Connection) -> AppResult<Vec<StoredTarget>> {
    let mut s = c.prepare("SELECT data FROM backup_targets ORDER BY created_at")?;
    let rows: Vec<String> = s.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    rows.iter().map(|d| serde_json::from_str(d).map_err(AppError::internal)).collect()
}

pub fn save_target(c: &Connection, t: &StoredTarget) -> AppResult<()> {
    c.execute(
        "INSERT INTO backup_targets (id, data, created_at) VALUES (?1, ?2, ?3) ON CONFLICT(id) DO UPDATE SET data = excluded.data",
        params![t.target.id, serde_json::to_string(t).map_err(AppError::internal)?, now_ms()],
    )?;
    Ok(())
}

/// Changes since the last backup? (vault sequences, vault metadata, attachments, account rows)
fn marker(c: &Connection) -> rusqlite::Result<String> {
    let seqs: i64 = c.query_row("SELECT COALESCE(SUM(seq), 0) + COALESCE(SUM(meta_revision), 0) FROM vaults", [], |r| r.get(0))?;
    let atts: i64 = c.query_row("SELECT COUNT(*) FROM attachments", [], |r| r.get(0))?;
    let acc: i64 = c.query_row("SELECT COALESCE(MAX(updated_at), 0) + COUNT(*) FROM accounts", [], |r| r.get(0))?;
    Ok(format!("{seqs}:{atts}:{acc}"))
}

pub fn pending_changes(c: &Connection) -> rusqlite::Result<bool> {
    Ok(db::get_setting(c, MARKER_KEY)?.as_deref() != Some(marker(c)?.as_str()))
}

pub fn runs(c: &Connection, limit: i64) -> AppResult<Vec<BackupRun>> {
    let mut s = c.prepare("SELECT data FROM backup_runs ORDER BY started_at DESC LIMIT ?1")?;
    let rows: Vec<String> = s.query_map([limit], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    Ok(rows.iter().filter_map(|d| serde_json::from_str(d).ok()).collect())
}

pub fn drills(c: &Connection, limit: i64) -> AppResult<Vec<DrillRun>> {
    let mut s = c.prepare("SELECT data FROM drill_runs ORDER BY at DESC LIMIT ?1")?;
    let rows: Vec<String> = s.query_map([limit], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    Ok(rows.iter().filter_map(|d| serde_json::from_str(d).ok()).collect())
}

pub fn manual_drill_at(c: &Connection) -> rusqlite::Result<Option<i64>> {
    Ok(db::get_setting(c, MANUAL_DRILL_KEY)?.and_then(|v| v.parse().ok()))
}

pub fn set_manual_drill(c: &Connection) -> rusqlite::Result<()> {
    db::set_setting(c, MANUAL_DRILL_KEY, &now_ms().to_string())
}

struct Snapshot {
    db: Vec<u8>,
    manifest: npw_backup::Manifest,
    marker: String,
    attachments: Vec<String>,
}

async fn snapshot(st: &Shared) -> AppResult<Snapshot> {
    let tmp = st.cfg.tmp_dir();
    std::fs::create_dir_all(&tmp).map_err(AppError::internal)?;
    let path = tmp.join(format!("snapshot-{}.sqlite3", uuid::Uuid::new_v4()));
    let p2 = path.clone();
    let epoch = st.epoch.clone();
    let (manifest, marker, attachments) = st
        .db
        .run(move |c| {
            // VACUUM INTO writes a consistent, compact copy while holding the lock
            c.execute("VACUUM INTO ?1", [p2.to_string_lossy().to_string()])?;
            let counts = crate::items::counts(c)?;
            let mut vaults = BTreeMap::new();
            let mut s = c.prepare("SELECT id, seq FROM vaults")?;
            for r in s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
                let (id, seq) = r?;
                vaults.insert(id, seq);
            }
            let mut s = c.prepare("SELECT id FROM attachments")?;
            let atts: Vec<String> = s.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
            let m = npw_backup::Manifest {
                format: npw_backup::FORMAT,
                created_at: now_ms(),
                server_version: env!("CARGO_PKG_VERSION").into(),
                epoch,
                accounts: counts["accounts"],
                items: counts["items"],
                revisions: counts["revisions"],
                attachments: counts["attachments"],
                vaults,
                files: Default::default(),
            };
            Ok((m, marker(c)?, atts))
        })
        .await?;
    let db = std::fs::read(&path).map_err(AppError::internal);
    let _ = std::fs::remove_file(&path);
    Ok(Snapshot { db: db?, manifest, marker, attachments })
}

/// Runs one backup to every enabled target. `trigger`: `change`, `daily`, `manual`.
pub async fn run_backup(st: &Shared, trigger: &str) -> AppResult<BackupRun> {
    let _guard = st.backup_lock.lock().await;
    let st2 = st.clone();
    let (settings, all_targets) = st.db.run(move |c| Ok((load_settings(c, &st2)?, load_targets(c)?))).await?;
    let targets: Vec<StoredTarget> = all_targets.into_iter().filter(|t| t.target.enabled).collect();
    let started_at = now_ms();
    let snap = snapshot(st).await?;
    let mut recipients = vec![st.keys.age_recipient()];
    recipients.extend(settings.recipients.iter().filter(|r| npw_backup::valid_recipient(r)).cloned());
    let key_file = std::fs::read(st.cfg.key_path()).map_err(AppError::internal)?;
    let archive = npw_backup::seal(snap.manifest.clone(), &[("db.sqlite3", &snap.db), ("server.key", &key_file)], &recipients).map_err(AppError::internal)?;
    let sha = npw_crypto::sha256_hex(&archive);
    let object = npw_backup::object_name(snap.manifest.created_at, snap.manifest.max_seq());

    let mut results = vec![];
    for t in &targets {
        let res = backup_to(st, t, &object, &archive, &sha, &snap.attachments, &settings.retention).await;
        let (ok, verified, error) = match res {
            Ok(v) => (true, v, String::new()),
            Err(e) => (false, false, format!("{e:#}")),
        };
        let tid = t.target.id.clone();
        let err = error.clone();
        st.db
            .run(move |c| {
                c.execute(
                    "INSERT INTO backup_target_state (target_id, last_success_at, last_attempt_at, last_error) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(target_id) DO UPDATE SET last_success_at = COALESCE(excluded.last_success_at, last_success_at),
                     last_attempt_at = excluded.last_attempt_at, last_error = excluded.last_error",
                    params![tid, if ok { Some(now_ms()) } else { None }, now_ms(), err],
                )?;
                Ok(())
            })
            .await?;
        results.push(TargetResult { target_id: t.target.id.clone(), ok, object: object.clone(), verified, error });
    }

    let run = BackupRun {
        id: uuid::Uuid::now_v7().to_string(),
        started_at,
        finished_at: now_ms(),
        trigger: trigger.into(),
        size: archive.len() as i64,
        items: snap.manifest.items,
        max_seq: snap.manifest.max_seq(),
        results,
    };
    let all_ok = !run.results.is_empty() && run.results.iter().all(|r| r.ok);
    let run2 = run.clone();
    let marker = snap.marker.clone();
    st.db
        .run(move |c| {
            c.execute("INSERT INTO backup_runs (id, started_at, data) VALUES (?1, ?2, ?3)", params![run2.id, run2.started_at, serde_json::to_string(&run2).map_err(AppError::internal)?])?;
            c.execute("DELETE FROM backup_runs WHERE id NOT IN (SELECT id FROM backup_runs ORDER BY started_at DESC LIMIT 500)", [])?;
            if all_ok {
                db::set_setting(c, MARKER_KEY, &marker)?;
            }
            Ok(())
        })
        .await?;
    let failed: Vec<&TargetResult> = run.results.iter().filter(|r| !r.ok).collect();
    if !failed.is_empty() {
        let body = failed.iter().map(|r| format!("{}: {}", r.target_id, r.error)).collect::<Vec<_>>().join("\n");
        notify::send(&settings.notify, "NyaPassword 备份失败", &body).await;
    }
    tracing::info!("backup {} ({}): {} bytes, {} ok / {} targets", run.id, trigger, run.size, run.results.iter().filter(|r| r.ok).count(), run.results.len());
    Ok(run)
}

/// Uploads the archive and new attachments, reads the archive back, prunes. Returns "verified".
async fn backup_to(st: &Shared, t: &StoredTarget, object: &str, archive: &[u8], sha: &str, attachments: &[String], retention: &Retention) -> anyhow::Result<bool> {
    let op = t.operator(&st.keys)?;
    targets::write(&op, object, archive.to_vec()).await?;
    let back = targets::read(&op, object).await?;
    if npw_crypto::sha256_hex(&back) != sha {
        anyhow::bail!("read-back of {object} does not match what was uploaded");
    }

    // attachments are immutable: copy each once per target
    let tid = t.target.id.clone();
    let done: std::collections::HashSet<String> = st
        .db
        .run(move |c| {
            let mut s = c.prepare("SELECT attachment_id FROM backup_target_blobs WHERE target_id = ?1")?;
            let rows = s.query_map([&tid], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
        .await?;
    for a in attachments.iter().filter(|a| !done.contains(*a)) {
        let data = tokio::fs::read(st.cfg.attachments_dir().join(a)).await?;
        targets::write(&op, &format!("{}{a}", npw_backup::ATTACHMENT_PREFIX), data).await?;
        let (tid, aid) = (t.target.id.clone(), a.clone());
        st.db
            .run(move |c| {
                c.execute("INSERT OR IGNORE INTO backup_target_blobs (target_id, attachment_id) VALUES (?1, ?2)", [tid, aid])?;
                Ok(())
            })
            .await?;
    }

    if !t.target.protect_mode {
        let objects = targets::list_backups(&op).await?;
        let times: Vec<i64> = objects.iter().map(|o| o.modified_at).collect();
        let keep = npw_backup::retain(&times, retention.recent as usize, retention.daily as usize, retention.weekly as usize, retention.monthly as usize);
        for o in objects {
            if o.name != object && !keep.contains(&o.modified_at) {
                if let Err(e) = targets::delete(&op, &o.name).await {
                    tracing::warn!("retention: could not delete {}: {e}", o.name);
                }
            }
        }
    }
    Ok(true)
}

/// Downloads the newest backup from a target and proves it restores.
pub async fn run_drill(st: &Shared, target_id: Option<String>) -> AppResult<DrillRun> {
    let _guard = st.backup_lock.lock().await;
    let all = st.db.run(|c| load_targets(c)).await?;
    let t = all
        .into_iter()
        .filter(|t| t.target.enabled)
        .find(|t| target_id.as_ref().is_none_or(|id| &t.target.id == id))
        .ok_or_else(|| AppError::invalid("no enabled backup target"))?;
    let started = now_ms();
    let (ok, object, detail) = match drill(st, &t).await {
        Ok((object, detail)) => (true, object, detail),
        Err(e) => (false, String::new(), format!("{e:#}")),
    };
    let run = DrillRun { id: uuid::Uuid::now_v7().to_string(), at: started, target_id: t.target.id.clone(), object, ok, detail, duration_ms: now_ms() - started };
    let r2 = run.clone();
    st.db
        .run(move |c| {
            c.execute("INSERT INTO drill_runs (id, at, data) VALUES (?1, ?2, ?3)", params![r2.id, r2.at, serde_json::to_string(&r2).map_err(AppError::internal)?])?;
            Ok(())
        })
        .await?;
    if !run.ok {
        let st2 = st.clone();
        let settings = st.db.run(move |c| load_settings(c, &st2)).await?;
        notify::send(&settings.notify, "NyaPassword 恢复演练失败", &format!("{}: {}", t.target.name, run.detail)).await;
    }
    Ok(run)
}

async fn drill(st: &Shared, t: &StoredTarget) -> anyhow::Result<(String, String)> {
    let op = t.operator(&st.keys)?;
    let latest = targets::list_backups(&op).await?.into_iter().next().ok_or_else(|| anyhow::anyhow!("the target has no backups"))?;
    let data = targets::read(&op, &latest.name).await?;
    let (manifest, files) = npw_backup::open(&data, &[st.keys.age_identity.clone()])?;
    let db_bytes = files.get("db.sqlite3").ok_or_else(|| anyhow::anyhow!("archive has no database"))?;
    let dir = tempfile::Builder::new().prefix("drill-").tempdir_in({
        std::fs::create_dir_all(st.cfg.tmp_dir())?;
        st.cfg.tmp_dir()
    })?;
    let path = dir.path().join("db.sqlite3");
    std::fs::write(&path, db_bytes)?;
    let (items, revisions, sample) = check_snapshot(&path, &manifest)?;
    let present: std::collections::HashSet<String> = if sample.is_empty() { Default::default() } else { targets::list_attachments(&op).await?.into_iter().collect() };
    let missing: Vec<&String> = sample.iter().filter(|a| !present.contains(*a)).collect();
    if !missing.is_empty() {
        anyhow::bail!("{} of {} sampled attachments are missing on the target", missing.len(), sample.len());
    }
    Ok((
        latest.name.clone(),
        format!(
            "{}：解密成功，integrity_check 通过，{} 个条目 / {} 个版本与清单一致，附件抽查 {}/{} 存在",
            latest.name,
            items,
            revisions,
            sample.len(),
            sample.len()
        ),
    ))
}

/// Synchronous checks of a restored database: (items, revisions, sampled attachment ids).
fn check_snapshot(path: &std::path::Path, manifest: &npw_backup::Manifest) -> anyhow::Result<(i64, i64, Vec<String>)> {
    let c = Connection::open(path)?;
    let integrity: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    if integrity != "ok" {
        anyhow::bail!("integrity_check: {integrity}");
    }
    let items: i64 = c.query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))?;
    let revisions: i64 = c.query_row("SELECT COUNT(*) FROM item_revisions", [], |r| r.get(0))?;
    if items != manifest.items || revisions != manifest.revisions {
        anyhow::bail!("counts differ from the manifest: items {items}/{}, revisions {revisions}/{}", manifest.items, manifest.revisions);
    }
    // every item head must point at an existing revision
    let dangling: i64 = c.query_row(
        "SELECT COUNT(*) FROM items i LEFT JOIN item_revisions r ON r.vault_id = i.vault_id AND r.item_id = i.item_id AND r.revision = i.revision WHERE r.item_id IS NULL",
        [],
        |r| r.get(0),
    )?;
    if dangling > 0 {
        anyhow::bail!("{dangling} items point at missing revisions");
    }
    let mut s = c.prepare("SELECT id FROM attachments ORDER BY RANDOM() LIMIT 20")?;
    let sample: Vec<String> = s.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    Ok((items, revisions, sample))
}

/// The scheduler: debounced backups after changes, a daily backup, a weekly
/// drill, and an alert when nothing succeeded for 26 hours.
pub async fn scheduler(st: Shared) {
    loop {
        tokio::select! {
            _ = st.changed.notified() => {}
            _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
        }
        if let Err(e) = tick(&st).await {
            tracing::warn!("backup scheduler: {}", e.message);
        }
    }
}

async fn tick(st: &Shared) -> AppResult<()> {
    let st2 = st.clone();
    let (settings, targets, pending, last_run, last_drill, last_success, alerted) = st
        .db
        .run(move |c| {
            let targets: Vec<StoredTarget> = load_targets(c)?.into_iter().filter(|t| t.target.enabled).collect();
            let last_run: Option<i64> = c.query_row("SELECT MAX(started_at) FROM backup_runs", [], |r| r.get(0))?;
            let last_drill: Option<i64> = c.query_row("SELECT MAX(at) FROM drill_runs", [], |r| r.get(0))?;
            let last_success: Option<i64> = c.query_row("SELECT MAX(last_success_at) FROM backup_target_state", [], |r| r.get(0)).optional()?.flatten();
            let alerted: i64 = db::get_setting(c, ALERTED_KEY)?.and_then(|v| v.parse().ok()).unwrap_or(0);
            Ok((load_settings(c, &st2)?, targets, pending_changes(c)?, last_run.unwrap_or(0), last_drill.unwrap_or(0), last_success, alerted))
        })
        .await?;
    if targets.is_empty() {
        return Ok(());
    }
    let now = now_ms();
    let last_change = *st.last_change_at.lock().expect("lock");
    let hour = 3_600_000;
    let quiet = now - last_change >= settings.debounce_minutes as i64 * 60_000;
    if pending && quiet && now - last_run >= hour {
        run_backup(st, "change").await?;
    } else {
        let day_start = now - now.rem_euclid(86_400_000);
        let daily_at = day_start + settings.daily_hour_utc as i64 * hour;
        if now >= daily_at && last_run < daily_at {
            run_backup(st, "daily").await?;
        }
    }
    if now - last_drill >= 7 * 24 * hour && now - last_run < 30 * 60_000 {
        run_drill(st, None).await?;
    }
    let stale = last_success.is_none_or(|t| now - t > 26 * hour);
    if stale && now - alerted > 24 * hour && now - st.started_at > hour {
        notify::send(&settings.notify, "NyaPassword 备份告警", "超过 26 小时没有成功的备份，请检查备份目标。").await;
        st.db.run(move |c| Ok(db::set_setting(c, ALERTED_KEY, &now.to_string())?)).await?;
    }
    Ok(())
}
