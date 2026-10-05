//! The server database (SQLite, WAL). Item revisions are append-only: a write
//! adds a revision, deleting moves to the trash (also a revision), and only an
//! explicit purge of trashed items removes rows.

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension};

use crate::error::{AppError, AppResult};

const MIGRATIONS: &[&str] = &[
    r#"
CREATE TABLE settings (k TEXT PRIMARY KEY, v TEXT NOT NULL);

CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    login TEXT NOT NULL UNIQUE COLLATE NOCASE,
    opaque_record BLOB NOT NULL,
    opaque_recovery BLOB,
    kdf TEXT NOT NULL,
    account_salt TEXT NOT NULL,
    encrypted_account_key TEXT NOT NULL,
    encrypted_account_key_recovery TEXT,
    public_key TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    name TEXT NOT NULL,
    platform TEXT NOT NULL,
    client_version TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    account_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX sessions_device ON sessions(device_id);

CREATE TABLE login_attempts (
    id TEXT PRIMARY KEY,
    account_id TEXT,
    state BLOB NOT NULL,
    method TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE vaults (
    id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL DEFAULT 0,
    encrypted_meta TEXT NOT NULL,
    meta_revision INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- v1 has one member (the owner) per vault; sharing adds rows here.
CREATE TABLE vault_members (
    vault_id TEXT NOT NULL REFERENCES vaults(id),
    account_id TEXT NOT NULL REFERENCES accounts(id),
    role TEXT NOT NULL,
    wrapped_key TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (vault_id, account_id)
);

CREATE TABLE item_revisions (
    vault_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    deleted INTEGER NOT NULL,
    format_major INTEGER NOT NULL,
    wrapped_key BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    hash TEXT NOT NULL,
    size INTEGER NOT NULL,
    device_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (vault_id, item_id, revision)
);

CREATE TABLE items (
    vault_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    deleted INTEGER NOT NULL,
    hash TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (vault_id, item_id)
);
CREATE INDEX items_seq ON items(vault_id, seq);

-- tombstones of permanently deleted items
CREATE TABLE purged (
    vault_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    at INTEGER NOT NULL,
    PRIMARY KEY (vault_id, item_id)
);

CREATE TABLE ops (
    op_id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE attachments (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT,
    at INTEGER NOT NULL,
    action TEXT NOT NULL,
    device_id TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_account ON audit(account_id, at);

CREATE TABLE invites (
    code_hash TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE backup_targets (id TEXT PRIMARY KEY, data TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE backup_target_state (
    target_id TEXT PRIMARY KEY,
    last_success_at INTEGER,
    last_attempt_at INTEGER,
    last_error TEXT NOT NULL DEFAULT ''
);
-- attachments already copied to a target
CREATE TABLE backup_target_blobs (target_id TEXT NOT NULL, attachment_id TEXT NOT NULL, PRIMARY KEY (target_id, attachment_id));
CREATE TABLE backup_runs (id TEXT PRIMARY KEY, started_at INTEGER NOT NULL, data TEXT NOT NULL);
CREATE TABLE drill_runs (id TEXT PRIMARY KEY, at INTEGER NOT NULL, data TEXT NOT NULL);
"#,
    r#"
-- Idempotency records are scoped to the vault and the writing account: an op_id
-- used elsewhere must never make a write look already done.
CREATE TABLE ops_scoped (
    vault_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    op_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (vault_id, account_id, op_id)
);
INSERT INTO ops_scoped (vault_id, account_id, op_id, item_id, revision, seq, created_at)
    SELECT o.vault_id,
           COALESCE((SELECT m.account_id FROM vault_members m WHERE m.vault_id = o.vault_id AND m.role = 'owner' LIMIT 1), ''),
           o.op_id, o.item_id, o.revision, o.seq, o.created_at
    FROM ops o;
DROP TABLE ops;
ALTER TABLE ops_scoped RENAME TO ops;
"#,
];

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn open(path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    Ok(conn)
}

pub fn migrate(conn: &mut Connection) -> anyhow::Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    for (i, m) in MIGRATIONS.iter().enumerate().skip(version as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(m)?;
        tx.pragma_update(None, "user_version", (i + 1) as i64)?;
        tx.commit()?;
    }
    Ok(())
}

impl Db {
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    /// Runs `f` on the connection in a blocking thread.
    pub async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> AppResult<T> + Send + 'static,
    ) -> AppResult<T> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut c = conn
                .lock()
                .map_err(|_| AppError::internal("database lock poisoned"))?;
            f(&mut c)
        })
        .await
        .map_err(AppError::internal)?
    }

    /// Same, synchronously (startup, CLI).
    pub fn run_sync<T>(&self, f: impl FnOnce(&mut Connection) -> AppResult<T>) -> AppResult<T> {
        let mut c = self
            .conn
            .lock()
            .map_err(|_| AppError::internal("database lock poisoned"))?;
        f(&mut c)
    }
}

pub fn get_setting(c: &Connection, k: &str) -> rusqlite::Result<Option<String>> {
    c.query_row("SELECT v FROM settings WHERE k = ?1", [k], |r| r.get(0))
        .optional()
}

pub fn set_setting(c: &Connection, k: &str, v: &str) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO settings (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        [k, v],
    )?;
    Ok(())
}

pub fn audit(
    c: &Connection,
    account_id: Option<&str>,
    action: &str,
    device_id: &str,
    ip: &str,
    detail: &str,
) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO audit (account_id, at, action, device_id, ip, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![account_id, now_ms(), action, device_id, ip, detail],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_migration_keeps_records_and_scopes_them_to_the_owner() {
        let mut c = Connection::open_in_memory().unwrap();
        c.execute_batch(MIGRATIONS[0]).unwrap();
        c.pragma_update(None, "user_version", 1).unwrap();
        c.execute_batch(
            "INSERT INTO accounts (id, login, opaque_record, kdf, account_salt, encrypted_account_key, public_key, encrypted_private_key, created_at, updated_at)
               VALUES ('acc', 'me@example.com', x'00', '{}', 's', 'k', 'p', 'e', 0, 0);
             INSERT INTO vaults (id, encrypted_meta, created_by, created_at) VALUES ('v', 'm', 'acc', 0);
             INSERT INTO vault_members (vault_id, account_id, role, wrapped_key, created_at) VALUES ('v', 'acc', 'owner', 'w', 0);
             INSERT INTO ops (op_id, vault_id, item_id, revision, seq, created_at) VALUES ('op', 'v', 'i', 3, 7, 0);",
        )
        .unwrap();
        migrate(&mut c).unwrap();
        let row: (String, String, String, i64, i64) = c
            .query_row(
                "SELECT vault_id, account_id, item_id, revision, seq FROM ops WHERE op_id = 'op'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(row, ("v".into(), "acc".into(), "i".into(), 3, 7));
        // the same op id may now exist in another vault or for another account
        c.execute(
            "INSERT INTO ops (vault_id, account_id, op_id, item_id, revision, seq, created_at) VALUES ('v2', 'acc', 'op', 'j', 1, 1, 0)",
            [],
        )
        .unwrap();
        let v: i64 = c
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v as usize, MIGRATIONS.len());
    }
}
