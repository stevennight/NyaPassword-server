use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use npw_crypto::{aad, b64, envelope, unb64, Key32};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Notify};

use crate::config::Config;
use crate::db::{self, Db};

/// `server.key` in the data directory: the server's own secrets. It is inside
/// every backup (which is age-encrypted), so a restored server keeps working.
#[derive(Serialize, Deserialize)]
pub struct ServerKeys {
    /// Seals stored backup-target credentials; keys the fake prelogin answers.
    pub secret: String,
    /// The server's age identity: lets it run restore drills on its own backups.
    pub age_identity: String,
    pub created_at: i64,
}

impl ServerKeys {
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            return Ok(serde_json::from_slice(&std::fs::read(path)?)?);
        }
        let (age_identity, _) = npw_backup::generate_identity();
        let k = Self {
            secret: b64(Key32::generate().as_bytes()),
            age_identity,
            created_at: db::now_ms(),
        };
        write_private(path, &serde_json::to_vec_pretty(&k)?)?;
        Ok(k)
    }

    pub fn key(&self) -> Key32 {
        Key32::from_slice(&unb64(&self.secret).unwrap_or_default())
            .expect("server.key holds a 32-byte secret")
    }

    pub fn age_recipient(&self) -> String {
        npw_backup::recipient_of(&self.age_identity).expect("valid server age identity")
    }

    /// Seals a configuration secret (backup credentials) for the database.
    pub fn seal(&self, name: &str, value: &str) -> String {
        b64(&envelope::seal(
            &self.key(),
            value.as_bytes(),
            &aad::device_secret(name),
        ))
    }

    pub fn open(&self, name: &str, sealed: &str) -> Option<String> {
        let data = unb64(sealed)?;
        envelope::open(&self.key(), &data, &aad::device_secret(name))
            .ok()
            .and_then(|v| String::from_utf8(v).ok())
    }
}

pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// A simple fixed-window limiter keyed by IP or login.
#[derive(Default)]
pub struct Limiter {
    windows: Mutex<HashMap<String, (i64, u32)>>,
}

impl Limiter {
    /// Records one attempt; false when `key` exceeded `max` within `window_ms`.
    pub fn hit(&self, key: &str, max: u32, window_ms: i64) -> bool {
        let now = db::now_ms();
        let mut w = self.windows.lock().expect("limiter lock");
        if w.len() > 10_000 {
            w.retain(|_, (start, _)| now - *start < window_ms);
        }
        let e = w.entry(key.to_string()).or_insert((now, 0));
        if now - e.0 >= window_ms {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= max
    }

    pub fn clear(&self, key: &str) {
        self.windows.lock().expect("limiter lock").remove(key);
    }
}

pub struct AppState {
    pub cfg: Config,
    pub db: Db,
    pub keys: ServerKeys,
    pub opaque_setup: Vec<u8>,
    /// Changes when the database is replaced by a restore; clients then reconcile.
    pub epoch: String,
    /// (account id, event) for the WebSocket.
    pub events: broadcast::Sender<(String, npw_api::Event)>,
    pub limiter: Limiter,
    /// Admin session token hash → expiry.
    pub admin_sessions: Mutex<HashMap<String, i64>>,
    pub started_at: i64,
    /// Woken on every write, for the backup scheduler.
    pub changed: Arc<Notify>,
    pub last_change_at: Mutex<i64>,
    /// Serializes backup runs and drills.
    pub backup_lock: tokio::sync::Mutex<()>,
}

pub type Shared = Arc<AppState>;

impl AppState {
    pub fn notify_change(&self) {
        *self.last_change_at.lock().expect("lock") = db::now_ms();
        self.changed.notify_one();
    }
}
