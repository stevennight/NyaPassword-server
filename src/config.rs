//! Configuration: `config.toml` in the data directory (optional), overridden
//! by `NYAPASSWORD_*` environment variables.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Listen address. Keep it on loopback and let Caddy terminate TLS.
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    /// Trust `X-Forwarded-For` from the reverse proxy for client IPs.
    pub trust_proxy: bool,
    /// Largest attachment in MiB.
    pub max_attachment_mb: u64,
    /// Largest encrypted item in KiB.
    pub max_item_kb: u64,
    /// Allow registration without an invite while no account exists.
    pub open_first_registration: bool,
    /// Keep at least this many revisions per item when pruning (0 = keep all, the default).
    pub keep_revisions: u32,
    /// Log filter, e.g. `info` or `nyapassword_server=debug`.
    pub log: String,
    /// Accept key-derivation parameters below the minimum. Tests only; never set it in production.
    #[serde(skip)]
    pub allow_weak_kdf: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8087".parse().expect("valid address"),
            data_dir: PathBuf::from("data"),
            trust_proxy: true,
            max_attachment_mb: 100,
            max_item_kb: 1024,
            open_first_registration: true,
            keep_revisions: 0,
            log: "info".into(),
            allow_weak_kdf: false,
        }
    }
}

impl Config {
    pub fn load(data_dir: Option<PathBuf>) -> anyhow::Result<Self> {
        let dir = data_dir
            .or_else(|| std::env::var_os("NYAPASSWORD_DATA").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("data"));
        let file = dir.join("config.toml");
        let mut cfg: Config = if file.exists() {
            toml::from_str(&std::fs::read_to_string(&file)?)?
        } else {
            Config::default()
        };
        cfg.data_dir = dir;
        if let Ok(v) = std::env::var("NYAPASSWORD_LISTEN") {
            cfg.listen = v.parse()?;
        }
        if let Ok(v) = std::env::var("NYAPASSWORD_TRUST_PROXY") {
            cfg.trust_proxy = matches!(v.as_str(), "1" | "true" | "yes");
        }
        if let Ok(v) = std::env::var("NYAPASSWORD_MAX_ATTACHMENT_MB") {
            cfg.max_attachment_mb = v.parse()?;
        }
        if let Ok(v) = std::env::var("NYAPASSWORD_LOG") {
            cfg.log = v;
        }
        Ok(cfg)
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("nyapassword.sqlite3")
    }

    pub fn attachments_dir(&self) -> PathBuf {
        self.data_dir.join("attachments")
    }

    pub fn key_path(&self) -> PathBuf {
        self.data_dir.join("server.key")
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.data_dir.join("tmp")
    }
}
