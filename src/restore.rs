//! `nyapassword-server restore`: rebuilds a data directory from a backup.
//!
//! The archive comes from a local file or straight from a backup target
//! (given on the command line, so this also works when the old server and its
//! configuration are gone). It is decrypted with an age identity (normally
//! the offline key from the Emergency Kit), verified, and written to the data
//! directory. The database epoch is changed, so every client reconciles and
//! re-uploads anything newer than the backup.

use std::path::{Path, PathBuf};

use npw_api::admin::{BackupTarget, TargetKind};
use rusqlite::Connection;

use crate::backup::targets::{self, StoredTarget};
use crate::state::ServerKeys;

#[derive(clap::Args, Debug)]
pub struct RestoreArgs {
    /// A local backup file (`*.tar.zst.age`). Without it, the backup is downloaded from the target given below.
    #[arg(long)]
    pub file: Option<PathBuf>,
    /// File holding the age identity (`AGE-SECRET-KEY-1...`), e.g. the offline key from the Emergency Kit.
    #[arg(long)]
    pub identity: PathBuf,
    /// Data directory to restore into. Must not contain a database unless --replace.
    #[arg(long)]
    pub to: Option<PathBuf>,
    /// Move an existing database aside (to `pre-restore-<time>/`) instead of refusing.
    #[arg(long)]
    pub replace: bool,
    /// Only download, decrypt and verify; write nothing.
    #[arg(long)]
    pub dry_run: bool,
    /// Which backup object on the target (default: the newest).
    #[arg(long)]
    pub object: Option<String>,
    /// Target type when downloading: `oss`, `webdav` or `fs` (a directory).
    #[arg(long)]
    pub kind: Option<String>,
    #[arg(long)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub bucket: Option<String>,
    #[arg(long, default_value = "")]
    pub root: String,
    /// OSS access key ID / WebDAV user name.
    #[arg(long, default_value = "")]
    pub username: String,
    /// OSS access key secret / WebDAV password (or set NYAPASSWORD_RESTORE_SECRET).
    #[arg(long, env = "NYAPASSWORD_RESTORE_SECRET", default_value = "", hide_env_values = true)]
    pub secret: String,
}

pub async fn run(args: RestoreArgs, default_dir: PathBuf) -> anyhow::Result<()> {
    let identity = std::fs::read_to_string(&args.identity)?
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .ok_or_else(|| anyhow::anyhow!("{} holds no AGE-SECRET-KEY line", args.identity.display()))?
        .to_string();

    let (data, op) = match &args.file {
        Some(f) => (std::fs::read(f)?, None),
        None => {
            let kind = match args.kind.as_deref() {
                Some("oss") => TargetKind::Oss,
                Some("webdav") => TargetKind::Webdav,
                Some("fs") => TargetKind::Fs,
                _ => anyhow::bail!("give --file, or --kind oss|webdav|fs with --endpoint (and --bucket for OSS)"),
            };
            let target = StoredTarget {
                target: BackupTarget {
                    id: "restore".into(),
                    kind,
                    name: "restore".into(),
                    enabled: true,
                    protect_mode: true,
                    endpoint: args.endpoint.clone().ok_or_else(|| anyhow::anyhow!("--endpoint is required"))?,
                    bucket: args.bucket.clone().unwrap_or_default(),
                    root: args.root.clone(),
                    username: args.username.clone(),
                    secret: String::new(),
                    has_secret: true,
                },
                secret_sealed: String::new(),
            };
            // a throwaway key just to hold the secret for the operator
            let tmp_keys = ServerKeys { secret: npw_crypto::b64(npw_crypto::Key32::generate().as_bytes()), age_identity: identity.clone(), created_at: 0 };
            let target = StoredTarget { secret_sealed: tmp_keys.seal("target:restore", &args.secret), ..target };
            let op = target.operator(&tmp_keys)?;
            let object = match &args.object {
                Some(o) => o.clone(),
                None => {
                    let list = targets::list_backups(&op).await?;
                    println!("backups on the target: {}", list.len());
                    list.first().ok_or_else(|| anyhow::anyhow!("no backups found on the target"))?.name.clone()
                }
            };
            println!("downloading {object}");
            (targets::read(&op, &object).await?, Some(op))
        }
    };

    let (manifest, files) = npw_backup::open(&data, &[identity])?;
    println!("backup created:    {}", npw_backup::utc_stamp(manifest.created_at));
    println!("server version:    {}", manifest.server_version);
    println!("accounts / items / revisions / attachments: {} / {} / {} / {}", manifest.accounts, manifest.items, manifest.revisions, manifest.attachments);
    for (v, seq) in &manifest.vaults {
        println!("vault {v}: seq {seq}");
    }

    // verify the database before touching anything
    let tmp = tempfile::tempdir()?;
    let probe = tmp.path().join("db.sqlite3");
    std::fs::write(&probe, files.get("db.sqlite3").ok_or_else(|| anyhow::anyhow!("archive has no database"))?)?;
    {
        let c = Connection::open(&probe)?;
        let ok: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        anyhow::ensure!(ok == "ok", "database integrity_check failed: {ok}");
        let items: i64 = c.query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))?;
        anyhow::ensure!(items == manifest.items, "item count {items} differs from the manifest {}", manifest.items);
    }
    println!("verified: decrypts, integrity_check ok, counts match the manifest");
    if args.dry_run {
        println!("dry run: nothing written");
        return Ok(());
    }

    let dir = args.to.unwrap_or(default_dir);
    std::fs::create_dir_all(&dir)?;
    let db_path = dir.join("nyapassword.sqlite3");
    if db_path.exists() {
        anyhow::ensure!(args.replace, "{} already has a database; pass --replace to move it aside", dir.display());
        let aside = dir.join(format!("pre-restore-{}", npw_backup::utc_stamp(crate::db::now_ms())));
        std::fs::create_dir_all(&aside)?;
        for name in ["nyapassword.sqlite3", "nyapassword.sqlite3-wal", "nyapassword.sqlite3-shm", "server.key"] {
            let p = dir.join(name);
            if p.exists() {
                std::fs::rename(&p, aside.join(name))?;
            }
        }
        println!("moved the existing database to {}", aside.display());
    }
    std::fs::copy(&probe, &db_path)?;
    if let Some(k) = files.get("server.key") {
        crate::state::write_private(&dir.join("server.key"), k)?;
    }
    {
        let c = Connection::open(&db_path)?;
        let epoch = uuid::Uuid::now_v7().to_string();
        crate::db::set_setting(&c, "epoch", &epoch)?;
        // the restored server has not backed this state up yet
        c.execute("DELETE FROM settings WHERE k = 'backup_marker'", [])?;
        c.execute("DELETE FROM backup_target_blobs", [])?;
        c.execute("DELETE FROM sessions WHERE kind = 'access'", [])?;
        println!("new database epoch {epoch}: clients will reconcile and re-upload newer data");
    }
    if let Some(op) = op {
        restore_attachments(&op, &dir.join("attachments")).await?;
    } else {
        println!("attachments are not inside the archive: copy `attachments/` from the backup target into {}", dir.join("attachments").display());
    }
    println!("restored into {}", dir.display());
    Ok(())
}

async fn restore_attachments(op: &opendal::Operator, dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let names = targets::list_attachments(op).await?;
    let mut n = 0;
    for name in names {
        let p = dir.join(&name);
        if p.exists() {
            continue;
        }
        let data = targets::read(op, &format!("{}{name}", npw_backup::ATTACHMENT_PREFIX)).await?;
        std::fs::write(p, data)?;
        n += 1;
    }
    println!("downloaded {n} attachments");
    Ok(())
}
