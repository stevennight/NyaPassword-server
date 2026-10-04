//! Backup destinations through OpenDAL: Aliyun OSS and WebDAV.

use npw_api::admin::{BackupObject, BackupTarget, TargetKind};
use opendal::{services, Operator};
use serde::{Deserialize, Serialize};

use crate::state::ServerKeys;

/// A target as stored in the database: the secret is sealed with server.key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTarget {
    pub target: BackupTarget,
    #[serde(default)]
    pub secret_sealed: String,
}

impl StoredTarget {
    pub fn secret(&self, keys: &ServerKeys) -> String {
        if self.secret_sealed.is_empty() {
            return String::new();
        }
        keys.open(&format!("target:{}", self.target.id), &self.secret_sealed)
            .unwrap_or_default()
    }

    /// The target for API responses: no secret, `has_secret` set.
    pub fn public(&self) -> BackupTarget {
        let mut t = self.target.clone();
        t.secret.clear();
        t.has_secret = !self.secret_sealed.is_empty();
        t
    }

    pub fn operator(&self, keys: &ServerKeys) -> anyhow::Result<Operator> {
        let t = &self.target;
        let secret = self.secret(keys);
        let root = format!("/{}", t.root.trim_matches('/'));
        let op = match t.kind {
            TargetKind::Oss => {
                let b = services::Oss::default()
                    .bucket(&t.bucket)
                    .endpoint(&t.endpoint)
                    .access_key_id(&t.username)
                    .access_key_secret(&secret)
                    .root(&root);
                Operator::new(b)?.finish()
            }
            TargetKind::Webdav => {
                let b = services::Webdav::default()
                    .endpoint(&t.endpoint)
                    .username(&t.username)
                    .password(&secret)
                    .root(&root);
                Operator::new(b)?.finish()
            }
            TargetKind::Fs => {
                let dir = std::path::Path::new(&t.endpoint).join(t.root.trim_matches('/'));
                std::fs::create_dir_all(&dir)?;
                let b = services::Fs::default().root(&dir.to_string_lossy());
                Operator::new(b)?.finish()
            }
        };
        Ok(op)
    }
}

pub async fn write(op: &Operator, path: &str, data: Vec<u8>) -> anyhow::Result<()> {
    op.write(path, data).await?;
    Ok(())
}

pub async fn read(op: &Operator, path: &str) -> anyhow::Result<Vec<u8>> {
    Ok(op.read(path).await?.to_vec())
}

/// Backup archives on the target, newest first.
pub async fn list_backups(op: &Operator) -> anyhow::Result<Vec<BackupObject>> {
    let entries = match op.list(npw_backup::PREFIX).await {
        Ok(e) => e,
        Err(e) if e.kind() == opendal::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    let mut out = vec![];
    for e in entries {
        let name = e.path().to_string();
        let Some(t) = npw_backup::object_time(&name) else {
            continue;
        };
        out.push(BackupObject {
            size: e.metadata().content_length() as i64,
            modified_at: t,
            name,
        });
    }
    out.sort_by_key(|o| std::cmp::Reverse(o.modified_at));
    Ok(out)
}

pub async fn list_attachments(op: &Operator) -> anyhow::Result<Vec<String>> {
    let entries = match op.list(npw_backup::ATTACHMENT_PREFIX).await {
        Ok(e) => e,
        Err(e) if e.kind() == opendal::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    Ok(entries
        .into_iter()
        .filter_map(|e| e.path().rsplit('/').next().map(str::to_string))
        .filter(|n| !n.is_empty())
        .collect())
}

pub async fn delete(op: &Operator, path: &str) -> anyhow::Result<()> {
    op.delete(path).await?;
    Ok(())
}
