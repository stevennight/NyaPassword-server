#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use npw_core::{Client, ClientConfig, Key32, MemoryStore};
use nyapassword_server::config::Config;
use nyapassword_server::state::Shared;

pub struct TestServer {
    pub url: String,
    pub state: Shared,
    pub dir: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
    _tmp: Option<tempfile::TempDir>,
}

impl TestServer {
    pub async fn start() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("data");
        let mut s = Self::start_in(dir, None).await;
        s._tmp = Some(tmp);
        s
    }

    /// Starts a server on `dir`, optionally on a fixed port (to "restart" the same server).
    pub async fn start_in(dir: PathBuf, port: Option<u16>) -> Self {
        let cfg = Config { data_dir: dir.clone(), allow_weak_kdf: true, log: "warn".into(), ..Config::default() };
        let state = nyapassword_server::open_state(cfg).unwrap();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port.unwrap_or(0))).await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let st = state.clone();
        let task = tokio::spawn(async move {
            nyapassword_server::serve_on(st, listener, async {
                let _ = rx.await;
            })
            .await
            .unwrap();
        });
        Self { url, state, dir, shutdown: Some(tx), task: Some(task), _tmp: None }
    }

    pub fn port(&self) -> u16 {
        self.url.rsplit(':').next().unwrap().parse().unwrap()
    }

    pub async fn stop(mut self) -> Option<tempfile::TempDir> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
        self._tmp.take()
    }
}

pub fn client(name: &str) -> Client {
    client_with_store(name, Arc::new(MemoryStore::new()))
}

pub fn client_with_store(name: &str, store: Arc<MemoryStore>) -> Client {
    let mut cfg = ClientConfig::new(name, "cli", "test");
    cfg.allow_weak_kdf = true;
    cfg.new_account_kdf = npw_crypto::KdfParams::insecure_for_tests();
    Client::new(cfg, store, Key32::from_bytes([7u8; 32])).unwrap()
}

pub fn login_item(title: &str, user: &str, pw: &str) -> npw_model::ItemContent {
    let mut it = npw_model::template("login").unwrap().new_item("zh-CN");
    it.title = title.into();
    it.field_mut("username").unwrap().value = user.into();
    it.field_mut("password").unwrap().value = pw.into();
    it.urls.push(npw_model::UrlEntry::new(format!("https://{}.example.com/login", title.to_lowercase())));
    it
}
