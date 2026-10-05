//! Regression tests for review findings: each one failed before its fix.

mod common;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::{client, client_with_store, login_item, TestServer};
use npw_api::{self as api, Event};
use npw_core::transport::{HttpRequest, HttpResponse, ReqwestTransport, Transport};
use npw_core::{Client, ClientConfig, CoreError, ItemFilter, Key32, MemoryStore, Store};
use npw_crypto::{aad, b64, envelope, kdf, opaque, unb64, KdfParams, SecretKey};
use nyapassword_server::{admin, backup, db};
use serde_json::{json, Value};

// ------------------------------------------------------------------ helpers

/// A raw API call; returns the status and the JSON body (or `null`).
async fn call(
    url: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (u16, Value) {
    let c = reqwest::Client::new();
    let mut rb = c.request(
        reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
        format!("{url}{path}"),
    );
    if let Some(t) = token {
        rb = rb.bearer_auth(t);
    }
    if let Some(b) = body {
        rb = rb.json(&b);
    }
    let r = rb.send().await.unwrap();
    let status = r.status().as_u16();
    let bytes = r.bytes().await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn put_blob(url: &str, path: &str, token: &str, body: Vec<u8>) -> (u16, Value) {
    let r = reqwest::Client::new()
        .put(format!("{url}{path}"))
        .bearer_auth(token)
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let bytes = r.bytes().await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn push_item(op_id: &str, item_id: &str, base: i64) -> Value {
    json!({
        "op_id": op_id,
        "item_id": item_id,
        "base_revision": base,
        "format_major": 1,
        "wrapped_key": b64(&npw_crypto::random_bytes::<40>()),
        "ciphertext": b64(&npw_crypto::random_bytes::<64>()),
    })
}

fn all_ids(c: &Client) -> Vec<String> {
    c.list_items(&ItemFilter::default())
        .unwrap()
        .into_iter()
        .chain(
            c.list_items(&ItemFilter {
                trash: true,
                ..Default::default()
            })
            .unwrap(),
        )
        .map(|v| v.item_id)
        .collect()
}

async fn registered(srv: &TestServer) -> (Client, String, String) {
    let a = client("A");
    let kit = a
        .register(&srv.url, "me@example.com", "pw", None)
        .await
        .unwrap();
    let vault = a.vaults().unwrap()[0].id.clone();
    (a, kit.secret_key, vault)
}

async fn second_device(srv: &TestServer, name: &str, sk: &str) -> Client {
    let b = client(name);
    b.sign_in(&srv.url, "me@example.com", "pw", sk)
        .await
        .unwrap();
    b.sync().await.unwrap();
    b
}

fn drain(rx: &mut tokio::sync::broadcast::Receiver<(String, Event)>) -> Vec<Event> {
    let mut v = vec![];
    while let Ok((_, e)) = rx.try_recv() {
        v.push(e);
    }
    v
}

// ------------------------------------------------------------------ 1. tombstones on every page

#[tokio::test(flavor = "multi_thread")]
async fn purge_tombstones_reach_clients_across_pages() {
    let srv = TestServer::start().await;
    let (a, sk, vault) = registered(&srv).await;
    let x = a
        .save_item(&vault, None, login_item("X", "u", "p"))
        .unwrap();
    let y = a
        .save_item(&vault, None, login_item("Y", "u", "p"))
        .unwrap();
    a.sync().await.unwrap();
    a.delete_item(&vault, &x).unwrap();
    a.delete_item(&vault, &y).unwrap();
    a.sync().await.unwrap();
    let b = second_device(&srv, "B", &sk).await;
    assert!(b.item(&vault, &x).unwrap().deleted);

    // incremental pull: the tombstone sits on the first of two pages of changes
    a.purge(&vault, std::slice::from_ref(&x)).await.unwrap();
    let many: Vec<_> = (0..600)
        .map(|i| login_item(&format!("Bulk{i}"), "u", "p"))
        .collect();
    a.import_items(&vault, many, "test").await.unwrap();
    let r = b.sync().await.unwrap();
    assert_eq!(r.restored_to_server, 0, "{r:?}");
    assert!(b.item(&vault, &x).is_err(), "the purged item is dropped");

    // full reconciliation (server restored: new epoch): the tombstone is on a middle page
    a.purge(&vault, std::slice::from_ref(&y)).await.unwrap();
    let many: Vec<_> = (0..600)
        .map(|i| login_item(&format!("More{i}"), "u", "p"))
        .collect();
    a.import_items(&vault, many, "test").await.unwrap();
    let (port, dir) = (srv.port(), srv.dir.clone());
    srv.state
        .db
        .run_sync(|c| {
            Ok(db::set_setting(
                c,
                "epoch",
                &uuid::Uuid::now_v7().to_string(),
            )?)
        })
        .unwrap();
    let _tmp = srv.stop().await;
    let srv = TestServer::start_in(dir, Some(port)).await;
    let r = b.sync().await.unwrap();
    assert!(r.full_resyncs >= 1, "{r:?}");
    assert_eq!(r.restored_to_server, 0, "{r:?}");
    assert!(b.item(&vault, &y).is_err(), "the purged item is dropped");
    a.sync().await.unwrap();
    for c in [&a, &b] {
        let ids = all_ids(c);
        assert_eq!(ids.len(), 1200);
        assert!(!ids.contains(&x) && !ids.contains(&y));
    }
    srv.stop().await;
}

// ------------------------------------------------------------------ 2. revocation

#[tokio::test(flavor = "multi_thread")]
async fn revoked_device_is_wiped_and_does_not_sign_in_again() {
    let srv = TestServer::start().await;
    let (a, sk, vault) = registered(&srv).await;
    a.save_item(&vault, None, login_item("Site", "u", "p"))
        .unwrap();
    a.sync().await.unwrap();

    let store_b = Arc::new(MemoryStore::new());
    let b = client_with_store("B", store_b.clone());
    b.sign_in(&srv.url, "me@example.com", "pw", &sk)
        .await
        .unwrap();
    b.sync().await.unwrap();
    let store_c = Arc::new(MemoryStore::new());
    let c = client_with_store("C", store_c.clone());
    c.sign_in(&srv.url, "me@example.com", "pw", &sk)
        .await
        .unwrap();
    c.sync().await.unwrap();
    let devices = a.devices().await.unwrap().len();

    // B: its session is still there and answers device_revoked
    a.revoke_device(&b.lock_state().device_id).await.unwrap();
    let r = b.sync().await;
    assert!(matches!(r, Err(CoreError::DeviceRevoked)), "{r:?}");
    assert!(!b.lock_state().signed_in);
    assert!(store_b.list_all_items().unwrap().is_empty());
    assert!(store_b.get_meta("account").unwrap().is_none());
    assert!(store_b.get_meta("secret_key").unwrap().is_none());
    b.sign_out(true).await.unwrap(); // what hosts do next: must not fail

    // C: its session expired meanwhile; the silent sign-in presents the revoked device ID
    let c_id = c.lock_state().device_id;
    a.revoke_device(&c_id).await.unwrap();
    srv.state
        .db
        .run_sync(|conn| Ok(conn.execute("DELETE FROM sessions WHERE device_id = ?1", [&c_id])?))
        .unwrap();
    let r = c.sync().await;
    assert!(matches!(r, Err(CoreError::DeviceRevoked)), "{r:?}");
    assert!(!c.lock_state().signed_in);
    assert!(store_c.list_all_items().unwrap().is_empty());

    assert_eq!(
        a.devices().await.unwrap().len(),
        devices,
        "no new device was created behind the revocation"
    );
    // the owner can still sign the wiped device in again (as a new device)
    c.sign_in(&srv.url, "me@example.com", "pw", &sk)
        .await
        .unwrap();
    c.sync().await.unwrap();
    assert_eq!(all_ids(&c).len(), 1);
    srv.stop().await;
}

// ------------------------------------------------------------------ 3. vault missing from /v1/account

#[tokio::test(flavor = "multi_thread")]
async fn vault_missing_from_account_keeps_local_edits() {
    let srv = TestServer::start().await;
    let (a, sk, vault) = registered(&srv).await;
    let id = a
        .save_item(&vault, None, login_item("Site", "u", "p0"))
        .unwrap();
    a.sync().await.unwrap();
    let mut c = a.item(&vault, &id).unwrap().content.unwrap();
    c.field_mut("password").unwrap().value = "unsynced".into();
    a.save_item(&vault, Some(&id), c).unwrap();

    let v = vault.clone();
    let member: (String, String, String, i64) = srv
        .state
        .db
        .run_sync(move |conn| {
            let row = conn.query_row(
                "SELECT account_id, role, wrapped_key, created_at FROM vault_members WHERE vault_id = ?1",
                [&v],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            conn.execute("DELETE FROM vault_members WHERE vault_id = ?1", [&v])?;
            Ok(row)
        })
        .unwrap();
    let r = a.sync().await.unwrap();
    assert_eq!(r.vaults_missing_on_server, 1);
    let it = a.item(&vault, &id).unwrap();
    assert_eq!(it.content.unwrap().password().unwrap(), "unsynced");
    assert_eq!(a.attention().unwrap().1, 1, "the edit is still pending");
    // survives a restart too
    a.lock();
    a.unlock("pw").unwrap();
    assert_eq!(a.vaults().unwrap().len(), 1);

    // the vault comes back: the edit is pushed
    let v = vault.clone();
    srv.state
        .db
        .run_sync(move |conn| {
            conn.execute(
                "INSERT INTO vault_members (vault_id, account_id, role, wrapped_key, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![v, member.0, member.1, member.2, member.3],
            )?;
            Ok(())
        })
        .unwrap();
    let r = a.sync().await.unwrap();
    assert_eq!(r.vaults_missing_on_server, 0);
    assert_eq!(r.pushed, 1);
    let b = second_device(&srv, "B", &sk).await;
    assert_eq!(
        b.item(&vault, &id)
            .unwrap()
            .content
            .unwrap()
            .password()
            .unwrap(),
        "unsynced"
    );
    srv.stop().await;
}

// ------------------------------------------------------------------ 4. unlock material from the server

fn set_account_row(srv: &TestServer, kdf: &KdfParams, salt: &str, eak: &str) {
    let (k, s, e) = (
        serde_json::to_string(kdf).unwrap(),
        salt.to_string(),
        eak.to_string(),
    );
    srv.state
        .db
        .run_sync(move |c| {
            c.execute(
                "UPDATE accounts SET kdf = ?1, account_salt = ?2, encrypted_account_key = ?3",
                [&k, &s, &e],
            )?;
            Ok(())
        })
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn server_cannot_block_offline_unlock_and_password_changes_still_arrive() {
    let srv = TestServer::start().await;
    let store = Arc::new(MemoryStore::new());
    let a = client_with_store("A", store.clone());
    let kit = a
        .register(&srv.url, "me@example.com", "pw", None)
        .await
        .unwrap();
    let account_id = a.lock_state().account_id;
    let weak = KdfParams::insecure_for_tests();

    // garbage that passes validation: adopted, but the previous material still unlocks
    set_account_row(&srv, &weak, &b64(&[9u8; 16]), &b64(&[1u8; 72]));
    a.sync().await.unwrap();
    a.lock();
    a.unlock("pw").unwrap();
    let restarted = client_with_store("A", store.clone());
    restarted.unlock("pw").unwrap();

    // a real password change elsewhere: the new password unlocks, and then the old one no longer does
    let ak = Key32::from_slice(&a.quick_unlock_key().unwrap()).unwrap();
    let sk = SecretKey::parse(&kit.secret_key).unwrap();
    let salt = [5u8; 16];
    let mk = kdf::derive_master("new pw", &sk, &salt, &weak).unwrap();
    let id_bytes = *uuid::Uuid::parse_str(&account_id).unwrap().as_bytes();
    let wrapped = envelope::wrap_key(&mk.auk, &ak, &aad::account_key(&id_bytes));
    set_account_row(&srv, &weak, &b64(&salt), &b64(&wrapped));
    a.sync().await.unwrap();
    a.lock();
    a.unlock("pw").unwrap(); // still the fallback until the new one has worked here
    a.lock();
    a.unlock("new pw").unwrap();
    a.lock();
    assert!(matches!(a.unlock("pw"), Err(CoreError::WrongPassword)));
    a.unlock("new pw").unwrap();
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn weak_kdf_parameters_from_the_server_are_refused() {
    let srv = TestServer::start().await;
    let min = KdfParams {
        m: 16 * 1024,
        t: 1,
        p: 1,
        ..KdfParams::default()
    };
    let mut cfg = ClientConfig::new("A", "cli", "test");
    cfg.new_account_kdf = min; // validation stays on
    let a = Client::new(
        cfg,
        Arc::new(MemoryStore::new()),
        Key32::from_bytes([7u8; 32]),
    )
    .unwrap();
    a.register(&srv.url, "me@example.com", "pw", None)
        .await
        .unwrap();
    let (salt, eak): (String, String) = srv
        .state
        .db
        .run_sync(|c| {
            Ok(c.query_row(
                "SELECT account_salt, encrypted_account_key FROM accounts",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .unwrap();
    set_account_row(&srv, &KdfParams::insecure_for_tests(), &salt, &eak);
    let r = a.sync().await.unwrap();
    assert!(r.account_key_update_refused);
    a.lock();
    a.unlock("pw").unwrap();
    srv.stop().await;
}

// ------------------------------------------------------------------ 6. idempotency scope

#[tokio::test(flavor = "multi_thread")]
async fn op_ids_are_scoped_to_account_and_vault() {
    let srv = TestServer::start().await;
    let (a, _, va) = registered(&srv).await;
    let inv = srv
        .state
        .db
        .run_sync(|c| Ok(admin::create_invite(c, 1)?))
        .unwrap();
    let b = client("B");
    b.register(&srv.url, "other@example.com", "pw", Some(&inv.code))
        .await
        .unwrap();
    let vb = b.vaults().unwrap()[0].id.clone();
    let (ta, tb) = (
        a.events_token().await.unwrap(),
        b.events_token().await.unwrap(),
    );
    let (i1, i2, i3) = (
        npw_model::new_id(),
        npw_model::new_id(),
        npw_model::new_id(),
    );
    let batch = |it: Value| Some(json!({ "items": [it], "atomic": false }));

    let (s, r) = call(
        &srv.url,
        "POST",
        &format!("/v1/vaults/{va}/items/batch"),
        Some(&ta),
        batch(push_item("op-1", &i1, 0)),
    )
    .await;
    assert_eq!((s, r["results"][0]["status"].as_str()), (200, Some("ok")));

    // another account, another vault, same op id: a real write of its own item
    let (s, r) = call(
        &srv.url,
        "POST",
        &format!("/v1/vaults/{vb}/items/batch"),
        Some(&tb),
        batch(push_item("op-1", &i2, 0)),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(r["results"][0]["status"], "ok");
    assert_eq!(r["results"][0]["item_id"], i2.as_str(), "{r}");
    let (_, ch) = call(
        &srv.url,
        "GET",
        &format!("/v1/vaults/{vb}/changes"),
        Some(&tb),
        None,
    )
    .await;
    assert_eq!(ch["items"][0]["item_id"], i2.as_str(), "{ch}");

    // same account and vault, same op id, other item: never "already done"
    let (_, r) = call(
        &srv.url,
        "POST",
        &format!("/v1/vaults/{va}/items/batch"),
        Some(&ta),
        batch(push_item("op-1", &i3, 0)),
    )
    .await;
    assert_eq!(r["results"][0]["status"], "rejected", "{r}");

    // a true retry is still idempotent
    let (_, r) = call(
        &srv.url,
        "POST",
        &format!("/v1/vaults/{va}/items/batch"),
        Some(&ta),
        batch(push_item("op-1", &i1, 0)),
    )
    .await;
    assert_eq!(r["results"][0]["status"], "ok");
    assert_eq!(r["results"][0]["revision"], 1);
    srv.stop().await;
}

// ------------------------------------------------------------------ 7. corrupt attachment downloads

#[tokio::test(flavor = "multi_thread")]
async fn corrupt_attachment_download_is_not_cached() {
    let srv = TestServer::start().await;
    let (a, sk, vault) = registered(&srv).await;
    let id = a
        .save_item(&vault, None, login_item("Site", "u", "p"))
        .unwrap();
    a.sync().await.unwrap();
    let data: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
    let att = a
        .add_attachment(&vault, &id, "f.bin", "application/octet-stream", &data)
        .await
        .unwrap();
    a.sync().await.unwrap();
    let b = second_device(&srv, "B", &sk).await;

    let path = srv.dir.join("attachments").join(&att);
    let good = std::fs::read(&path).unwrap();
    let mut bad = good.clone();
    bad[100] ^= 0xff;
    std::fs::write(&path, &bad).unwrap();
    assert!(b.attachment(&vault, &id, &att).await.is_err());
    std::fs::write(&path, &good).unwrap();
    assert_eq!(b.attachment(&vault, &id, &att).await.unwrap(), data);
    srv.stop().await;
}

// ------------------------------------------------------------------ 8. attachment uploads

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_attachment_uploads_stay_consistent() {
    let srv = TestServer::start().await;
    let (a, _, vault) = registered(&srv).await;
    let token = a.events_token().await.unwrap();
    let item = npw_model::new_id();
    let att = uuid::Uuid::new_v4().to_string();
    let path = format!("/v1/vaults/{vault}/attachments/{att}?item={item}");

    let mut tasks = vec![];
    for i in 0..8u8 {
        let (url, path, token) = (srv.url.clone(), path.clone(), token.clone());
        let body = vec![i; 512 * 1024];
        tasks.push(tokio::spawn(async move {
            let sha = npw_crypto::sha256_hex(&body);
            (put_blob(&url, &path, &token, body).await, sha)
        }));
    }
    let mut ok = vec![];
    for t in tasks {
        let ((status, r), sha) = t.await.unwrap();
        assert!(status == 200 || status == 409, "status {status}: {r}");
        if status == 200 {
            assert_eq!(r["sha256"], sha.as_str());
            ok.push(sha);
        }
    }
    assert_eq!(ok.len(), 1, "exactly one upload wins");
    let stored = std::fs::read(srv.dir.join("attachments").join(&att)).unwrap();
    assert_eq!(npw_crypto::sha256_hex(&stored), ok[0]);
    let (sha_db, vault_db): (String, String) = srv
        .state
        .db
        .run_sync({
            let att = att.clone();
            move |c| {
                Ok(c.query_row(
                    "SELECT sha256, vault_id FROM attachments WHERE id = ?1",
                    [&att],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?)
            }
        })
        .unwrap();
    assert_eq!((sha_db, vault_db), (ok[0].clone(), vault.clone()));
    let leftovers = std::fs::read_dir(srv.dir.join("attachments"))
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".part")
        })
        .count();
    assert_eq!(leftovers, 0);

    // the same ID and content in another vault is not "already stored"
    let other = a.create_vault("Other").await.unwrap();
    let winner = (0..8u8)
        .map(|i| vec![i; 512 * 1024])
        .find(|b| npw_crypto::sha256_hex(b) == ok[0])
        .unwrap();
    let (s, _) = put_blob(
        &srv.url,
        &format!("/v1/vaults/{other}/attachments/{att}?item={item}"),
        &token,
        winner.clone(),
    )
    .await;
    assert_eq!(s, 409);
    // a retry in the right vault is idempotent
    let (s, _) = put_blob(&srv.url, &path, &token, winner).await;
    assert_eq!(s, 200);
    srv.stop().await;
}

// ------------------------------------------------------------------ 10. events

#[tokio::test(flavor = "multi_thread")]
async fn purge_vault_creation_and_password_change_send_events() {
    let srv = TestServer::start().await;
    let (a, _, vault) = registered(&srv).await;
    let mut rx = srv.state.events.subscribe();
    let id = a
        .save_item(&vault, None, login_item("Site", "u", "p"))
        .unwrap();
    a.sync().await.unwrap();
    a.delete_item(&vault, &id).unwrap();
    a.sync().await.unwrap();
    drain(&mut rx);

    a.purge(&vault, std::slice::from_ref(&id)).await.unwrap();
    assert!(drain(&mut rx)
        .iter()
        .any(|e| matches!(e, Event::VaultChanged { vault_id, .. } if *vault_id == vault)));

    a.create_vault("Second").await.unwrap();
    assert!(drain(&mut rx).contains(&Event::AccountChanged));

    a.change_password("pw", "new pw").await.unwrap();
    assert!(drain(&mut rx).contains(&Event::AccountChanged));
    srv.stop().await;
}

// ------------------------------------------------------------------ 11. admin secrets, password change input, rate limits

#[tokio::test(flavor = "multi_thread")]
async fn admin_backup_secrets_are_masked() {
    let srv = TestServer::start().await;
    srv.state
        .db
        .run_sync(|c| Ok(admin::set_password(c, "admin password 123")?))
        .unwrap();
    let (s, r) = call(
        &srv.url,
        "POST",
        "/v1/admin/login",
        None,
        Some(json!({ "password": "admin password 123" })),
    )
    .await;
    assert_eq!(s, 200);
    let token = r["token"].as_str().unwrap().to_string();

    let mut settings = backup::default_settings();
    settings.notify.smtp_password = "smtp-secret".into();
    settings.notify.telegram_bot_token = "123:bot-token".into();
    settings.notify.smtp_host = "smtp.example.com".into();
    let (s, _) = call(
        &srv.url,
        "PUT",
        "/v1/admin/backup/settings",
        Some(&token),
        Some(serde_json::to_value(&settings).unwrap()),
    )
    .await;
    assert_eq!(s, 200);

    let (_, status) = call(&srv.url, "GET", "/v1/admin/backup", Some(&token), None).await;
    let text = status.to_string();
    assert!(
        !text.contains("smtp-secret") && !text.contains("bot-token"),
        "{text}"
    );
    assert_eq!(
        status["settings"]["notify"]["smtp_password"],
        api::admin::SECRET_MASK
    );
    assert_eq!(
        status["settings"]["notify"]["smtp_host"],
        "smtp.example.com"
    );

    // the console saves what it read: the stored secrets stay
    let (s, _) = call(
        &srv.url,
        "PUT",
        "/v1/admin/backup/settings",
        Some(&token),
        Some(status["settings"].clone()),
    )
    .await;
    assert_eq!(s, 200);
    let st = srv.state.clone();
    let stored = srv
        .state
        .db
        .run_sync(|c| backup::load_settings(c, &st))
        .unwrap();
    assert_eq!(stored.notify.smtp_password, "smtp-secret");
    assert_eq!(stored.notify.telegram_bot_token, "123:bot-token");

    // a new value replaces it, an empty one clears it
    let mut s2 = status["settings"].clone();
    s2["notify"]["smtp_password"] = json!("changed");
    s2["notify"]["telegram_bot_token"] = json!("");
    call(
        &srv.url,
        "PUT",
        "/v1/admin/backup/settings",
        Some(&token),
        Some(s2),
    )
    .await;
    let st = srv.state.clone();
    let stored = srv
        .state
        .db
        .run_sync(|c| backup::load_settings(c, &st))
        .unwrap();
    assert_eq!(stored.notify.smtp_password, "changed");
    assert_eq!(stored.notify.telegram_bot_token, "");
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn password_change_with_a_bad_salt_is_refused() {
    let srv = TestServer::start().await;
    let (a, sk, _) = registered(&srv).await;
    let token = a.events_token().await.unwrap();
    for (salt, eak) in [
        (b64(&[0u8; 8]), b64(&[1u8; 72])), // too short: no key could ever be derived
        (b64(&[0u8; 16]), "not base64!".to_string()),
        ("not base64!".to_string(), b64(&[1u8; 72])),
    ] {
        let login_key = Key32::generate();
        let (state, req) = opaque::client_register_start(&login_key).unwrap();
        let (s, r) = call(
            &srv.url,
            "POST",
            "/v1/account/password/start",
            Some(&token),
            Some(json!({ "opaque_request": b64(&req) })),
        )
        .await;
        assert_eq!(s, 200);
        let upload = opaque::client_register_finish(
            state,
            &login_key,
            &unb64(r["opaque_response"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let (s, r) = call(
            &srv.url,
            "POST",
            "/v1/account/password/finish",
            Some(&token),
            Some(json!({ "opaque_upload": b64(&upload), "kdf": KdfParams::insecure_for_tests(), "account_salt": salt, "encrypted_account_key": eak })),
        )
        .await;
        assert_eq!(s, 400, "{r}");
    }
    // nothing was replaced: the account still signs in with its password
    second_device(&srv, "B", &sk).await;
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn prelogin_and_register_are_rate_limited() {
    let srv = TestServer::start().await;
    let pre = |login: &str| Some(json!({ "login": login }));
    for _ in 0..20 {
        assert_eq!(
            call(
                &srv.url,
                "POST",
                "/v1/auth/prelogin",
                None,
                pre("me@example.com")
            )
            .await
            .0,
            200
        );
    }
    assert_eq!(
        call(
            &srv.url,
            "POST",
            "/v1/auth/prelogin",
            None,
            pre("me@example.com")
        )
        .await
        .0,
        429,
        "per login"
    );
    for i in 21..30 {
        assert_eq!(
            call(
                &srv.url,
                "POST",
                "/v1/auth/prelogin",
                None,
                pre(&format!("u{i}@example.com"))
            )
            .await
            .0,
            200
        );
    }
    assert_eq!(
        call(
            &srv.url,
            "POST",
            "/v1/auth/prelogin",
            None,
            pre("x@example.com")
        )
        .await
        .0,
        429,
        "per IP"
    );

    let reg = Some(
        json!({ "login": "new@example.com", "account_id": uuid::Uuid::now_v7().to_string(), "opaque_request": "AAAA" }),
    );
    let mut last = 0;
    for _ in 0..31 {
        last = call(
            &srv.url,
            "POST",
            "/v1/auth/register/start",
            None,
            reg.clone(),
        )
        .await
        .0;
    }
    assert_eq!(last, 429);
    srv.stop().await;
}

// ------------------------------------------------------------------ 13. digest check under concurrent writes

/// Runs `hook` once, right before the first digest request goes out.
struct HookTransport {
    inner: ReqwestTransport,
    fired: AtomicBool,
    other: Arc<Client>,
    vault: String,
}

impl Transport for HookTransport {
    fn send<'a, 'b>(
        &'a self,
        req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, CoreError>> + Send + 'b>>
    where
        'a: 'b,
        Self: 'b,
    {
        Box::pin(async move {
            if req.path.ends_with("/digest") && !self.fired.swap(true, Ordering::SeqCst) {
                // another device writes between this device's push and its digest check
                self.other
                    .save_item(&self.vault, None, login_item("Concurrent", "u", "p"))
                    .unwrap();
                self.other.sync().await.unwrap();
            }
            self.inner.send(req).await
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_writes_do_not_force_a_full_reconcile() {
    let srv = TestServer::start().await;
    let (a, sk, vault) = registered(&srv).await;
    a.save_item(&vault, None, login_item("First", "u", "p"))
        .unwrap();
    a.sync().await.unwrap();
    let b = Arc::new(second_device(&srv, "B", &sk).await);

    let mut cfg = ClientConfig::new("C", "cli", "test");
    cfg.allow_weak_kdf = true;
    let (b2, v2) = (b.clone(), vault.clone());
    let c = Client::with_transport_factory(
        cfg,
        Arc::new(MemoryStore::new()),
        Key32::from_bytes([7u8; 32]),
        Box::new(move |url| {
            Ok(Arc::new(HookTransport {
                inner: ReqwestTransport::new(url)?,
                fired: AtomicBool::new(false),
                other: b2.clone(),
                vault: v2.clone(),
            }) as Arc<dyn Transport>)
        }),
    )
    .unwrap();
    c.sign_in(&srv.url, "me@example.com", "pw", &sk)
        .await
        .unwrap();
    c.save_item(&vault, None, login_item("Mine", "u", "p"))
        .unwrap();
    let r = c.sync().await.unwrap();
    assert_eq!(r.full_resyncs, 0, "{r:?}");
    assert_eq!(r.pushed, 1);
    assert_eq!(all_ids(&c).len(), 3, "the concurrent write was pulled");
    b.sync().await.unwrap();
    assert_eq!(all_ids(&b).len(), 3);
    srv.stop().await;
}

// ------------------------------------------------------------------ 14. signing out with an unresponsive server

/// Sends to the real server until `hang` is set, then to a socket that accepts
/// connections and never answers.
struct HangTransport {
    real: ReqwestTransport,
    hole: ReqwestTransport,
    hang: Arc<AtomicBool>,
}

impl Transport for HangTransport {
    fn send<'a, 'b>(
        &'a self,
        req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, CoreError>> + Send + 'b>>
    where
        'a: 'b,
        Self: 'b,
    {
        Box::pin(async move {
            if self.hang.load(Ordering::SeqCst) {
                self.hole.send(req).await
            } else {
                self.real.send(req).await
            }
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_out_does_not_wait_for_an_unresponsive_server() {
    let srv = TestServer::start().await;
    let (_a, sk, _vault) = registered(&srv).await;

    // a "server" that accepts and never answers
    let hole = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hole_url = format!("http://{}", hole.local_addr().unwrap());
    let held = Arc::new(std::sync::Mutex::new(Vec::new()));
    let h2 = held.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = hole.accept().await {
            h2.lock().unwrap().push(s);
        }
    });

    let hang = Arc::new(AtomicBool::new(false));
    let (hang2, hole2) = (hang.clone(), hole_url.clone());
    let mut cfg = ClientConfig::new("B", "cli", "test");
    cfg.allow_weak_kdf = true;
    let b = Client::with_transport_factory(
        cfg,
        Arc::new(MemoryStore::new()),
        Key32::from_bytes([7u8; 32]),
        Box::new(move |url| {
            Ok(Arc::new(HangTransport {
                real: ReqwestTransport::new(url)?,
                hole: ReqwestTransport::new(&hole2)?,
                hang: hang2.clone(),
            }) as Arc<dyn Transport>)
        }),
    )
    .unwrap();
    b.sign_in(&srv.url, "me@example.com", "pw", &sk)
        .await
        .unwrap();
    b.sync().await.unwrap();

    hang.store(true, Ordering::SeqCst);
    let started = std::time::Instant::now();
    b.sign_out(false).await.unwrap();
    let took = started.elapsed();
    assert!(
        took < std::time::Duration::from_secs(10),
        "sign-out waited {took:?} for the server"
    );
    assert!(!b.lock_state().signed_in, "signed out locally");
    assert!(!held.lock().unwrap().is_empty(), "the logout was attempted");
    srv.stop().await;
}
