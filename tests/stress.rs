//! Randomized multi-device test (development plan M1 acceptance): three
//! devices edit, delete and restore the same items with random sync timing,
//! some syncs cancelled half-way (as if the app was killed), and the clients
//! sometimes restarted from their stores. Afterwards:
//! - every value a device had saved when it started a sync can be found in
//!   the server's revision history (in place or as a recorded conflict);
//! - all devices and the server agree (same digest, same item content).
//!
//! `NPW_STRESS_OPS` sets the number of operations (default 600).

mod common;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use common::{client_with_store, login_item, TestServer};
use npw_core::{Client, ItemFilter, MemoryStore};
use npw_model::{Field, ItemContent};
use rand::{Rng, SeedableRng};

struct Device {
    name: String,
    store: Arc<MemoryStore>,
    client: Client,
}

fn all_strings(v: &serde_json::Value, out: &mut HashSet<String>) {
    match v {
        serde_json::Value::String(s) => {
            out.insert(s.clone());
            for line in s.lines() {
                out.insert(line.to_string());
            }
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| all_strings(x, out)),
        serde_json::Value::Object(o) => o.values().for_each(|x| all_strings(x, out)),
        _ => {}
    }
}

fn tokens_of(c: &ItemContent) -> HashSet<String> {
    let mut s = HashSet::new();
    all_strings(&serde_json::to_value(c).unwrap(), &mut s);
    s.into_iter().filter(|t| t.starts_with("tok-")).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn random_concurrent_edits_lose_nothing() {
    let ops: usize = std::env::var("NPW_STRESS_OPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(600);
    let seed: u64 = std::env::var("NPW_STRESS_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20261004);
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let srv = TestServer::start().await;

    let first = Arc::new(MemoryStore::new());
    let a = client_with_store("dev0", first.clone());
    let kit = a
        .register(&srv.url, "me@example.com", "pw", None)
        .await
        .unwrap();
    let vault = a.vaults().unwrap()[0].id.clone();
    let mut devices = vec![Device {
        name: "dev0".into(),
        store: first,
        client: a,
    }];
    for i in 1..3 {
        let store = Arc::new(MemoryStore::new());
        let c = client_with_store(&format!("dev{i}"), store.clone());
        c.sign_in(&srv.url, "me@example.com", "pw", &kit.secret_key)
            .await
            .unwrap();
        devices.push(Device {
            name: format!("dev{i}"),
            store,
            client: c,
        });
    }

    let mut counter = 0u64;
    let mut tok = || {
        counter += 1;
        format!("tok-{counter}")
    };
    // tokens each device had saved when a sync began: they must survive
    let mut committed: HashSet<String> = HashSet::new();
    let mut cancelled = 0;
    let mut restarts = 0;

    for step in 0..ops {
        let d = rng.gen_range(0..devices.len());
        let dev = &devices[d];
        let items = dev.client.list_items(&ItemFilter::default()).unwrap();
        let trash = dev
            .client
            .list_items(&ItemFilter {
                trash: true,
                ..Default::default()
            })
            .unwrap();
        match rng.gen_range(0..100) {
            0..=14 => {
                let t = tok();
                let mut it = login_item("Item", &t, &tok());
                it.title = format!("Item {t}");
                dev.client.save_item(&vault, None, it).unwrap();
            }
            15..=59 if !items.is_empty() => {
                let v = &items[rng.gen_range(0..items.len())];
                let mut c = dev
                    .client
                    .item(&vault, &v.item_id)
                    .unwrap()
                    .content
                    .unwrap();
                match rng.gen_range(0..5) {
                    0 => c.field_mut("password").unwrap().value = tok().into(),
                    1 => c.field_mut("username").unwrap().value = tok().into(),
                    2 => c.notes = format!("{}{}\n", c.notes, tok()),
                    3 => c.fields.push(
                        Field::new(npw_model::new_short_id("f"), "extra", "text").with_value(tok()),
                    ),
                    _ => c.tags.push(tok()),
                }
                dev.client.save_item(&vault, Some(&v.item_id), c).unwrap();
            }
            60..=64 if !items.is_empty() => {
                let v = &items[rng.gen_range(0..items.len())];
                dev.client.delete_item(&vault, &v.item_id).unwrap();
            }
            65..=67 if !trash.is_empty() => {
                let v = &trash[rng.gen_range(0..trash.len())];
                dev.client.restore_item(&vault, &v.item_id).unwrap();
            }
            68..=70 => {
                // the app is killed and restarted: a new client over the same store
                let name = dev.name.clone();
                let store = dev.store.clone();
                let c = client_with_store(&name, store.clone());
                c.unlock("pw").unwrap();
                devices[d].client = c;
                restarts += 1;
            }
            _ => {
                for v in dev
                    .client
                    .list_items(&ItemFilter::default())
                    .unwrap()
                    .into_iter()
                    .chain(
                        dev.client
                            .list_items(&ItemFilter {
                                trash: true,
                                ..Default::default()
                            })
                            .unwrap(),
                    )
                {
                    committed.extend(tokens_of(
                        &dev.client
                            .item(&vault, &v.item_id)
                            .unwrap()
                            .content
                            .unwrap(),
                    ));
                }
                if rng.gen_bool(0.15) {
                    // cancel the sync part-way, as if the process died mid-request
                    let ms = rng.gen_range(0..20);
                    if tokio::time::timeout(std::time::Duration::from_millis(ms), dev.client.sync())
                        .await
                        .is_err()
                    {
                        cancelled += 1;
                    }
                } else {
                    dev.client
                        .sync()
                        .await
                        .unwrap_or_else(|e| panic!("step {step}: sync failed: {e}"));
                }
            }
        }
    }

    // settle: everyone syncs until nothing changes
    for _ in 0..3 {
        for dev in &devices {
            for v in dev
                .client
                .list_items(&ItemFilter::default())
                .unwrap()
                .into_iter()
                .chain(
                    dev.client
                        .list_items(&ItemFilter {
                            trash: true,
                            ..Default::default()
                        })
                        .unwrap(),
                )
            {
                committed.extend(tokens_of(
                    &dev.client
                        .item(&vault, &v.item_id)
                        .unwrap()
                        .content
                        .unwrap(),
                ));
            }
            dev.client.sync().await.unwrap();
        }
    }

    // 1. nothing lost: every committed token is in some server revision
    let reference = &devices[0].client;
    let all: Vec<_> = reference
        .list_items(&ItemFilter::default())
        .unwrap()
        .into_iter()
        .chain(
            reference
                .list_items(&ItemFilter {
                    trash: true,
                    ..Default::default()
                })
                .unwrap(),
        )
        .collect();
    let mut on_server: HashSet<String> = HashSet::new();
    for v in &all {
        for r in reference.item_history(&vault, &v.item_id).await.unwrap() {
            on_server.extend(tokens_of(
                &reference
                    .item_revision(&vault, &v.item_id, r.revision)
                    .await
                    .unwrap(),
            ));
        }
    }
    let lost: Vec<&String> = committed
        .iter()
        .filter(|t| !on_server.contains(*t))
        .collect();
    assert!(
        lost.is_empty(),
        "{} of {} committed values are missing on the server: {:?}",
        lost.len(),
        committed.len(),
        lost.iter().take(10).collect::<Vec<_>>()
    );

    // 2. everyone agrees
    let snapshot = |c: &Client| -> HashMap<String, (bool, ItemContent)> {
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
            .map(|v| {
                (
                    v.item_id.clone(),
                    (
                        v.deleted,
                        c.item(&vault, &v.item_id).unwrap().content.unwrap(),
                    ),
                )
            })
            .collect()
    };
    let base = snapshot(&devices[0].client);
    for dev in &devices[1..] {
        let other = snapshot(&dev.client);
        assert_eq!(
            base.len(),
            other.len(),
            "{} sees a different number of items",
            dev.name
        );
        for (id, v) in &base {
            assert_eq!(Some(v), other.get(id), "{} differs on item {id}", dev.name);
        }
        let (_, pending, rejected) = dev.client.attention().unwrap();
        assert_eq!(
            (pending, rejected),
            (0, 0),
            "{} still has unsynced edits",
            dev.name
        );
        let h = dev.client.health_check().unwrap();
        assert!(h.problems.is_empty(), "{:?}", h.problems);
    }
    eprintln!(
        "stress: {ops} ops, {} items, {} committed values all on the server, {cancelled} cancelled syncs, {restarts} restarts",
        base.len(),
        committed.len()
    );
    srv.stop().await;
}
