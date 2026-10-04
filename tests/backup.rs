//! Backups end to end (development plan M1 acceptance): back up to a target,
//! keep working, lose the whole server data directory, restore from the
//! target with the offline key, and have the clients carry on — re-uploading
//! what the backup did not have.

mod common;

use common::{client, login_item, TestServer};
use npw_api::admin::{BackupTarget, TargetKind};
use npw_core::ItemFilter;
use nyapassword_server::backup::{self, targets::StoredTarget};

fn fs_target(dir: &std::path::Path) -> StoredTarget {
    StoredTarget {
        target: BackupTarget {
            id: "local".into(),
            kind: TargetKind::Fs,
            name: "NAS".into(),
            enabled: true,
            protect_mode: false,
            endpoint: dir.to_string_lossy().to_string(),
            bucket: String::new(),
            root: "npw".into(),
            username: String::new(),
            secret: String::new(),
            has_secret: false,
        },
        secret_sealed: String::new(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn backup_lose_everything_restore_and_continue() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let target_dir = tmp.path().join("target");
    let srv = TestServer::start_in(data.clone(), None).await;
    let port = srv.port();

    // offline key (Emergency Kit) as a backup recipient, and a directory target
    let (offline_identity, offline_recipient) = npw_backup::generate_identity();
    let st = srv.state.clone();
    srv.state
        .db
        .run_sync(|c| {
            let mut s = backup::load_settings(c, &st)?;
            s.recipients = vec![offline_recipient.clone()];
            backup::save_settings(c, &st, &s)?;
            backup::save_target(c, &fs_target(&target_dir))
        })
        .unwrap();

    let a = client("A");
    let kit = a
        .register(&srv.url, "me@example.com", "pw", None)
        .await
        .unwrap();
    let vault = a.vaults().unwrap()[0].id.clone();
    let mut ids = vec![];
    for i in 0..20 {
        ids.push(
            a.save_item(&vault, None, login_item(&format!("Before{i}"), "u", "p"))
                .unwrap(),
        );
    }
    a.sync().await.unwrap();
    let att = a
        .add_attachment(
            &vault,
            &ids[0],
            "a.bin",
            "application/octet-stream",
            b"attachment bytes",
        )
        .await
        .unwrap();
    a.sync().await.unwrap();

    let run = backup::run_backup(&srv.state, "manual").await.unwrap();
    assert!(
        run.results.iter().all(|r| r.ok && r.verified),
        "{:?}",
        run.results
    );
    assert_eq!(run.items, 20);
    let drill = backup::run_drill(&srv.state, None).await.unwrap();
    assert!(drill.ok, "{}", drill.detail);

    // work continues after the backup
    for i in 0..5 {
        a.save_item(&vault, None, login_item(&format!("After{i}"), "u", "p"))
            .unwrap();
    }
    let mut c0 = a.item(&vault, &ids[1]).unwrap().content.unwrap();
    c0.field_mut("password").unwrap().value = "changed after backup".into();
    a.save_item(&vault, Some(&ids[1]), c0).unwrap();
    a.sync().await.unwrap();

    // disaster: the server and its data directory are gone
    drop(st);
    srv.stop().await;
    std::fs::remove_dir_all(&data).unwrap();

    // restore with the offline key only (no server.key, no database)
    let id_file = tmp.path().join("offline.key");
    std::fs::write(&id_file, format!("# offline key\n{offline_identity}\n")).unwrap();
    let args = nyapassword_server::restore::RestoreArgs {
        file: None,
        identity: id_file,
        to: Some(data.clone()),
        replace: false,
        dry_run: false,
        object: None,
        kind: Some("fs".into()),
        endpoint: Some(target_dir.to_string_lossy().to_string()),
        bucket: None,
        root: "npw".into(),
        username: String::new(),
        secret: String::new(),
    };
    nyapassword_server::restore::run(args, data.clone())
        .await
        .unwrap();

    let srv = TestServer::start_in(data.clone(), Some(port)).await;
    // the device carries on: it notices the restore and re-uploads what the backup lacked
    let r = a.sync().await.unwrap();
    assert!(r.full_resyncs >= 1);
    assert_eq!(
        r.restored_to_server, 6,
        "5 new items and 1 edit were newer than the backup"
    );

    // a fresh device sees everything
    let b = client("B");
    b.sign_in(&srv.url, "me@example.com", "pw", &kit.secret_key)
        .await
        .unwrap();
    b.sync().await.unwrap();
    assert_eq!(b.list_items(&ItemFilter::default()).unwrap().len(), 25);
    assert_eq!(
        b.item(&vault, &ids[1])
            .unwrap()
            .content
            .unwrap()
            .password()
            .unwrap(),
        "changed after backup"
    );
    assert_eq!(
        b.attachment(&vault, &ids[0], &att).await.unwrap(),
        b"attachment bytes"
    );

    // and the restored server backs up again
    let run = backup::run_backup(&srv.state, "manual").await.unwrap();
    assert!(run.results.iter().all(|r| r.ok), "{:?}", run.results);
    assert_eq!(run.items, 25);
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn retention_prunes_and_drill_detects_damage() {
    let tmp = tempfile::tempdir().unwrap();
    let target_dir = tmp.path().join("target");
    let srv = TestServer::start().await;
    srv.state
        .db
        .run_sync(|c| backup::save_target(c, &fs_target(&target_dir)))
        .unwrap();
    let a = client("A");
    a.register(&srv.url, "me@example.com", "pw", None)
        .await
        .unwrap();
    let vault = a.vaults().unwrap()[0].id.clone();

    let st = srv.state.clone();
    srv.state
        .db
        .run_sync(|c| {
            let mut s = backup::load_settings(c, &st)?;
            s.retention = npw_api::admin::Retention {
                recent: 2,
                daily: 1,
                weekly: 1,
                monthly: 1,
            };
            backup::save_settings(c, &st, &s)
        })
        .unwrap();
    for i in 0..5 {
        a.save_item(&vault, None, login_item(&format!("I{i}"), "u", "p"))
            .unwrap();
        a.sync().await.unwrap();
        backup::run_backup(&srv.state, "manual").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await; // object names have 1 s resolution
    }
    let dir = target_dir.join("npw").join("backups");
    let n = std::fs::read_dir(&dir).unwrap().count();
    assert_eq!(
        n, 2,
        "recent=2 keeps two; the daily/weekly/monthly newest are among them"
    );

    // damage the newest archive: the drill must fail loudly
    let mut newest: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    newest.sort();
    let p = newest.last().unwrap();
    let mut bytes = std::fs::read(p).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    std::fs::write(p, bytes).unwrap();
    let drill = backup::run_drill(&srv.state, None).await.unwrap();
    assert!(!drill.ok);
    srv.stop().await;
}
