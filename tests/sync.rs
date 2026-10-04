//! End-to-end: real server, real client core, two devices.

mod common;

use common::{client, login_item, TestServer};
use npw_core::{CoreError, ItemFilter};

#[tokio::test(flavor = "multi_thread")]
async fn register_sign_in_and_sync_between_devices() {
    let srv = TestServer::start().await;
    let a = client("A");
    let kit = a
        .register(&srv.url, "me@example.com", "correct horse", None)
        .await
        .unwrap();
    assert!(kit.secret_key.starts_with("A1-"));
    let vault = a.vaults().unwrap()[0].id.clone();
    assert_eq!(a.vaults().unwrap()[0].name, "个人");

    let id = a
        .save_item(&vault, None, login_item("GitHub", "octocat", "p0"))
        .unwrap();
    let r = a.sync().await.unwrap();
    assert_eq!(r.pushed, 1);

    // a second device needs the Secret Key
    let b = client("B");
    assert!(b
        .sign_in(
            &srv.url,
            "me@example.com",
            "correct horse",
            "A1-AAAAAA-AAAAA-AAAAA-AAAAA-AAAAA-A"
        )
        .await
        .is_err());
    let b = client("B");
    assert!(matches!(
        b.sign_in(&srv.url, "me@example.com", "wrong", &kit.secret_key)
            .await,
        Err(CoreError::WrongPassword)
    ));
    let b = client("B");
    b.sign_in(&srv.url, "ME@example.com", "correct horse", &kit.secret_key)
        .await
        .unwrap();
    b.sync().await.unwrap();
    let got = b.item(&vault, &id).unwrap();
    assert_eq!(got.title, "GitHub");
    assert_eq!(got.content.unwrap().password().unwrap(), "p0");

    // unknown logins look like real ones
    let c = client("C");
    assert!(matches!(
        c.sign_in(&srv.url, "nobody@example.com", "x", &kit.secret_key)
            .await,
        Err(CoreError::WrongPassword)
    ));

    // offline unlock with the password, wrong password refused
    a.lock();
    assert!(matches!(
        a.list_items(&ItemFilter::default()),
        Err(CoreError::Locked)
    ));
    assert!(matches!(a.unlock("nope"), Err(CoreError::WrongPassword)));
    a.unlock("correct horse").unwrap();
    assert_eq!(a.list_items(&ItemFilter::default()).unwrap().len(), 1);

    // quick unlock key round trip
    let k = a.quick_unlock_key().unwrap();
    a.lock();
    a.unlock_with_key(&k).unwrap();
    assert!(a.unlock_with_key(&[1u8; 32]).is_err());
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_edits_keep_every_value() {
    let srv = TestServer::start().await;
    let a = client("A");
    let kit = a
        .register(&srv.url, "me@example.com", "pw", None)
        .await
        .unwrap();
    let vault = a.vaults().unwrap()[0].id.clone();
    let id = a
        .save_item(&vault, None, login_item("Site", "user", "p0"))
        .unwrap();
    a.sync().await.unwrap();
    let b = client("B");
    b.sign_in(&srv.url, "me@example.com", "pw", &kit.secret_key)
        .await
        .unwrap();
    b.sync().await.unwrap();

    // both edit offline: the same field differently, plus different fields
    let mut ca = a.item(&vault, &id).unwrap().content.unwrap();
    ca.field_mut("password").unwrap().value = "from-A".into();
    ca.notes = "note from A\n".into();
    a.save_item(&vault, Some(&id), ca).unwrap();
    let mut cb = b.item(&vault, &id).unwrap().content.unwrap();
    cb.field_mut("password").unwrap().value = "from-B".into();
    cb.field_mut("username").unwrap().value = "user-B".into();
    cb.tags.push("work".into());
    b.save_item(&vault, Some(&id), cb).unwrap();

    a.sync().await.unwrap();
    let rb = b.sync().await.unwrap();
    assert_eq!(rb.merged, 1);
    assert_eq!(rb.conflicts, 1);
    a.sync().await.unwrap();

    for c in [&a, &b] {
        let it = c.item(&vault, &id).unwrap().content.unwrap();
        assert_eq!(
            it.password().unwrap(),
            "from-A",
            "the server's value is kept in place"
        );
        assert_eq!(it.username().unwrap(), "user-B");
        assert_eq!(it.notes, "note from A\n");
        assert_eq!(it.tags, vec!["work".to_string()]);
        assert_eq!(it.conflicts.len(), 1);
        assert_eq!(
            it.conflicts[0].value, "from-B",
            "the other value is kept as a conflict"
        );
        // the replaced password went into the password history too
        assert!(it.history.iter().any(|h| h.value == "p0"));
    }

    // resolving: take B's value
    let cid = a.item(&vault, &id).unwrap().content.unwrap().conflicts[0]
        .id
        .clone();
    a.resolve_conflict(&vault, &id, &cid, true).unwrap();
    a.sync().await.unwrap();
    b.sync().await.unwrap();
    let it = b.item(&vault, &id).unwrap().content.unwrap();
    assert_eq!(it.password().unwrap(), "from-B");
    assert!(it.conflicts.is_empty());
    assert!(it.history.iter().any(|h| h.value == "from-A"));
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_versus_edit_and_trash() {
    let srv = TestServer::start().await;
    let a = client("A");
    let kit = a
        .register(&srv.url, "me@example.com", "pw", None)
        .await
        .unwrap();
    let vault = a.vaults().unwrap()[0].id.clone();
    let id = a
        .save_item(&vault, None, login_item("Site", "u", "p"))
        .unwrap();
    a.sync().await.unwrap();
    let b = client("B");
    b.sign_in(&srv.url, "me@example.com", "pw", &kit.secret_key)
        .await
        .unwrap();
    b.sync().await.unwrap();

    a.delete_item(&vault, &id).unwrap();
    let mut cb = b.item(&vault, &id).unwrap().content.unwrap();
    cb.title = "Edited on B".into();
    b.save_item(&vault, Some(&id), cb).unwrap();
    a.sync().await.unwrap();
    b.sync().await.unwrap();
    a.sync().await.unwrap();
    for c in [&a, &b] {
        let v = c.item(&vault, &id).unwrap();
        assert!(!v.deleted, "an edit beats a deletion");
        assert_eq!(v.title, "Edited on B");
    }

    // trash, restore, trash, purge
    a.delete_item(&vault, &id).unwrap();
    a.sync().await.unwrap();
    b.sync().await.unwrap();
    assert!(b.item(&vault, &id).unwrap().deleted);
    assert_eq!(
        b.list_items(&ItemFilter {
            trash: true,
            ..Default::default()
        })
        .unwrap()
        .len(),
        1
    );
    b.restore_item(&vault, &id).unwrap();
    b.sync().await.unwrap();
    a.sync().await.unwrap();
    assert!(!a.item(&vault, &id).unwrap().deleted);
    a.delete_item(&vault, &id).unwrap();
    a.sync().await.unwrap();
    let purged = a.purge(&vault, std::slice::from_ref(&id)).await.unwrap();
    assert_eq!(purged, vec![id.clone()]);
    assert!(a.item(&vault, &id).is_err());
    // the other device drops it too, instead of re-uploading it
    let r = b.sync().await.unwrap();
    assert_eq!(r.restored_to_server, 0);
    assert!(b.item(&vault, &id).is_err());
    a.sync().await.unwrap();
    assert!(a.item(&vault, &id).is_err());
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn history_attachments_import_and_password_change() {
    let srv = TestServer::start().await;
    let a = client("A");
    let kit = a
        .register(&srv.url, "me@example.com", "pw", None)
        .await
        .unwrap();
    let vault = a.vaults().unwrap()[0].id.clone();
    let id = a
        .save_item(&vault, None, login_item("Site", "u", "p1"))
        .unwrap();
    a.sync().await.unwrap();
    for pw in ["p2", "p3"] {
        let mut c = a.item(&vault, &id).unwrap().content.unwrap();
        c.field_mut("password").unwrap().value = pw.into();
        a.save_item(&vault, Some(&id), c).unwrap();
        a.sync().await.unwrap();
    }
    let hist = a.item_history(&vault, &id).await.unwrap();
    assert_eq!(hist.len(), 3);
    let first = a.item_revision(&vault, &id, 1).await.unwrap();
    assert_eq!(first.password().unwrap(), "p1");
    a.restore_revision(&vault, &id, 1).await.unwrap();
    a.sync().await.unwrap();
    assert_eq!(
        a.item(&vault, &id)
            .unwrap()
            .content
            .unwrap()
            .password()
            .unwrap(),
        "p1"
    );
    assert_eq!(
        a.item_history(&vault, &id).await.unwrap().len(),
        4,
        "restoring adds a revision"
    );

    // attachments
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    let att = a
        .add_attachment(&vault, &id, "scan.pdf", "application/pdf", &data)
        .await
        .unwrap();
    a.sync().await.unwrap();
    let b = client("B");
    b.sign_in(&srv.url, "me@example.com", "pw", &kit.secret_key)
        .await
        .unwrap();
    b.sync().await.unwrap();
    assert_eq!(b.attachment(&vault, &id, &att).await.unwrap(), data);

    // atomic import and undo
    let items: Vec<_> = (0..250)
        .map(|i| login_item(&format!("Imported{i}"), "u", "p"))
        .collect();
    let res = a.import_items(&vault, items, "bitwarden").await.unwrap();
    assert_eq!(res.imported, 250);
    b.sync().await.unwrap();
    assert_eq!(
        b.list_items(&ItemFilter {
            query: "imported".into(),
            ..Default::default()
        })
        .unwrap()
        .len(),
        250
    );
    assert_eq!(b.import_batches().unwrap().len(), 1);
    assert_eq!(b.undo_import(&res.batch_id).unwrap(), 250);
    b.sync().await.unwrap();
    a.sync().await.unwrap();
    assert_eq!(
        a.list_items(&ItemFilter {
            query: "imported".into(),
            ..Default::default()
        })
        .unwrap()
        .len(),
        0
    );

    // change the master password: old password stops working, other devices must sign in again
    a.change_password("pw", "new pw").await.unwrap();
    a.lock();
    assert!(a.unlock("pw").is_err());
    a.unlock("new pw").unwrap();
    let c = client("C");
    c.sign_in(&srv.url, "me@example.com", "new pw", &kit.secret_key)
        .await
        .unwrap();
    let c2 = client("C2");
    assert!(c2
        .sign_in(&srv.url, "me@example.com", "pw", &kit.secret_key)
        .await
        .is_err());

    // devices and revoking one
    let devices = a.devices().await.unwrap();
    assert!(devices.len() >= 3);
    let b_id = b.lock_state().device_id;
    a.revoke_device(&b_id).await.unwrap();
    assert!(b.sync().await.is_err());
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn registration_is_closed_after_the_first_account() {
    let srv = TestServer::start().await;
    client("A")
        .register(&srv.url, "first@example.com", "pw", None)
        .await
        .unwrap();
    let r = client("B")
        .register(&srv.url, "second@example.com", "pw", None)
        .await;
    assert!(
        matches!(r, Err(CoreError::Api { status: 403, .. })),
        "{r:?}"
    );
    let inv = srv
        .state
        .db
        .run_sync(|c| Ok(nyapassword_server::admin::create_invite(c, 1).unwrap()))
        .unwrap();
    client("B")
        .register(&srv.url, "second@example.com", "pw", Some(&inv.code))
        .await
        .unwrap();
    // an invite works once
    let r = client("C")
        .register(&srv.url, "third@example.com", "pw", Some(&inv.code))
        .await;
    assert!(r.is_err());
    srv.stop().await;
}
