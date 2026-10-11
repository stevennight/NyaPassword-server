//! End-to-end: bulk edits, tag renaming / deleting, duplicate detection and
//! merging, synced to a second device.

mod common;

use common::{client, login_item, TestServer};
use npw_core::{BulkAction, Client, ItemFilter, ItemRef};

async fn two_devices(srv: &TestServer) -> (Client, Client, String) {
    let a = client("A");
    let kit = a
        .register(&srv.url, "me@example.com", "correct horse", None)
        .await
        .unwrap();
    let vault = a.vaults().unwrap()[0].id.clone();
    let b = client("B");
    b.sign_in(&srv.url, "me@example.com", "correct horse", &kit.secret_key)
        .await
        .unwrap();
    (a, b, vault)
}

fn tags_of(c: &Client, vault: &str, id: &str) -> Vec<String> {
    c.item(vault, id).unwrap().tags
}

#[tokio::test(flavor = "multi_thread")]
async fn bulk_edits_reach_the_other_device() {
    let srv = TestServer::start().await;
    let (a, b, vault) = two_devices(&srv).await;
    let mut ids = vec![];
    for t in ["One", "Two", "Three"] {
        let mut it = login_item(t, "me", "pw");
        if t == "One" {
            it.tags = vec!["old".into()];
        }
        ids.push(a.save_item(&vault, None, it).unwrap());
    }
    a.sync().await.unwrap();
    let refs: Vec<ItemRef> = ids.iter().map(|i| ItemRef::new(&vault, i)).collect();

    let r = a
        .bulk_update(
            &refs,
            &BulkAction::AddTags {
                tags: vec![" 工作 / 开发 ".into(), "old".into()],
            },
        )
        .unwrap();
    assert_eq!((r.changed, r.unchanged), (3, 0));
    assert_eq!(tags_of(&a, &vault, &ids[0]), vec!["old", "工作/开发"]);
    assert_eq!(tags_of(&a, &vault, &ids[1]), vec!["工作/开发", "old"]);

    let r = a
        .bulk_update(
            &refs[..2],
            &BulkAction::RemoveTags {
                tags: vec!["old".into()],
            },
        )
        .unwrap();
    assert_eq!((r.changed, r.unchanged), (2, 0));
    let r = a
        .bulk_update(&refs, &BulkAction::Favorite { on: true })
        .unwrap();
    assert_eq!(r.changed, 3);
    // the same item twice, and one that does not exist
    let mut twice = refs[..1].to_vec();
    twice.push(refs[0].clone());
    twice.push(ItemRef::new(&vault, "00000000-0000-0000-0000-000000000000"));
    let r = a
        .bulk_update(&twice, &BulkAction::Archive { on: true })
        .unwrap();
    assert_eq!((r.changed, r.unchanged, r.skipped.len()), (1, 0, 1));
    assert_eq!(r.skipped[0].reason, "not_found");
    let r = a.bulk_update(&refs[1..], &BulkAction::Trash).unwrap();
    assert_eq!(r.changed, 2);
    let r = a.bulk_update(&refs[1..], &BulkAction::Trash).unwrap();
    assert_eq!((r.changed, r.unchanged), (0, 2));
    assert_eq!(a.attention().unwrap().1, 3, "one pending edit per item");

    let pushed = a.sync().await.unwrap().pushed;
    assert_eq!(pushed, 3);
    b.sync().await.unwrap();
    let one = b.item(&vault, &ids[0]).unwrap();
    assert!(one.favorite && one.archived);
    assert_eq!(one.tags, vec!["工作/开发"]);
    let trash = b
        .list_items(&ItemFilter {
            trash: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(trash.len(), 2);
    assert!(trash.iter().all(|v| v.favorite && v.tags[0] == "工作/开发"));

    // restoring keeps the edits
    b.bulk_update(&refs[1..], &BulkAction::Restore).unwrap();
    b.sync().await.unwrap();
    a.sync().await.unwrap();
    assert!(!a.item(&vault, &ids[2]).unwrap().deleted);
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tags_are_renamed_and_deleted_everywhere() {
    let srv = TestServer::start().await;
    let (a, b, vault) = two_devices(&srv).await;
    let mk = |title: &str, tags: &[&str]| {
        let mut it = login_item(title, "me", "pw");
        it.tags = tags.iter().map(|t| t.to_string()).collect();
        a.save_item(&vault, None, it).unwrap()
    };
    let x = mk("X", &["工作", "工作/开发"]);
    let y = mk("Y", &["工作室", "公司"]);
    let z = mk("Z", &["工作/开发/前端"]);
    let t = mk("T", &["工作"]);
    a.delete_item(&vault, &t).unwrap();
    a.sync().await.unwrap();

    let counts: Vec<(String, usize)> = a
        .tag_counts()
        .unwrap()
        .into_iter()
        .map(|c| (c.tag, c.items))
        .collect();
    assert_eq!(
        counts,
        vec![
            ("公司".to_string(), 1),
            ("工作".to_string(), 2),
            ("工作/开发".to_string(), 2),
            ("工作/开发/前端".to_string(), 1),
            ("工作室".to_string(), 1),
        ]
    );

    // renaming into an existing tag merges them; the trash is renamed too
    let r = a.rename_tag("工作", "公司").unwrap();
    assert_eq!(r.changed, 3);
    assert_eq!(tags_of(&a, &vault, &x), vec!["公司", "公司/开发"]);
    assert_eq!(tags_of(&a, &vault, &y), vec!["工作室", "公司"]);
    assert_eq!(tags_of(&a, &vault, &z), vec!["公司/开发/前端"]);
    assert_eq!(tags_of(&a, &vault, &t), vec!["公司"]);
    assert_eq!(a.rename_tag("公司", " 公司 ").unwrap().changed, 0);
    assert!(a.rename_tag("公司", " / ").is_err());

    let r = a.delete_tag("公司/开发").unwrap();
    assert_eq!(r.changed, 2);
    assert_eq!(tags_of(&a, &vault, &x), vec!["公司"]);
    assert!(tags_of(&a, &vault, &z).is_empty());
    assert_eq!(a.delete_tag("nothing").unwrap().changed, 0);

    a.sync().await.unwrap();
    b.sync().await.unwrap();
    assert_eq!(b.tags().unwrap(), vec!["公司", "工作室"]);
    assert_eq!(tags_of(&b, &vault, &t), vec!["公司"]);
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicates_merge_without_losing_anything() {
    let srv = TestServer::start().await;
    let (a, b, vault) = two_devices(&srv).await;

    let mut old = login_item("GitHub", "Octocat", "old-pw");
    old.urls[0].url = "https://github.com/login".into();
    old.notes = "recovery codes in the safe".into();
    old.tags = vec!["imported".into()];
    let old_id = a.save_item(&vault, None, old).unwrap();
    let file = b"two-factor backup codes".to_vec();
    a.sync().await.unwrap();
    a.add_attachment(&vault, &old_id, "codes.txt", "text/plain", &file)
        .await
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(5));
    let mut new = login_item("github.com", "octocat", "new-pw");
    new.urls[0].url = "https://www.github.com/".into();
    let new_id = a.save_item(&vault, None, new).unwrap();
    let other = a
        .save_item(&vault, None, login_item("Gitee", "octocat", "new-pw"))
        .unwrap();
    a.sync().await.unwrap();

    let groups = a.duplicates().unwrap();
    assert_eq!(groups.len(), 1);
    let g = &groups[0];
    assert_eq!(
        (g.site.as_str(), g.username.as_str()),
        ("github.com", "octocat")
    );
    assert_eq!(g.items[0].item_id, new_id, "newest first");
    assert!(!g.same_password && !g.identical);
    assert!(!g.items.iter().any(|v| v.item_id == other));

    let keep = ItemRef::new(&vault, &new_id);
    let r = a
        .merge_items(&keep, &[ItemRef::new(&vault, &old_id)])
        .await
        .unwrap();
    assert_eq!(
        (r.trashed, r.attachments_copied, r.secrets_to_history),
        (1, 1, 1)
    );
    assert!(a.duplicates().unwrap().is_empty());
    // a trashed item cannot be merged again
    assert!(a
        .merge_items(&keep, &[ItemRef::new(&vault, &old_id)])
        .await
        .is_err());
    a.sync().await.unwrap();

    // the other device sees the result; the file survives emptying the trash
    b.sync().await.unwrap();
    b.purge(&vault, std::slice::from_ref(&old_id))
        .await
        .unwrap();
    let c = client("C");
    let kit = a.emergency_kit().unwrap();
    c.sign_in(&srv.url, "me@example.com", "correct horse", &kit.secret_key)
        .await
        .unwrap();
    c.sync().await.unwrap();
    for d in [&b, &c] {
        let v = d.item(&vault, &new_id).unwrap();
        let m = v.content.unwrap();
        assert_eq!(m.password().as_deref(), Some("new-pw"));
        assert!(m.history.iter().any(|h| h.value == "old-pw"));
        assert_eq!(m.urls.len(), 2);
        assert_eq!(m.tags, vec!["imported"]);
        assert_eq!(m.notes, "recovery codes in the safe");
        assert_eq!(m.attachments.len(), 1);
        let got = d
            .attachment(&vault, &new_id, &m.attachments[0].id)
            .await
            .unwrap();
        assert_eq!(got, file);
        assert!(d.item(&vault, &old_id).is_err(), "purged");
    }
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn identical_items_merge_offline() {
    let srv = TestServer::start().await;
    let (a, _b, vault) = two_devices(&srv).await;
    let mut note = npw_model::template("secure_note")
        .unwrap()
        .new_item("zh-CN");
    note.title = "Wi-Fi".into();
    note.notes = "pass: hunter2".into();
    let ids: Vec<String> = (0..3)
        .map(|_| a.save_item(&vault, None, note.clone()).unwrap())
        .collect();
    let groups = a.duplicates().unwrap();
    assert_eq!(groups.len(), 1);
    assert!(groups[0].identical);
    assert_eq!(groups[0].items.len(), 3);

    // without attachments, merging needs no server
    srv.stop().await;
    let refs: Vec<ItemRef> = ids.iter().map(|i| ItemRef::new(&vault, i)).collect();
    let r = a.merge_items(&refs[0], &refs).await.unwrap();
    assert_eq!(r.trashed, 2);
    let kept = a.item(&vault, &ids[0]).unwrap().content.unwrap();
    assert_eq!(kept.notes, "pass: hunter2");
    assert!(a.item(&vault, &ids[1]).unwrap().deleted);
    assert!(
        a.merge_items(&refs[0], &refs[..1]).await.is_err(),
        "nothing to merge"
    );
}
