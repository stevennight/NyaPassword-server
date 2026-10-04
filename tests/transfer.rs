//! Import and export end to end: a Bitwarden export goes into a vault through
//! the server, the vault proves it holds everything, and exports reopen.

mod common;

use common::{client, TestServer};
use npw_core::ItemFilter;

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../common/crates/npw-import/tests/fixtures"
);

#[tokio::test(flavor = "multi_thread")]
async fn bitwarden_import_arrives_complete_and_exports_reopen() {
    let srv = TestServer::start().await;
    let a = client("A");
    let kit = a
        .register(&srv.url, "me@example.com", "pw", None)
        .await
        .unwrap();
    let vault = a.vaults().unwrap()[0].id.clone();

    let data = std::fs::read(format!("{FIXTURES}/bitwarden_export.json")).unwrap();
    let (source, parsed) =
        npw_core::transfer::parse_import("bitwarden_export.json", &data, None, "zh-CN").unwrap();
    let total = parsed.items.len();
    let passkeys = parsed.report.passkeys;
    assert!(total >= 5, "fixture has {total} items");
    let report = a
        .import_parsed(&vault, parsed, &source.to_lowercase())
        .await
        .unwrap();
    assert!(
        report.problems.is_empty(),
        "import lost data: {:?}",
        report.problems
    );
    assert_eq!(report.imported, total);

    // another device sees the same
    let b = client("B");
    b.sign_in(&srv.url, "me@example.com", "pw", &kit.secret_key)
        .await
        .unwrap();
    b.sync().await.unwrap();
    let items = b.list_items(&ItemFilter::default()).unwrap();
    let archived = b
        .list_items(&ItemFilter {
            archived: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(items.len() + archived.len(), total);
    let pk: usize = items.iter().chain(&archived).map(|i| i.passkeys).sum();
    assert_eq!(pk, passkeys, "passkeys survive the migration");

    // exports
    assert!(matches!(
        b.export_vault("native", "wrong").await,
        Err(npw_core::CoreError::WrongPassword)
    ));
    let native = b.export_vault("native", "pw").await.unwrap();
    let sk = npw_crypto::SecretKey::parse(&kit.secret_key).unwrap();
    let opened = npw_export::native::open_native(&native, "pw", &sk).unwrap();
    assert_eq!(opened.iter().map(|v| v.items.len()).sum::<usize>(), total);
    let kdbx = b.export_vault("kdbx", "pw").await.unwrap();
    assert!(kdbx.len() > 100);
    let csv = b.export_vault("csv", "pw").await.unwrap();
    assert!(csv.starts_with(b"\xef\xbb\xbf"));

    // the whole import can be undone
    let batches = b.import_batches().unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(b.undo_import(&batches[0].0).unwrap(), total);
    srv.stop().await;
}
