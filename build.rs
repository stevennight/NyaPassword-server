// The web UI is embedded from webdist/ (built from ../common/web by
// scripts/build-web.ps1 or the Dockerfile). Without a build, embed a
// placeholder so `cargo build` / `cargo test` work on a fresh checkout.
fn main() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("webdist");
    if !dir.join("index.html").exists() {
        std::fs::create_dir_all(&dir).expect("create webdist");
        let page = "<!doctype html><meta charset=utf-8><title>NyaPassword</title>\
                    <p>NyaPassword server is running. The web vault was not built into this binary \
                    (run scripts/build-web.ps1, or use the Docker image).</p>";
        std::fs::write(dir.join("index.html"), page).expect("write placeholder");
        std::fs::write(dir.join("admin.html"), page).expect("write placeholder");
    }
    println!("cargo:rerun-if-changed=webdist");
}
