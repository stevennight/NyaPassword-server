//! The web vault (`/`) and admin console (`/admin`), built from common/web and
//! embedded in the binary (see build.rs: `webdist/` is filled by
//! scripts/build-web.ps1 or the Dockerfile; without it a placeholder is served).

use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/webdist/"]
struct Assets;

fn serve(path: &str) -> Option<Response> {
    let file = Assets::get(path)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let cache = if path.starts_with("assets/") { "public, max-age=31536000, immutable" } else { "no-cache" };
    Some(
        (
            [
                (header::CONTENT_TYPE, mime.as_ref().to_string()),
                (header::CACHE_CONTROL, cache.to_string()),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
                (header::REFERRER_POLICY, "no-referrer".to_string()),
                (header::X_FRAME_OPTIONS, "DENY".to_string()),
                (
                    header::CONTENT_SECURITY_POLICY,
                    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'".to_string(),
                ),
            ],
            file.data.into_owned(),
        )
            .into_response(),
    )
}

/// Static files with a single-page-app fallback: `/admin/...` → `admin.html`, anything else → `index.html`.
pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("v1/") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    if !path.is_empty() {
        if let Some(r) = serve(path) {
            return r;
        }
    }
    let fallback = if path == "admin" || path.starts_with("admin/") { "admin.html" } else { "index.html" };
    serve(fallback).unwrap_or_else(|| (StatusCode::NOT_FOUND, "web UI not built").into_response())
}
