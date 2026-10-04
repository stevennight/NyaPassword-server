//! Backup alerts: generic webhook, Telegram, Bark, e-mail.

use npw_api::admin::NotifyConfig;
use serde_json::json;

/// Sends to every configured channel. Returns the channels that failed.
pub async fn send(cfg: &NotifyConfig, title: &str, body: &str) -> Vec<String> {
    let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(20)).build() {
        Ok(c) => c,
        Err(e) => return vec![format!("http client: {e}")],
    };
    let mut failed = vec![];
    if !cfg.webhook_url.is_empty() {
        let r = client.post(&cfg.webhook_url).json(&json!({ "title": title, "message": body, "source": "nyapassword" })).send().await;
        if !matches!(&r, Ok(resp) if resp.status().is_success()) {
            failed.push(format!("webhook: {}", describe(r)));
        }
    }
    if !cfg.telegram_bot_token.is_empty() && !cfg.telegram_chat_id.is_empty() {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", cfg.telegram_bot_token);
        let r = client.post(url).json(&json!({ "chat_id": cfg.telegram_chat_id, "text": format!("{title}\n{body}") })).send().await;
        if !matches!(&r, Ok(resp) if resp.status().is_success()) {
            failed.push(format!("telegram: {}", describe(r)));
        }
    }
    if !cfg.bark_url.is_empty() {
        let url = format!("{}/{}/{}", cfg.bark_url.trim_end_matches('/'), enc(title), enc(body));
        let r = client.get(url).send().await;
        if !matches!(&r, Ok(resp) if resp.status().is_success()) {
            failed.push(format!("bark: {}", describe(r)));
        }
    }
    if !cfg.smtp_host.is_empty() && !cfg.smtp_to.is_empty() {
        if let Err(e) = send_mail(cfg, title, body).await {
            failed.push(format!("email: {e}"));
        }
    }
    for f in &failed {
        tracing::warn!("notification failed: {f}");
    }
    failed
}

fn describe(r: Result<reqwest::Response, reqwest::Error>) -> String {
    match r {
        Ok(resp) => format!("HTTP {}", resp.status()),
        Err(e) => e.to_string(),
    }
}

fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

async fn send_mail(cfg: &NotifyConfig, title: &str, body: &str) -> anyhow::Result<()> {
    use lettre::message::Mailbox;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
    let from: Mailbox = if cfg.smtp_from.is_empty() { cfg.smtp_username.parse()? } else { cfg.smtp_from.parse()? };
    let mut msg = Message::builder().from(from).subject(title);
    for to in cfg.smtp_to.split([',', ';']).map(str::trim).filter(|s| !s.is_empty()) {
        msg = msg.to(to.parse()?);
    }
    let msg = msg.body(body.to_string())?;
    let port = if cfg.smtp_port == 0 { 465 } else { cfg.smtp_port };
    let builder = if port == 465 {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host)?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host)?
    };
    let transport = builder.port(port).credentials(Credentials::new(cfg.smtp_username.clone(), cfg.smtp_password.clone())).build();
    transport.send(msg).await?;
    Ok(())
}
