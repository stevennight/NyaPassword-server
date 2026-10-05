//! Backup alerts: generic webhook, Telegram, Bark, e-mail.

use npw_api::admin::{channel, NotifyConfig};
use serde_json::json;

/// Whether `channel` has the settings it needs.
pub fn configured(cfg: &NotifyConfig, channel: &str) -> bool {
    match channel {
        channel::WEBHOOK => !cfg.webhook_url.is_empty(),
        channel::TELEGRAM => !cfg.telegram_bot_token.is_empty() && !cfg.telegram_chat_id.is_empty(),
        channel::BARK => !cfg.bark_url.is_empty(),
        channel::EMAIL => !cfg.smtp_host.is_empty() && !cfg.smtp_to.is_empty(),
        _ => false,
    }
}

/// Configured channels that are not switched off.
pub fn active(cfg: &NotifyConfig) -> Vec<&'static str> {
    channel::ALL
        .into_iter()
        .filter(|c| configured(cfg, c) && !cfg.off.iter().any(|o| o == c))
        .collect()
}

/// Sends an alert `event` ([`npw_api::admin::alert`]) to every active
/// channel, unless the event is muted. Returns the channels that failed.
pub async fn send_event(cfg: &NotifyConfig, event: &str, title: &str, body: &str) -> Vec<String> {
    if cfg.muted_events.iter().any(|e| e == event) {
        return vec![];
    }
    send_to(cfg, &active(cfg), title, body).await
}

/// Sends to every active channel. Returns the channels that failed.
pub async fn send(cfg: &NotifyConfig, title: &str, body: &str) -> Vec<String> {
    send_to(cfg, &active(cfg), title, body).await
}

/// Sends to the given channels (whether switched off or not). Returns the channels that failed.
pub async fn send_to(
    cfg: &NotifyConfig,
    channels: &[&str],
    title: &str,
    body: &str,
) -> Vec<String> {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
    {
        Ok(c) => c,
        Err(e) => return vec![format!("http client: {e}")],
    };
    let mut failed = vec![];
    for ch in channels {
        if !configured(cfg, ch) {
            failed.push(format!("{ch}: not configured"));
            continue;
        }
        match *ch {
            channel::WEBHOOK => {
                let r = client
                    .post(&cfg.webhook_url)
                    .json(&json!({ "title": title, "message": body, "source": "nyapassword" }))
                    .send()
                    .await;
                if !matches!(&r, Ok(resp) if resp.status().is_success()) {
                    failed.push(format!("webhook: {}", describe(r)));
                }
            }
            channel::TELEGRAM => {
                let url = format!(
                    "https://api.telegram.org/bot{}/sendMessage",
                    cfg.telegram_bot_token
                );
                let r = client
                    .post(url)
                    .json(
                        &json!({ "chat_id": cfg.telegram_chat_id, "text": format!("{title}
{body}") }),
                    )
                    .send()
                    .await;
                if !matches!(&r, Ok(resp) if resp.status().is_success()) {
                    failed.push(format!("telegram: {}", describe(r)));
                }
            }
            channel::BARK => {
                let url = format!(
                    "{}/{}/{}",
                    cfg.bark_url.trim_end_matches('/'),
                    enc(title),
                    enc(body)
                );
                let r = client.get(url).send().await;
                if !matches!(&r, Ok(resp) if resp.status().is_success()) {
                    failed.push(format!("bark: {}", describe(r)));
                }
            }
            channel::EMAIL => {
                if let Err(e) = send_mail(cfg, title, body).await {
                    failed.push(format!("email: {e}"));
                }
            }
            other => failed.push(format!("{other}: unknown channel")),
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
    let from: Mailbox = if cfg.smtp_from.is_empty() {
        cfg.smtp_username.parse()?
    } else {
        cfg.smtp_from.parse()?
    };
    let mut msg = Message::builder().from(from).subject(title);
    for to in cfg
        .smtp_to
        .split([',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        msg = msg.to(to.parse()?);
    }
    let msg = msg.body(body.to_string())?;
    let port = if cfg.smtp_port == 0 {
        465
    } else {
        cfg.smtp_port
    };
    let builder = if port == 465 {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host)?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host)?
    };
    let transport = builder
        .port(port)
        .credentials(Credentials::new(
            cfg.smtp_username.clone(),
            cfg.smtp_password.clone(),
        ))
        .build();
    transport.send(msg).await?;
    Ok(())
}
