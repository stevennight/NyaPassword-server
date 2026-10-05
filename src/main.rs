//! NyaPassword server: command line.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use nyapassword_server::config::Config;
use nyapassword_server::{admin, backup, db, open_state, restore, serve};

#[derive(Parser)]
#[command(
    name = "nyapassword-server",
    version,
    about = "NyaPassword sync server"
)]
struct Cli {
    /// Data directory (default: $NYAPASSWORD_DATA or ./data).
    #[arg(long, global = true)]
    data: Option<PathBuf>,
    /// Exit 0 when the server on the configured address answers (for Docker HEALTHCHECK).
    #[arg(long)]
    healthcheck: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once
enum Cmd {
    /// Run the server (the default).
    Serve,
    /// Set the admin console password (prompted, or from NYAPASSWORD_ADMIN_PASSWORD).
    AdminPassword,
    /// Turn on TOTP for the admin console; prints the otpauth:// URI to scan.
    AdminTotp {
        /// Turn it off instead.
        #[arg(long)]
        off: bool,
    },
    /// Create an invite code for registering another account.
    Invite {
        #[arg(long, default_value_t = 24)]
        hours: u32,
    },
    /// Run a backup now (the server may keep running).
    BackupNow,
    /// Run a restore drill on the newest backup now.
    Drill,
    /// Generate an age key pair for the offline backup key (print and keep the secret part safe).
    AgeKeygen,
    /// Restore a data directory from a backup.
    Restore(restore::RestoreArgs),
}

fn read_password(prompt: &str) -> anyhow::Result<String> {
    if let Ok(p) = std::env::var("NYAPASSWORD_ADMIN_PASSWORD") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    eprint!("{prompt}");
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load(cli.data.clone())?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&cfg.log).unwrap_or_else(|_| "info".into()),
        )
        .init();

    if cli.healthcheck {
        let addr = if cfg.listen.ip().is_unspecified() {
            SocketAddr::from(([127, 0, 0, 1], cfg.listen.port()))
        } else {
            cfg.listen
        };
        let ok = reqwest::Client::new()
            .get(format!("http://{addr}/v1/health"))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        std::process::exit(if ok { 0 } else { 1 });
    }

    match cli.cmd.unwrap_or(Cmd::Serve) {
        Cmd::Serve => serve(open_state(cfg)?).await,
        Cmd::AdminPassword => {
            let st = open_state(cfg)?;
            let pw = read_password("new admin password: ")?;
            anyhow::ensure!(pw.chars().count() >= 12, "use at least 12 characters");
            st.db
                .run_sync(|c| Ok(admin::set_password(c, &pw)?))
                .map_err(|e| anyhow::anyhow!(e.message))?;
            println!("admin password set");
            Ok(())
        }
        Cmd::AdminTotp { off } => {
            let st = open_state(cfg)?;
            if off {
                st.db
                    .run_sync(|c| {
                        Ok(
                            c.execute("DELETE FROM settings WHERE k = ?1", [admin::TOTP_KEY])
                                .map(|_| ())?,
                        )
                    })
                    .map_err(|e| anyhow::anyhow!(e.message))?;
                println!("admin TOTP off");
            } else {
                let secret = npw_otp::base32_encode(&npw_crypto::random_bytes::<20>());
                st.db
                    .run_sync(|c| Ok(db::set_setting(c, admin::TOTP_KEY, &secret)?))
                    .map_err(|e| anyhow::anyhow!(e.message))?;
                println!("{}", admin::totp_uri(&secret));
            }
            Ok(())
        }
        Cmd::Invite { hours } => {
            let st = open_state(cfg)?;
            let inv = st
                .db
                .run_sync(|c| Ok(admin::create_invite(c, hours)?))
                .map_err(|e| anyhow::anyhow!(e.message))?;
            println!("{} (valid for {hours} h)", inv.code);
            Ok(())
        }
        Cmd::BackupNow => {
            let st = open_state(cfg)?;
            let run = backup::run_backup(&st, "manual")
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            println!("{}", serde_json::to_string_pretty(&run)?);
            anyhow::ensure!(run.results.iter().all(|r| r.ok), "some targets failed");
            Ok(())
        }
        Cmd::Drill => {
            let st = open_state(cfg)?;
            let run = backup::run_drill(&st, None)
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            println!("{}", serde_json::to_string_pretty(&run)?);
            anyhow::ensure!(run.ok, "drill failed");
            Ok(())
        }
        Cmd::AgeKeygen => {
            let (secret, public) = npw_backup::generate_identity();
            println!("# public key (register it in the admin console: 恢复密钥, paste an existing public key): {public}");
            println!("{secret}");
            Ok(())
        }
        Cmd::Restore(args) => restore::run(args, cfg.data_dir).await,
    }
}
