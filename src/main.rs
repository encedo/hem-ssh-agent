//! hem-ssh-agent CLI: `keys`, `pubkey`, `run`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use hem_sdk::{AuthOptions, Hem, HemError, HemOptions, RemoteOptions, Uv};
use hem_ssh_agent::config::{self, AuthMode, Config, UvSetting};
use hem_ssh_agent::{key_scopes, listen, load_key, Auth, HemAgent};
use zeroize::Zeroizing;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// SSH agent whose keys live in an Encedo HEM.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Configuration file [default: %APPDATA%\hem-ssh-agent\config.toml,
    /// ~/.config/hem-ssh-agent/config.toml]
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List the Ed25519 keys in the HEM (kid and label).
    Keys {
        /// HEM address; default: `url` from the configuration file.
        #[arg(long, env = "HEM_URL")]
        url: Option<String>,
    },
    /// Print a key as an OpenSSH public key line (config `pubkey`, authorized_keys, GitHub).
    Pubkey {
        #[arg(long, env = "HEM_URL")]
        url: Option<String>,
        /// Key ID (32 hex characters).
        #[arg(long)]
        kid: String,
    },
    /// Run the agent for the keys in the configuration file.
    Run {
        /// Password mode: ask for the HEM password now ($HEM_PASSWORD if set)
        /// instead of starting locked (unlock later with `ssh-add -X`).
        #[arg(long)]
        login: bool,
        /// Named pipe (Windows) or socket path; overrides `listen` in the file.
        #[arg(long)]
        listen: Option<String>,
    },
}

fn uv(s: UvSetting) -> Option<Uv> {
    match s {
        UvSetting::Bio => Some(Uv::Bio),
        UvSetting::Pin => Some(Uv::Pin),
        UvSetting::None => None,
    }
}

/// The configuration file: `required` for `run`, optional for the others.
fn load_config(path: Option<PathBuf>, required: bool) -> Res<Option<Config>> {
    let explicit = path.is_some();
    let Some(path) = path.or_else(config::default_path) else {
        return if required { Err("no configuration path (APPDATA / HOME not set)".into()) } else { Ok(None) };
    };
    if !path.exists() && !explicit && !required {
        return Ok(None);
    }
    Ok(Some(config::load(&path)?))
}

/// The user password: $HEM_PASSWORD (tests) or asked on the terminal.
fn password() -> std::io::Result<Zeroizing<String>> {
    match std::env::var("HEM_PASSWORD") {
        Ok(p) => Ok(Zeroizing::new(p)),
        Err(_) => rpassword::prompt_password("HEM password: ").map(Zeroizing::new),
    }
}

/// One token for a CLI command: the password, or the phone if the
/// configuration says `auth = "remote"`.
async fn cli_token(hem: &Hem, cfg: Option<&Config>, scope: Vec<String>, what: &str) -> Res<String> {
    match cfg {
        Some(c) if c.auth == AuthMode::Remote => {
            hem.hem_checkin().await?;
            eprintln!("approve on the phone: {what}");
            let opts = RemoteOptions {
                require: uv(c.uv),
                note: Some(format!("hem-ssh-agent: {what}")),
                poll_timeout: std::time::Duration::from_secs(c.approve_timeout.into()),
                ..Default::default()
            };
            Ok(hem.authorize_remote(scope, opts).await?)
        }
        _ => {
            // The check-in sets the HEM clock; a HEM behind an air gap goes without it.
            if let Err(e) = hem.hem_checkin().await {
                eprintln!("check-in failed, logging in without it: {e}");
            }
            let pw = password()?;
            Ok(hem.authorize_password(Some(&pw), scope, AuthOptions { remember: false, ..Default::default() }).await?)
        }
    }
}

fn url(flag: Option<String>, cfg: Option<&Config>) -> Res<String> {
    flag.or_else(|| cfg.map(|c| c.url.clone())).ok_or_else(|| "no HEM address: --url, HEM_URL or the configuration file".into())
}

async fn keys(cfg: Option<Config>, url_flag: Option<String>) -> Res<()> {
    let hem = Hem::new(&url(url_flag, cfg.as_ref())?, HemOptions::default())?;
    let tok = cli_token(&hem, cfg.as_ref(), vec!["keymgmt:list".into()], "list keys").await?;
    for k in hem.list_keys_all(&tok, false).await?.into_iter().filter(|k| k.key_type == "ED25519") {
        println!("{}  {}", k.kid, k.label);
    }
    Ok(())
}

async fn pubkey(cfg: Option<Config>, url_flag: Option<String>, kid: String) -> Res<()> {
    let hem = Hem::new(&url(url_flag, cfg.as_ref())?, HemOptions::default())?;
    let tok = cli_token(&hem, cfg.as_ref(), key_scopes(&[&kid]), "read a public key").await?;
    println!("{}", load_key(&hem, &tok, &kid).await?.openssh());
    Ok(())
}

async fn run(cfg: Config, login: bool, listen_flag: Option<String>) -> Res<()> {
    let keys = cfg.keys.iter().map(|k| k.agent_key()).collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() || keys.len() > 8 {
        return Err("the configuration needs 1..8 [[key]] entries (one token holds up to 8 scopes)".into());
    }
    let address = match listen_flag.or(cfg.listen.clone()) {
        Some(a) => a,
        None => listen::default_address()?,
    };
    // Take the address first: nothing asked if another agent holds it.
    let listener = listen::bind(&address).await?;

    let hem = Arc::new(Hem::new(&cfg.url, HemOptions::default())?);
    let auth = match cfg.auth {
        AuthMode::Password => Auth::Password { ttl: cfg.ttl },
        AuthMode::Remote => {
            Auth::Remote { uv: uv(cfg.uv), timeout: std::time::Duration::from_secs(cfg.approve_timeout.into()) }
        }
    };
    let agent = HemAgent::new(hem, keys, auth.clone());
    for k in agent.keys() {
        eprintln!("{}", k.openssh());
    }
    match auth {
        Auth::Password { ttl } if login => {
            agent.unlock_with_password(&password()?).await?;
            eprintln!("unlocked; token lifetime {ttl} s; `ssh-add -x` locks");
        }
        Auth::Password { .. } => eprintln!("locked: `ssh-add -X` and the HEM password unlock"),
        Auth::Remote { uv, timeout } => eprintln!(
            "remote: each new token is approved on the phone (uv {uv:?}, wait {} s)",
            timeout.as_secs()
        ),
    }
    eprintln!("listening on {address}");
    #[cfg(unix)]
    eprintln!("export SSH_AUTH_SOCK={address}");

    tokio::select! {
        r = listen::serve(listener, agent) => r?,
        _ = tokio::signal::ctrl_c() => eprintln!("stopping"),
    }
    #[cfg(unix)]
    let _ = std::fs::remove_file(&address);
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("hem_ssh_agent=info")).init();
    let cli = Cli::parse();
    let r = async {
        match cli.cmd {
            Cmd::Keys { url } => keys(load_config(cli.config, false)?, url).await,
            Cmd::Pubkey { url, kid } => pubkey(load_config(cli.config, false)?, url, kid).await,
            Cmd::Run { login, listen } => {
                let cfg = load_config(cli.config, true)?.expect("required");
                run(cfg, login, listen).await
            }
        }
    }
    .await;
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            match e.downcast_ref::<HemError>() {
                Some(h) => eprintln!("error: {} ({})", e, h.code),
                None => eprintln!("error: {e}"),
            }
            ExitCode::FAILURE
        }
    }
}
