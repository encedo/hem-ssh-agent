//! The command line, shared by both executables:
//! `hem-ssh-agent` (console: keys, pubkey, run, install, uninstall) and
//! `hem-ssh-agentw` (Windows, no console window: `run` in the background,
//! logging to a file; started at logon by `install`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use hem_sdk::{AuthOptions, Hem, HemError, HemOptions, RemoteOptions, Uv};
use zeroize::Zeroizing;

use crate::config::{self, AuthMode, Config, UvSetting};
use crate::{key_scopes, listen, load_key, Auth, HemAgent};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// A log file is moved to `<name>.old` at start when it is bigger than this.
const LOG_ROTATE_BYTES: u64 = 1024 * 1024;

/// SSH agent whose keys live in an Encedo HEM.
#[derive(Parser)]
#[command(version, about)]
pub struct Cli {
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
        /// Not in the background executable (no terminal to ask on).
        #[arg(long)]
        login: bool,
        /// Named pipe (Windows) or socket path; overrides `listen` in the file.
        #[arg(long)]
        listen: Option<String>,
        /// Log to this file instead of the terminal [background default:
        /// %LOCALAPPDATA%\hem-ssh-agent\agent.log].
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
    /// Start the agent at logon (Windows: hem-ssh-agentw.exe from the
    /// current user's Run key; no administrator rights needed).
    Install {
        /// Also start it now, in the background.
        #[arg(long)]
        start: bool,
    },
    /// Stop starting the agent at logon (a running agent keeps running).
    Uninstall,
}

/// `hem-ssh-agent.exe`: logs on the terminal.
pub fn main_console() -> ExitCode {
    let cli = Cli::parse();
    let log_file = match &cli.cmd {
        Cmd::Run { log_file, .. } => log_file.clone(),
        _ => None,
    };
    if let Err(e) = init_log(log_file.as_deref()) {
        eprintln!("error: log file: {e}");
        return ExitCode::FAILURE;
    }
    finish(runtime().block_on(dispatch(cli, false)))
}

/// `hem-ssh-agentw.exe`: no terminal; `run` only, logs to a file.
pub fn main_background() -> ExitCode {
    let cli = Cli::parse();
    let log_file = match &cli.cmd {
        Cmd::Run { log_file, .. } => log_file.clone().or_else(default_log_path),
        _ => default_log_path(),
    };
    if init_log(log_file.as_deref()).is_err() {
        return ExitCode::FAILURE; // nowhere to say it
    }
    let r = match cli.cmd {
        Cmd::Run { login: true, .. } => Err("--login needs a terminal: use hem-ssh-agent.exe, or ssh-add -X".into()),
        Cmd::Run { .. } => runtime().block_on(dispatch(cli, true)),
        _ => Err("hem-ssh-agentw only runs the agent (`run`); use hem-ssh-agent.exe for the rest".into()),
    };
    finish(r)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime")
}

fn finish(r: Res<()>) -> ExitCode {
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let msg = match e.downcast_ref::<HemError>() {
                Some(h) => format!("{e} ({})", h.code),
                None => e.to_string(),
            };
            log::error!("{msg}");
            ExitCode::FAILURE
        }
    }
}

async fn dispatch(cli: Cli, background: bool) -> Res<()> {
    match cli.cmd {
        Cmd::Keys { url } => keys(load_config(cli.config, false)?, url).await,
        Cmd::Pubkey { url, kid } => pubkey(load_config(cli.config, false)?, url, kid).await,
        Cmd::Run { login, listen, .. } => {
            let cfg = load_config(cli.config, true)?.expect("required");
            run(cfg, login && !background, listen).await
        }
        Cmd::Install { start } => install(cli.config, start),
        Cmd::Uninstall => uninstall(),
    }
}

/// Terminal (stderr) or a file. A file over 1 MB is moved to `.old` first.
fn init_log(file: Option<&Path>) -> std::io::Result<()> {
    let mut b = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("hem_ssh_agent=info"));
    if let Some(path) = file {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        if std::fs::metadata(path).map(|m| m.len() > LOG_ROTATE_BYTES).unwrap_or(false) {
            let _ = std::fs::rename(path, path.with_extension("log.old"));
        }
        let f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        b.target(env_logger::Target::Pipe(Box::new(f))).write_style(env_logger::WriteStyle::Never);
    }
    b.init();
    Ok(())
}

/// %LOCALAPPDATA%\hem-ssh-agent\agent.log; ~/.local/state/hem-ssh-agent/agent.log.
fn default_log_path() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(unix)]
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("state")));
    base.map(|b| b.join("hem-ssh-agent").join("agent.log"))
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

fn agent_keys(cfg: &Config) -> Res<Vec<crate::AgentKey>> {
    let keys = cfg.keys.iter().map(|k| k.agent_key()).collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() || keys.len() > 8 {
        return Err("the configuration needs 1..8 [[key]] entries (one token holds up to 8 scopes)".into());
    }
    Ok(keys)
}

async fn run(cfg: Config, login: bool, listen_flag: Option<String>) -> Res<()> {
    let keys = agent_keys(&cfg)?;
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
    log::info!("hem-ssh-agent {} for {}", env!("CARGO_PKG_VERSION"), cfg.url);
    for k in agent.keys() {
        log::info!("key {}: {}", k.kid, k.openssh());
    }
    match auth {
        Auth::Password { ttl } if login => {
            agent.unlock_with_password(&password()?).await?;
            log::info!("unlocked; token lifetime {ttl} s; `ssh-add -x` locks");
        }
        Auth::Password { .. } => log::info!("locked: `ssh-add -X` and the HEM password unlock"),
        Auth::Remote { uv, timeout } => log::info!(
            "remote: each new token is approved on the phone (uv {uv:?}, wait {} s)",
            timeout.as_secs()
        ),
    }
    log::info!("listening on {address}");
    #[cfg(unix)]
    eprintln!("export SSH_AUTH_SOCK={address}");

    tokio::select! {
        r = listen::serve(listener, agent) => r?,
        _ = tokio::signal::ctrl_c() => log::info!("stopping"),
    }
    #[cfg(unix)]
    let _ = std::fs::remove_file(&address);
    Ok(())
}

#[cfg(windows)]
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(windows)]
const RUN_VALUE: &str = "hem-ssh-agent";

#[cfg(windows)]
fn install(config_flag: Option<PathBuf>, start: bool) -> Res<()> {
    use std::process::Command;

    let w = std::env::current_exe()?.with_file_name("hem-ssh-agentw.exe");
    if !w.exists() {
        return Err(format!("{} not found next to this program", w.display()).into());
    }
    // The configuration must be usable now, not at the next logon.
    let config_flag = config_flag.map(std::path::absolute).transpose()?;
    let cfg = load_config(config_flag.clone(), true)?.expect("required");
    agent_keys(&cfg)?;

    let mut args = vec!["run".to_owned()];
    if let Some(c) = &config_flag {
        args.push("--config".into());
        args.push(c.display().to_string());
    }
    let command = std::iter::once(format!("\"{}\"", w.display()))
        .chain(args.iter().map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a.clone() }))
        .collect::<Vec<_>>()
        .join(" ");
    let st = Command::new("reg")
        .args(["add", RUN_KEY, "/v", RUN_VALUE, "/t", "REG_SZ", "/d", &command, "/f"])
        .stdout(std::process::Stdio::null())
        .status()?;
    if !st.success() {
        return Err(format!("reg add {RUN_KEY} failed").into());
    }
    println!("starts at logon: {command}");
    println!("log: {}", default_log_path().map(|p| p.display().to_string()).unwrap_or_default());

    warn_openssh_service();

    if start {
        Command::new(&w).args(&args).spawn()?;
        println!("started in the background; `ssh-add -l` lists the keys");
    }
    Ok(())
}

/// The Windows OpenSSH agent service owns the same pipe: say so if it can run.
#[cfg(windows)]
fn warn_openssh_service() {
    use std::process::Command;
    let out = |args: &[&str]| {
        Command::new("sc").args(args).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
    };
    let running = out(&["query", "ssh-agent"]).contains("RUNNING");
    let disabled = out(&["qc", "ssh-agent"]).contains("DISABLED");
    if running || !disabled {
        println!(
            "warning: the Windows OpenSSH ssh-agent service {} - it uses the same pipe. As administrator:\n  \
             Stop-Service ssh-agent; Set-Service ssh-agent -StartupType Disabled",
            if running { "is running" } else { "is not disabled" }
        );
    }
}

#[cfg(windows)]
fn uninstall() -> Res<()> {
    let st = std::process::Command::new("reg")
        .args(["delete", RUN_KEY, "/v", RUN_VALUE, "/f"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if st.success() {
        println!("no longer started at logon");
    } else {
        println!("was not set to start at logon");
    }
    println!("a running agent keeps running: taskkill /IM hem-ssh-agentw.exe");
    Ok(())
}

#[cfg(unix)]
fn install(_config: Option<PathBuf>, _start: bool) -> Res<()> {
    Err("install: not on this platform yet (planned: systemd --user / launchd)".into())
}

#[cfg(unix)]
fn uninstall() -> Res<()> {
    Err("uninstall: not on this platform yet".into())
}
