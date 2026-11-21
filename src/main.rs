//! hem-ssh-agent CLI: `keys`, `pubkey`, `run`.

use std::process::ExitCode;
use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use hem_sdk::{AuthOptions, Hem, HemError, HemOptions};
use hem_ssh_agent::{key_scopes, listen, load_key, HemAgent};
use zeroize::Zeroizing;

/// SSH agent whose keys live in an Encedo HEM.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct Device {
    /// HEM address, e.g. https://my.ence.do
    #[arg(long, env = "HEM_URL")]
    url: String,
}

#[derive(Subcommand)]
enum Cmd {
    /// List the Ed25519 keys in the HEM (kid and label).
    Keys {
        #[command(flatten)]
        device: Device,
    },
    /// Print a key as an OpenSSH public key line (authorized_keys, GitHub).
    Pubkey {
        #[command(flatten)]
        device: Device,
        /// Key ID (32 hex characters).
        #[arg(long)]
        kid: String,
    },
    /// Run the agent for the given keys.
    Run {
        #[command(flatten)]
        device: Device,
        /// Key ID to serve; repeat for more keys (up to 8).
        #[arg(long = "kid", required = true)]
        kids: Vec<String>,
        /// Named pipe (Windows) or socket path; default: the OpenSSH pipe /
        /// $XDG_RUNTIME_DIR/hem-ssh-agent.sock.
        #[arg(long)]
        listen: Option<String>,
        /// Token lifetime in seconds; a new token is minted when it expires.
        #[arg(long, default_value_t = 300)]
        ttl: u32,
    },
}

/// The user password: $HEM_PASSWORD (tests) or asked on the terminal.
fn password() -> std::io::Result<Zeroizing<String>> {
    match std::env::var("HEM_PASSWORD") {
        Ok(p) => Ok(Zeroizing::new(p)),
        Err(_) => rpassword::prompt_password("HEM password: ").map(Zeroizing::new),
    }
}

fn hem(device: &Device) -> Result<Hem, HemError> {
    Hem::new(&device.url, HemOptions::default())
}

async fn keys(device: Device) -> Result<(), Box<dyn std::error::Error>> {
    let hem = hem(&device)?;
    let pw = password()?;
    let tok = hem.authorize_password(Some(&pw), "keymgmt:list", AuthOptions::default()).await?;
    for k in hem.list_keys_all(&tok, false).await?.into_iter().filter(|k| k.key_type == "ED25519") {
        println!("{}  {}", k.kid, k.label);
    }
    Ok(())
}

async fn pubkey(device: Device, kid: String) -> Result<(), Box<dyn std::error::Error>> {
    let hem = hem(&device)?;
    let pw = password()?;
    let tok = hem.authorize_password(Some(&pw), key_scopes(&[&kid]), AuthOptions::default()).await?;
    println!("{}", load_key(&hem, &tok, &kid).await?.openssh());
    Ok(())
}

async fn run(device: Device, kids: Vec<String>, address: Option<String>, ttl: u32) -> Result<(), Box<dyn std::error::Error>> {
    let address = match address {
        Some(a) => a,
        None => listen::default_address()?,
    };
    // Take the address first: no password asked if another agent holds it.
    let listener = listen::bind(&address).await?;

    let hem = Arc::new(hem(&device)?);
    let auth = AuthOptions { exp_seconds: ttl, remember: true, ctx: None };
    let pw = password()?;
    let tok = hem.authorize_password(Some(&pw), key_scopes(&kids), auth.clone()).await?;
    drop(pw);
    let mut keys = Vec::new();
    for kid in &kids {
        let k = load_key(&hem, &tok, kid).await?;
        eprintln!("{}", k.openssh());
        keys.push(k);
    }
    eprintln!("listening on {address}, {} key(s), token lifetime {ttl} s", keys.len());
    #[cfg(unix)]
    eprintln!("export SSH_AUTH_SOCK={address}");

    let agent = HemAgent::new(hem, keys, auth);
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
    let r = match cli.cmd {
        Cmd::Keys { device } => keys(device).await,
        Cmd::Pubkey { device, kid } => pubkey(device, kid).await,
        Cmd::Run { device, kids, listen, ttl } => run(device, kids, listen, ttl).await,
    };
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
