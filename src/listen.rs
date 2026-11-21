//! The platform-specific part: where clients reach the agent.
//!
//! Windows: the OpenSSH named pipe (`ssh.exe`, `ssh-add.exe`, `ssh-keygen.exe`
//! from Windows OpenSSH use it). Remote clients are refused (tokio default).
//! Unix: a socket for `SSH_AUTH_SOCK`, mode 0600, in a 0700 directory.

use std::io;

use ssh_agent_lib::agent::listen;
use ssh_agent_lib::error::AgentError;

use crate::agent::HemAgent;

#[cfg(windows)]
pub type Listener = ssh_agent_lib::agent::NamedPipeListener;
#[cfg(unix)]
pub type Listener = tokio::net::UnixListener;

/// The pipe Windows OpenSSH looks for (the system `ssh-agent` service uses it
/// too; it is disabled on a machine where this agent runs).
#[cfg(windows)]
pub const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// Where the agent listens unless told otherwise.
pub fn default_address() -> io::Result<String> {
    #[cfg(windows)]
    {
        Ok(OPENSSH_PIPE.to_owned())
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let dir = match std::env::var_os("XDG_RUNTIME_DIR") {
            // Already private to the user (systemd: 0700).
            Some(d) => std::path::PathBuf::from(d),
            None => {
                let home = std::env::var_os("HOME").ok_or_else(|| io::Error::other("HOME not set"))?;
                let d = std::path::PathBuf::from(home).join(".hem-ssh-agent");
                std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&d)?;
                d
            }
        };
        Ok(dir.join("hem-ssh-agent.sock").to_string_lossy().into_owned())
    }
}

/// Takes the address. Fails if another agent already holds it.
pub async fn bind(address: &str) -> io::Result<Listener> {
    #[cfg(windows)]
    {
        ssh_agent_lib::agent::NamedPipeListener::bind(address).map_err(|e| {
            io::Error::new(e.kind(), format!("{address}: {e} (another agent running? Windows OpenSSH ssh-agent service?)"))
        })
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        if let Ok(meta) = std::fs::symlink_metadata(address) {
            if !meta.file_type().is_socket() {
                return Err(io::Error::other(format!("{address} exists and is not a socket")));
            }
            if tokio::net::UnixStream::connect(address).await.is_ok() {
                return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("{address}: another agent is running")));
            }
            std::fs::remove_file(address)?; // stale socket from a previous run
        }
        let l = tokio::net::UnixListener::bind(address)?;
        std::fs::set_permissions(address, std::fs::Permissions::from_mode(0o600))?;
        Ok(l)
    }
}

/// Serves clients until the listener fails.
pub async fn serve(listener: Listener, agent: HemAgent) -> Result<(), AgentError> {
    listen(listener, agent).await
}
