//! The platform-specific part: where clients reach the agent.
//!
//! Windows: the OpenSSH named pipe (`ssh.exe`, `ssh-add.exe`, `ssh-keygen.exe`
//! from Windows OpenSSH use it). Remote clients are refused, and the pipe's
//! access list allows only the current user and SYSTEM.
//! Unix: a socket for `SSH_AUTH_SOCK`, mode 0600, in a 0700 directory.

use std::io;

use ssh_agent_lib::agent::listen;
use ssh_agent_lib::error::AgentError;

use crate::agent::HemAgent;

#[cfg(windows)]
pub use pipe::PipeListener as Listener;
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
        pipe::PipeListener::bind(address).map_err(|e| {
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

#[cfg(windows)]
mod pipe {
    //! A named pipe listener as `ssh_agent_lib::agent::NamedPipeListener`,
    //! with an access list: `D:P(A;;GA;;;SY)(A;;GA;;;<user SID>)` - the
    //! current user and SYSTEM only, no inherited entries. Every instance of
    //! the pipe is created with it.

    use std::ffi::{c_void, OsStr, OsString};
    use std::io;
    use std::os::windows::ffi::OsStrExt;

    use async_trait::async_trait;
    use ssh_agent_lib::agent::{Agent, ListeningSocket, Session};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use crate::agent::HemAgent;

    /// A security descriptor from SDDL, freed on drop.
    struct Descriptor(PSECURITY_DESCRIPTOR);

    // The descriptor is plain heap memory, written once and only read after.
    unsafe impl Send for Descriptor {}
    unsafe impl Sync for Descriptor {}

    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    /// The current user's SID as a string (S-1-5-21-...).
    fn user_sid() -> io::Result<String> {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
            // u64 elements: TOKEN_USER holds pointers, the buffer must be aligned for them.
            let mut buf = vec![0u64; (len as usize).div_ceil(8)];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
            CloseHandle(token);
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut s: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut s) == 0 {
                return Err(io::Error::last_os_error());
            }
            let n = (0..).take_while(|&i| *s.add(i) != 0).count();
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
            LocalFree(s.cast());
            Ok(sid)
        }
    }

    fn descriptor(sddl: &str) -> io::Result<Descriptor> {
        let w = wide(OsStr::new(sddl));
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(w.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut())
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Descriptor(sd))
    }

    pub struct PipeListener {
        server: NamedPipeServer,
        name: OsString,
        sd: Descriptor,
    }

    impl std::fmt::Debug for PipeListener {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PipeListener").field("name", &self.name).finish()
        }
    }

    impl PipeListener {
        pub fn bind(name: &str) -> io::Result<Self> {
            let sd = descriptor(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{})", user_sid()?))?;
            let name = OsString::from(name);
            let server = create(&name, &sd, true)?;
            Ok(Self { server, name, sd })
        }
    }

    fn create(name: &OsStr, sd: &Descriptor, first: bool) -> io::Result<NamedPipeServer> {
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        // Safety: `attrs` points at a valid descriptor that outlives the call.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(name, &mut attrs as *mut SECURITY_ATTRIBUTES as *mut c_void)
        }
    }

    #[async_trait]
    impl ListeningSocket for PipeListener {
        type Stream = NamedPipeServer;
        async fn accept(&mut self) -> io::Result<Self::Stream> {
            self.server.connect().await?;
            let next = create(&self.name, &self.sd, false)?;
            Ok(std::mem::replace(&mut self.server, next))
        }
    }

    impl Agent<PipeListener> for HemAgent {
        fn new_session(&mut self, _socket: &NamedPipeServer) -> impl Session {
            self.clone()
        }
    }
}
