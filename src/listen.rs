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

/// The control channel's pipe (`src/control.rs`, the GUI dials it).
#[cfg(windows)]
pub const CONTROL_PIPE: &str = r"\\.\pipe\hem-ssh-agent-control";

/// Where the agent listens unless told otherwise.
pub fn default_address() -> io::Result<String> {
    #[cfg(windows)]
    {
        Ok(OPENSSH_PIPE.to_owned())
    }
    #[cfg(unix)]
    {
        Ok(runtime_dir()?.join("hem-ssh-agent.sock").to_string_lossy().into_owned())
    }
}

/// Where the control channel listens unless told otherwise: same access
/// rules as the agent's own address.
pub fn default_control_address() -> io::Result<String> {
    #[cfg(windows)]
    {
        Ok(CONTROL_PIPE.to_owned())
    }
    #[cfg(unix)]
    {
        Ok(runtime_dir()?.join("hem-ssh-agent-control.sock").to_string_lossy().into_owned())
    }
}

/// A directory private to the user: `XDG_RUNTIME_DIR` (systemd: 0700), else
/// `~/.hem-ssh-agent` created 0700.
#[cfg(unix)]
fn runtime_dir() -> io::Result<std::path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    Ok(match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d) => std::path::PathBuf::from(d),
        None => {
            let home = std::env::var_os("HOME").ok_or_else(|| io::Error::other("HOME not set"))?;
            let d = std::path::PathBuf::from(home).join(".hem-ssh-agent");
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&d)?;
            d
        }
    })
}

/// Who is on the other end of an accepted connection, as the platform says:
/// for the control channel's log and `whoami`. Not an authorisation - the
/// access list of the pipe / the socket's mode is.
pub trait Peer {
    fn who(&self) -> String;
}

#[cfg(unix)]
impl Peer for tokio::net::UnixStream {
    fn who(&self) -> String {
        match self.peer_cred() {
            Ok(c) => match c.pid() {
                Some(pid) => format!("uid {} pid {pid}", c.uid()),
                None => format!("uid {}", c.uid()),
            },
            Err(e) => format!("unknown ({e})"),
        }
    }
}

#[cfg(windows)]
impl Peer for tokio::net::windows::named_pipe::NamedPipeServer {
    fn who(&self) -> String {
        pipe::client(self)
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
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

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
        // Safety: the pseudo handle of the current process needs no closing.
        unsafe { process_sid(GetCurrentProcess()) }
    }

    /// The pipe client's user SID and process id (`whoami`, the log).
    pub fn client(pipe: &NamedPipeServer) -> String {
        use std::os::windows::io::AsRawHandle;
        let mut pid = 0u32;
        // Safety: the handle is the connected pipe instance, owned by `pipe`.
        if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) } == 0 {
            return format!("unknown ({})", io::Error::last_os_error());
        }
        // Safety: the process handle is checked and closed here.
        let sid = unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                Err(io::Error::last_os_error())
            } else {
                let r = process_sid(h);
                CloseHandle(h);
                r
            }
        };
        match sid {
            Ok(sid) => format!("{sid} pid {pid}"),
            Err(e) => format!("pid {pid} ({e})"),
        }
    }

    /// The user SID of a process's token, as a string.
    ///
    /// Safety: `process` is a valid process handle with query access.
    unsafe fn process_sid(process: HANDLE) -> io::Result<String> {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
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
