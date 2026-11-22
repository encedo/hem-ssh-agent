//! The Pageant transport (Windows): PuTTY, plink, WinSCP, TortoiseGit and
//! the rest of the PuTTY family find an agent by its window, not by the
//! OpenSSH pipe.
//!
//! The protocol is PuTTY's (0.85: windows/agent-client.c, windows/pageant.c):
//! the client finds a top-level window of class and title "Pageant"
//! (`FindWindow`), creates a file mapping named `PageantRequest<thread id>`
//! owned by its user, writes the request into it (u32 big-endian length,
//! then the agent-protocol message) and sends `WM_COPYDATA` with
//! `dwData = 0x804e50ba` and the mapping's NUL-terminated name. The answer
//! is written into the same mapping, framed the same way; the message
//! returns nonzero. Pageant answers only a mapping owned by its own user
//! SID, or by the owner of its process (older clients): checked here alike.
//!
//! PuTTY 0.75 and later first try Pageant's named pipe
//! (`\\.\pipe\pageant.<user>.<hash>`) and fall back to this window, so the
//! window alone serves old and new clients. It is not started when a Pageant
//! is already running: two windows of that name and neither is reliably
//! found - the running one is left alone.

use std::io;
use std::sync::mpsc;
use std::thread::JoinHandle;

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Request, Response};
use ssh_agent_lib::ssh_encoding::{Decode, Encode};
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{
    MapViewOfFile, OpenFileMappingA, UnmapViewOfFile, VirtualQuery, FILE_MAP_ALL_ACCESS, FILE_MAP_WRITE,
    MEMORY_BASIC_INFORMATION,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThreadId};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, FindWindowW, GetMessageW, PostThreadMessageW,
    RegisterClassW, TranslateMessage, CW_USEDEFAULT, MSG, WM_COPYDATA, WM_QUIT, WNDCLASSW, WS_OVERLAPPEDWINDOW,
};

use crate::agent::HemAgent;

/// The window class and title PuTTY looks for.
pub const PAGEANT: &str = "Pageant";
/// `WM_COPYDATA` `dwData` of an agent request (PuTTY windows/platform.h).
pub const AGENT_COPYDATA_ID: usize = 0x804e50ba;
/// SSH_AGENT_FAILURE.
const FAILURE: u8 = 5;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Whether a window of this class and title exists (a running Pageant).
pub fn running(name: &str) -> bool {
    let w = wide(name);
    // Safety: two NUL-terminated wide strings.
    !unsafe { FindWindowW(w.as_ptr(), w.as_ptr()) }.is_null()
}

/// The window thread; `stop` ends it.
pub struct Pageant {
    thread: u32,
    join: Option<JoinHandle<()>>,
}

impl Pageant {
    pub fn stop(mut self) {
        self.quit();
    }

    fn quit(&mut self) {
        // Safety: posts to a thread id this value owns; a gone thread just fails.
        unsafe { PostThreadMessageW(self.thread, WM_QUIT, 0, 0) };
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for Pageant {
    fn drop(&mut self) {
        if self.join.is_some() {
            self.quit();
        }
    }
}

/// Serves `agent` as Pageant, or returns None (and logs why) when a Pageant
/// already runs. Requests are answered on `rt`.
pub fn start(agent: HemAgent, rt: tokio::runtime::Handle) -> io::Result<Option<Pageant>> {
    if running(PAGEANT) {
        log::warn!("Pageant is running: the Pageant transport stays off (PuTTY keeps using that Pageant)");
        return Ok(None);
    }
    start_as(PAGEANT, agent, rt).map(Some)
}

/// `start` under another window name: the tests, beside a real Pageant.
pub fn start_as(name: &str, agent: HemAgent, rt: tokio::runtime::Handle) -> io::Result<Pageant> {
    let ctx = Ctx { agent, rt, user: crate::listen::user_sid()?, default: default_sid()? };
    let name = name.to_owned();
    let (tx, rx) = mpsc::channel();
    let join = std::thread::Builder::new().name("pageant".into()).spawn(move || window(name, ctx, tx))?;
    match rx.recv() {
        Ok(Ok(thread)) => Ok(Pageant { thread, join: Some(join) }),
        Ok(Err(e)) => {
            let _ = join.join();
            Err(e)
        }
        Err(_) => Err(io::Error::other("the Pageant window thread ended")),
    }
}

struct Ctx {
    agent: HemAgent,
    rt: tokio::runtime::Handle,
    /// The SIDs a request's file mapping may be owned by, as strings.
    user: String,
    default: String,
}

thread_local! {
    // The window procedure runs on the window's own thread: its context too.
    static CTX: std::cell::RefCell<Option<Ctx>> = const { std::cell::RefCell::new(None) };
}

fn window(name: String, ctx: Ctx, ready: mpsc::Sender<io::Result<u32>>) {
    CTX.with(|c| *c.borrow_mut() = Some(ctx));
    let w = wide(&name);
    // Safety: plain Win32 calls with NUL-terminated strings that outlive them;
    // the window belongs to this thread and is destroyed on it.
    unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let class = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: instance,
            lpszClassName: w.as_ptr(),
            ..std::mem::zeroed()
        };
        // Registered once per process; a second start finds it registered.
        RegisterClassW(&class);
        let hwnd = CreateWindowExW(
            0,
            w.as_ptr(),
            w.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            100,
            100,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            let _ = ready.send(Err(io::Error::last_os_error()));
            return;
        }
        // Never shown: a top-level window only so that FindWindow sees it
        // (it does not see message-only windows).
        let _ = ready.send(Ok(GetCurrentThreadId()));
        log::info!("Pageant transport: window \"{name}\" (PuTTY, plink, WinSCP)");
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        DestroyWindow(hwnd);
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if msg == WM_COPYDATA {
        // Safety: WM_COPYDATA's lParam is a COPYDATASTRUCT valid for the call.
        return match unsafe { copydata(lparam as *const COPYDATASTRUCT) } {
            Ok(()) => 1,
            Err(why) => {
                log::warn!("Pageant request refused: {why}");
                0
            }
        };
    }
    // Safety: the arguments this procedure was called with.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

/// Closes a handle on drop.
struct Owned(HANDLE);
impl Drop for Owned {
    fn drop(&mut self) {
        // Safety: a handle this value opened.
        unsafe { CloseHandle(self.0) };
    }
}

/// Unmaps a view on drop.
struct View(windows_sys::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS);
impl Drop for View {
    fn drop(&mut self) {
        // Safety: a view this value mapped.
        unsafe { UnmapViewOfFile(self.0) };
    }
}

/// One request: the checks PuTTY's Pageant makes, in its order.
///
/// Safety: `cds` comes from a WM_COPYDATA message being handled.
unsafe fn copydata(cds: *const COPYDATASTRUCT) -> Result<(), String> {
    let cds = unsafe { cds.as_ref() }.ok_or("no COPYDATASTRUCT")?;
    if cds.dwData != AGENT_COPYDATA_ID {
        return Err(format!("not an agent request (dwData {:#x})", cds.dwData));
    }
    if cds.cbData == 0 || cds.lpData.is_null() {
        return Err("no mapping name".into());
    }
    // Safety: the system copied cbData bytes for this message.
    let name = unsafe { std::slice::from_raw_parts(cds.lpData as *const u8, cds.cbData as usize) };
    if name[name.len() - 1] != 0 {
        return Err("mapping name not NUL-terminated".into());
    }

    // Safety: a NUL-terminated name; the handle is closed by Owned.
    let map = unsafe { OpenFileMappingA(FILE_MAP_ALL_ACCESS, 0, name.as_ptr()) };
    if map.is_null() {
        return Err(format!("OpenFileMapping: {}", io::Error::last_os_error()));
    }
    let map = Owned(map);

    let owner = unsafe { owner_sid(map.0) }.map_err(|e| format!("owner of the mapping: {e}"))?;
    CTX.with(|c| {
        let c = c.borrow();
        let c = c.as_ref().ok_or("no context")?;
        if owner != c.user && owner != c.default {
            return Err(format!("mapping owned by {owner}, not by this user"));
        }
        Ok(())
    })?;

    // Safety: a mapping opened above; the view is unmapped by View.
    let view = unsafe { MapViewOfFile(map.0, FILE_MAP_WRITE, 0, 0, 0) };
    if view.Value.is_null() {
        return Err(format!("MapViewOfFile: {}", io::Error::last_os_error()));
    }
    let view = View(view);
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // Safety: queries the view just mapped into a local struct.
    if unsafe { VirtualQuery(view.0.Value, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) } == 0 {
        return Err(format!("VirtualQuery: {}", io::Error::last_os_error()));
    }
    let size = mbi.RegionSize;
    if size < 5 {
        return Err("mapping smaller than the smallest request".into());
    }
    // Safety: the region VirtualQuery reported for this view, writable.
    let buf = unsafe { std::slice::from_raw_parts_mut(view.0.Value as *mut u8, size) };

    let cap = size - 4;
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let reply = if len > cap {
        vec![FAILURE] // as Pageant: answered, without handling it
    } else {
        // A copy: the other process can write to the mapping meanwhile.
        let request = buf[4..4 + len].to_vec();
        let r = CTX.with(|c| c.borrow().as_ref().map(|c| answer(c, &request))).ok_or("no context")?;
        if r.len() > cap {
            vec![FAILURE]
        } else {
            r
        }
    };
    buf[..4].copy_from_slice(&(reply.len() as u32).to_be_bytes());
    buf[4..4 + reply.len()].copy_from_slice(&reply);
    Ok(())
}

/// The agent's answer to one message, as ssh-agent-lib's socket loop gives it.
fn answer(ctx: &Ctx, request: &[u8]) -> Vec<u8> {
    let response = match Request::decode(&mut &request[..]) {
        Ok(req) => {
            let mut session = ctx.agent.clone();
            match ctx.rt.block_on(session.handle(req)) {
                Ok(r) => r,
                Err(AgentError::ExtensionFailure) => Response::ExtensionFailure,
                Err(e) => {
                    log::debug!("Pageant request: {e:?}");
                    Response::Failure
                }
            }
        }
        Err(e) => {
            log::debug!("Pageant request not understood: {e:?}");
            Response::Failure
        }
    };
    let mut out = Vec::new();
    match response.encode(&mut out) {
        Ok(()) => out,
        Err(_) => vec![FAILURE],
    }
}

/// The owner SID of a kernel object, as a string.
///
/// Safety: `h` is a valid handle with READ_CONTROL.
unsafe fn owner_sid(h: HANDLE) -> io::Result<String> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let e = unsafe {
        GetSecurityInfo(
            h,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if e != 0 {
        return Err(io::Error::from_raw_os_error(e as i32));
    }
    let s = unsafe { sid_string(owner) };
    unsafe { LocalFree(sd) };
    s
}

/// Safety: `sid` is a valid SID.
unsafe fn sid_string(sid: PSID) -> io::Result<String> {
    let mut s: *mut u16 = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let n = (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count();
    let r = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(s, n) });
    unsafe { LocalFree(s.cast()) };
    Ok(r)
}

/// The owner of this process object: what a client's mapping is owned by
/// when it sets no owner (PuTTY before 0.61, and derived clients).
fn default_sid() -> io::Result<String> {
    // Safety: the pseudo handle of the current process needs no closing.
    unsafe { owner_sid(GetCurrentProcess()) }
}
