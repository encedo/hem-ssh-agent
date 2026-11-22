//! The Pageant transport, offline, as PuTTY's client calls it
//! (windows/agent-client.c): a file mapping, WM_COPYDATA, the answer in the
//! mapping. Under a window name of its own, so a real Pageant on the machine
//! is neither found nor disturbed. No HEM: listing keys needs none.
#![cfg(windows)]

use std::sync::Arc;

use hem_sdk::{Hem, HemOptions};
use hem_ssh_agent::pageant::{self, AGENT_COPYDATA_ID};
use hem_ssh_agent::{AgentKey, Auth, HemAgent};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
use windows_sys::Win32::System::Memory::{
    CreateFileMappingA, MapViewOfFile, UnmapViewOfFile, FILE_MAP_WRITE, PAGE_READWRITE,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, SendMessageW, WM_COPYDATA};

const MAP_SIZE: u32 = 8192; // PuTTY before 0.76 (AGENT_MAX_MSGLEN)

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// One request the way PuTTY sends it: (SendMessage result, reply bytes).
fn query(window: &str, frame: &[u8], dw_data: usize, nul: bool) -> (isize, Vec<u8>) {
    let name = format!("PageantRequest{:08x}\0", std::process::id());
    unsafe {
        let map = CreateFileMappingA(INVALID_HANDLE_VALUE, std::ptr::null(), PAGE_READWRITE, 0, MAP_SIZE, name.as_ptr());
        assert!(!map.is_null(), "CreateFileMapping");
        let view = MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, 0);
        assert!(!view.Value.is_null(), "MapViewOfFile");
        let p = view.Value as *mut u8;
        std::ptr::copy_nonoverlapping(frame.as_ptr(), p, frame.len());

        let w = wide(window);
        let hwnd = FindWindowW(w.as_ptr(), w.as_ptr());
        assert!(!hwnd.is_null(), "no window {window}");
        let cb = if nul { name.len() } else { name.len() - 1 };
        let cds = COPYDATASTRUCT { dwData: dw_data, cbData: cb as u32, lpData: name.as_ptr() as *mut _ };
        let r = SendMessageW(hwnd, WM_COPYDATA, 0, &cds as *const _ as isize);

        let len = u32::from_be_bytes(std::slice::from_raw_parts(p, 4).try_into().unwrap()) as usize;
        let reply = std::slice::from_raw_parts(p.add(4), len.min(MAP_SIZE as usize - 4)).to_vec();
        UnmapViewOfFile(view);
        CloseHandle(map);
        (r, reply)
    }
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut f = (body.len() as u32).to_be_bytes().to_vec();
    f.extend_from_slice(body);
    f
}

#[test]
fn pageant_window_answers_as_putty_expects() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let hem = Arc::new(Hem::new("https://127.0.0.1:9", HemOptions::default()).unwrap());
    let key = AgentKey {
        kid: "00112233445566778899aabbccddeeff".into(),
        public: KeyData::Ed25519(Ed25519PublicKey([7; 32])),
        comment: "pageant test".into(),
    };
    // Remote mode is never locked: the key is listed without the HEM.
    let agent = HemAgent::new(hem, vec![key], Auth::Remote { uv: None, timeout: std::time::Duration::from_secs(1) });
    let window = format!("hem-ssh-agent-pageant-test-{}", std::process::id());
    assert!(!pageant::running(&window));
    let p = pageant::start_as(&window, agent, rt.handle().clone()).unwrap();
    assert!(pageant::running(&window));

    // SSH_AGENTC_REQUEST_IDENTITIES -> SSH_AGENT_IDENTITIES_ANSWER, one key.
    let (r, reply) = query(&window, &framed(&[11]), AGENT_COPYDATA_ID, true);
    assert_eq!(r, 1);
    assert_eq!(reply[0], 12, "reply {reply:?}");
    assert_eq!(u32::from_be_bytes(reply[1..5].try_into().unwrap()), 1);
    assert!(reply.windows(12).any(|w| w == b"pageant test"), "comment in {reply:?}");

    // A length beyond the mapping: answered with SSH_AGENT_FAILURE, unread.
    let (r, reply) = query(&window, &[0xff, 0xff, 0xff, 0xff, 11], AGENT_COPYDATA_ID, true);
    assert_eq!((r, reply), (1, vec![5]));

    // A message type nobody knows: SSH_AGENT_FAILURE.
    let (r, reply) = query(&window, &framed(&[200]), AGENT_COPYDATA_ID, true);
    assert_eq!((r, reply), (1, vec![5]));

    // Not an agent request, or a name without its NUL: not answered.
    assert_eq!(query(&window, &framed(&[11]), 0x1234, true).0, 0);
    assert_eq!(query(&window, &framed(&[11]), AGENT_COPYDATA_ID, false).0, 0);

    p.stop();
    assert!(!pageant::running(&window));
}
