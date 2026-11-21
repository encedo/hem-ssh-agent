//! The control channel end to end, offline: the real transport (named pipe /
//! unix socket), a client as the GUI is, no HEM (every case here is refused
//! or answered before the agent would call it).

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hem_sdk::{Hem, HemOptions};
use hem_ssh_agent::control::{read_msg, write_msg, Build, Msg, Reply, Status, MAX_MESSAGE};
use hem_ssh_agent::{listen, AgentKey, Auth, HemAgent};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

const KID: &str = "00112233445566778899aabbccddeeff";

fn agent() -> HemAgent {
    // Nothing listens here: a case that reached the HEM would fail to connect.
    let hem = Arc::new(Hem::new("https://127.0.0.1:9", HemOptions::default()).unwrap());
    let key = AgentKey {
        kid: KID.into(),
        public: KeyData::Ed25519(Ed25519PublicKey([7; 32])),
        comment: "control test".into(),
    };
    HemAgent::new(hem, vec![key], Auth::Password { ttl: 60 })
}

fn address() -> String {
    let tag = format!("hem-ssh-agent-control-test-{}", std::process::id());
    #[cfg(windows)]
    return format!(r"\\.\pipe\{tag}");
    #[cfg(unix)]
    return std::env::temp_dir().join(format!("{tag}.sock")).to_string_lossy().into_owned();
}

#[cfg(windows)]
async fn connect(address: &str) -> impl AsyncRead + AsyncWrite + Unpin {
    tokio::net::windows::named_pipe::ClientOptions::new().open(address).unwrap()
}

#[cfg(unix)]
async fn connect(address: &str) -> impl AsyncRead + AsyncWrite + Unpin {
    tokio::net::UnixStream::connect(address).await.unwrap()
}

/// A token-shaped string (the agent reads `exp` and `scope` before anything else).
fn jwt(payload: &str) -> String {
    format!("{}.{}.{}", URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#), URL_SAFE_NO_PAD.encode(payload), "sig")
}

async fn ask<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, req: &str) -> Reply {
    let b = req.as_bytes();
    s.write_all(&(b.len() as u32).to_be_bytes()).await.unwrap();
    s.write_all(b).await.unwrap();
    match next(s).await {
        Msg::Reply { reply } => reply,
        m => panic!("expected a reply, got {m:?}"),
    }
}

async fn next<S: AsyncRead + Unpin>(s: &mut S) -> Msg {
    let b = read_msg(s).await.unwrap().expect("a message");
    serde_json::from_slice(&b).unwrap()
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

#[tokio::test]
async fn control_channel() {
    let address = address();
    let listener = listen::bind(&address).await.unwrap();
    tokio::spawn(hem_ssh_agent::control::serve(listener, agent()));
    let mut c = connect(&address).await;
    let build = serde_json::to_string(&Build::current()).unwrap();

    // whoami: the build and the caller, as the platform reports it.
    let r = ask(&mut c, r#"{"op":"whoami"}"#).await;
    assert!(r.ok, "{r:?}");
    assert_eq!(r.build, Some(Build::current()));
    assert!(r.who.as_deref().unwrap().contains("pid"), "{r:?}");

    // watch: a reply, then the snapshot - locked, nothing pending.
    let r = ask(&mut c, r#"{"op":"watch"}"#).await;
    assert!(r.ok, "{r:?}");
    let Msg::Event { event } = next(&mut c).await else { panic!("expected the snapshot") };
    let Status { state, auth, keys, expires_at, pending, .. } = event;
    assert_eq!((state.as_str(), auth.as_str()), ("locked", "password"));
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kid, KID);
    assert_eq!((expires_at, pending), (None, None));

    // Refused before the HEM is asked.
    let scope = format!("keymgmt:use:{KID}");
    let good = jwt(&format!(r#"{{"exp":{},"scope":["{scope}"]}}"#, now() + 600));
    let cases = [
        (r#"{"op":"token","token":"t","password":"p"}"#.to_owned(), "bad_request"), // only a token crosses
        (r#"{"op":"start"}"#.to_owned(), "bad_request"),
        (r#"not json"#.to_owned(), "bad_request"),
        (format!(r#"{{"op":"token","token":"{good}"}}"#), "bad_request"), // no build
        (format!(r#"{{"op":"token","token":"{good}","build":{{"release":"0.0.0+other"}}}}"#), "build"),
        (format!(r#"{{"op":"token","token":"x.y","build":{build}}}"#), "invalid_arg"),
        (
            format!(
                r#"{{"op":"token","token":"{}","build":{build}}}"#,
                jwt(&format!(r#"{{"exp":{},"scope":["{scope}"]}}"#, now() - 1))
            ),
            "invalid_arg",
        ), // expired
        (
            format!(
                r#"{{"op":"token","token":"{}","build":{build}}}"#,
                jwt(&format!(r#"{{"exp":{},"scope":"keymgmt:list"}}"#, now() + 600))
            ),
            "invalid_arg",
        ), // not the key's scope
    ];
    for (req, kind) in &cases {
        let r = ask(&mut c, req).await;
        assert!(!r.ok, "{req}: {r:?}");
        assert_eq!(r.kind.as_deref(), Some(*kind), "{req}: {r:?}");
    }
    // The build refusal names the agent's build.
    let r = ask(&mut c, &cases[4].0).await;
    assert_eq!(r.build, Some(Build::current()));

    // A well-formed token goes to the HEM (unreachable here) to check the keys: refused, still locked.
    let r = ask(&mut c, &format!(r#"{{"op":"token","token":"{good}","build":{build}}}"#)).await;
    assert!(!r.ok, "{r:?}");
    let r = ask(&mut c, r#"{"op":"lock"}"#).await;
    assert!(r.ok, "{r:?}");

    // A frame over the limit ends the connection.
    c.write_all(&((MAX_MESSAGE as u32) + 1).to_be_bytes()).await.unwrap();
    assert!(matches!(read_msg(&mut c).await, Ok(None) | Err(_)));

    // A new connection still works: one window's mistake is not the agent's.
    let mut c = connect(&address).await;
    write_msg(&mut c, &serde_json::json!({"op": "whoami"})).await.unwrap();
    assert!(matches!(next(&mut c).await, Msg::Reply { reply: Reply { ok: true, .. } }));
}
