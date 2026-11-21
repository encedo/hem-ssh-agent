//! The control channel: how the window (the GUI, `gui/`) talks to the agent.
//!
//! The same shape as encedo-wg-hsm `internal/ipc`, so both ends share one
//! vocabulary: a four-byte big-endian length and then JSON, at most 64 KiB,
//! over a named pipe (Windows) or a unix socket with the same access rules as
//! the agent's own (the current user and SYSTEM / mode 0600).
//!
//! What crosses is a scoped, expiring token and nothing else - never the
//! password, never the derived key. The window logs in to the HEM itself and
//! hands the agent the token; when it expires, new signs fail until the window
//! (or `ssh-add -X`) hands over another. `Request` refuses unknown fields, so
//! the rule holds even when a field would be convenient.
//!
//! Four operations: `whoami` (build and caller), `watch` (a snapshot of the
//! state now and on every change), `token` (use this token), `lock`.

use std::io;

use serde::{Deserialize, Serialize};
use ssh_agent_lib::agent::ListeningSocket;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

use crate::agent::HemAgent;
use crate::listen::Peer;

/// Bound of one framed message (as encedo-wg). A limit, not a target.
pub const MAX_MESSAGE: usize = 64 << 10;

/// What the window asks for. Strings on the wire, so a mismatched pair fails
/// legibly instead of doing the wrong thing.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    /// Which build the agent is and who it thinks the caller is. Changes nothing.
    Whoami,
    /// The state now, then again on every change, on this connection.
    Watch,
    /// Use this token for signing (password mode: the window logged in).
    Token,
    /// Drop the token (and the derived key of `ssh-add -X`).
    Lock,
}

/// Which artifact is speaking: a window and an agent from different builds
/// refuse to hand over a token.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Build {
    pub release: String,
}

impl Build {
    /// This build: the crate version, plus the commit when the build stamped
    /// one (`HEM_SSH_AGENT_COMMIT` at compile time).
    pub fn current() -> Self {
        let v = env!("CARGO_PKG_VERSION");
        Build {
            release: match option_env!("HEM_SSH_AGENT_COMMIT") {
                Some(c) if !c.is_empty() => format!("{v}+{c}"),
                _ => v.to_owned(),
            },
        }
    }
}

/// Everything the agent is ever told.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub op: Op,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<Build>,
    /// `op: token` only: a token with `keymgmt:use:<kid>` for every key the
    /// agent serves (the kids are in the `watch` snapshot).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl Request {
    /// Rejects a request the agent must not act on. Runs in the agent: the
    /// access list of the pipe / socket is the control, this is the check.
    pub fn validate(&self) -> Result<(), String> {
        match self.op {
            Op::Token => {
                if self.token.as_deref().unwrap_or("").is_empty() {
                    return Err("token needs a token".into());
                }
                if self.build.is_none() {
                    return Err("token needs to say which build is asking".into());
                }
            }
            Op::Whoami | Op::Watch | Op::Lock => {
                if self.token.is_some() {
                    return Err(format!("{:?} takes no token", self.op).to_lowercase());
                }
            }
        }
        Ok(())
    }
}

/// One thing the agent sent: an answer to a request or a state snapshot, in
/// the order they happened.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Msg {
    Reply { reply: Reply },
    Event { event: Status },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Reply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
    /// What sort of failure, for the window to choose a message: `bad_request`,
    /// `build`, or a hem-sdk error code (`auth_failed`, `invalid_arg`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The agent's build, on `whoami`, `watch` and a `build` refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<Build>,
    /// The caller as the platform reports it (`whoami`): a SID on Windows, a uid on unix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub who: Option<String>,
}

impl Reply {
    fn ok() -> Self {
        Reply { ok: true, ..Default::default() }
    }

    fn err(kind: &str, err: impl Into<String>) -> Self {
        Reply { ok: false, err: Some(err.into()), kind: Some(kind.to_owned()), ..Default::default() }
    }
}

/// What the window draws. A whole snapshot, never a delta: a late subscriber
/// cannot show a state that was never true.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// `locked` (password mode, no token and no derived key), `ready`, or
    /// `waiting` (a token is being approved on the phone).
    pub state: String,
    /// `password` or `remote` (the configuration's `auth`).
    pub auth: String,
    /// The HEM's address (the configuration's `url`): where the window logs in.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    /// Password mode: the token lifetime to ask for, in seconds (`ttl`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    pub keys: Vec<KeyInfo>,
    /// The current token's `exp` (unix seconds), read from the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// The approval the phone is showing now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
    /// The last sign request and how it ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<Last>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    pub kid: String,
    pub comment: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    /// The note shown on the phone (`src/note.rs`).
    pub note: String,
    /// Unix seconds.
    pub since: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Last {
    pub note: String,
    /// `signed`, `denied` (refused on the phone), `timeout` (no answer),
    /// `locked` (no token, password mode) or `failed`.
    pub result: String,
    /// Unix seconds.
    pub at: i64,
}

/// Frames a message. The length goes first so a reader knows where it ends.
pub async fn write_msg<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, v: &T) -> io::Result<()> {
    let b = serde_json::to_vec(v).map_err(io::Error::other)?;
    if b.len() > MAX_MESSAGE {
        return Err(io::Error::other(format!("message of {} bytes exceeds the limit", b.len())));
    }
    w.write_all(&(b.len() as u32).to_be_bytes()).await?;
    w.write_all(&b).await?;
    w.flush().await
}

/// Reads one framed message; `None` at a clean end of the stream. The length
/// is checked before anything is allocated.
pub async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut hdr = [0u8; 4];
    match r.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(hdr) as usize;
    if n > MAX_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("message of {n} bytes exceeds the limit")));
    }
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).await?;
    Ok(Some(b))
}

/// Serves windows until the listener fails. Each connection is independent.
pub async fn serve<L>(mut listener: L, agent: HemAgent) -> io::Result<()>
where
    L: ListeningSocket + Send,
    L::Stream: Peer,
{
    loop {
        let stream = listener.accept().await?;
        let who = stream.who();
        let agent = agent.clone();
        tokio::spawn(async move {
            log::info!("control: connected: {who}");
            if let Err(e) = connection(stream, &who, agent).await {
                log::warn!("control: {who}: {e}");
            }
            log::info!("control: closed: {who}");
        });
    }
}

/// One window. Requests are read in their own task (a framed read cancelled
/// half-way would lose bytes); replies and snapshots are written here, in order.
async fn connection<S: AsyncRead + AsyncWrite + Send + 'static>(stream: S, who: &str, agent: HemAgent) -> io::Result<()> {
    let (mut r, mut w) = tokio::io::split(stream);
    let (tx, mut requests) = mpsc::channel::<io::Result<Vec<u8>>>(4);
    let reader = tokio::spawn(async move {
        loop {
            let m = match read_msg(&mut r).await {
                Ok(Some(b)) => Ok(b),
                Ok(None) => break,
                Err(e) => Err(e),
            };
            let stop = m.is_err();
            if tx.send(m).await.is_err() || stop {
                break;
            }
        }
    });

    let mut events: Option<watch::Receiver<Status>> = None;
    let result = loop {
        enum Step {
            Request(Option<io::Result<Vec<u8>>>),
            Changed(bool),
        }
        let step = tokio::select! {
            m = requests.recv() => Step::Request(m),
            ok = changed(&mut events) => Step::Changed(ok),
        };
        match step {
            Step::Request(None) => break Ok(()),
            Step::Request(Some(Err(e))) => break Err(e),
            Step::Request(Some(Ok(b))) => {
                let (reply, watch) = handle(&b, who, &agent).await;
                write_msg(&mut w, &Msg::Reply { reply }).await?;
                if watch && events.is_none() {
                    let mut rx = agent.subscribe();
                    let snapshot = rx.borrow_and_update().clone();
                    write_msg(&mut w, &Msg::Event { event: snapshot }).await?;
                    events = Some(rx);
                }
            }
            Step::Changed(false) => break Ok(()), // the agent is gone
            Step::Changed(true) => {
                let snapshot = events.as_mut().expect("subscribed").borrow_and_update().clone();
                write_msg(&mut w, &Msg::Event { event: snapshot }).await?;
            }
        }
    };
    reader.abort();
    result
}

/// Waits for the next state change; never, when not subscribed.
async fn changed(events: &mut Option<watch::Receiver<Status>>) -> bool {
    match events {
        Some(rx) => rx.changed().await.is_ok(),
        None => std::future::pending().await,
    }
}

/// Answers one request; the flag says whether to start sending snapshots.
async fn handle(b: &[u8], who: &str, agent: &HemAgent) -> (Reply, bool) {
    let req: Request = match serde_json::from_slice(b) {
        Ok(r) => r,
        Err(e) => return (Reply::err("bad_request", format!("bad request: {e}")), false),
    };
    if let Err(e) = req.validate() {
        return (Reply::err("bad_request", e), false);
    }
    log::info!("control: {who}: {:?}", req.op);
    let current = Build::current();
    match req.op {
        Op::Whoami => (Reply { build: Some(current), who: Some(who.to_owned()), ..Reply::ok() }, false),
        Op::Watch => (Reply { build: Some(current), ..Reply::ok() }, true),
        Op::Lock => {
            agent.lock().await;
            (Reply::ok(), false)
        }
        Op::Token => {
            let theirs = req.build.unwrap_or_default();
            if theirs != current {
                let msg = format!("build mismatch: agent {}, window {}", current.release, theirs.release);
                log::warn!("control: {who}: {msg}");
                return (Reply { build: Some(current), ..Reply::err("build", msg) }, false);
            }
            match agent.accept_token(req.token.as_deref().unwrap_or("")).await {
                Ok(exp) => {
                    log::info!("control: {who}: token accepted, expires {exp}");
                    (Reply::ok(), false)
                }
                Err(e) => {
                    log::warn!("control: {who}: token refused: {} ({e})", e.code);
                    (Reply::err(&e.code, e.to_string()), false)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_shapes() {
        let r = Msg::Reply { reply: Reply { build: Some(Build { release: "0.1.0".into() }), ..Reply::ok() } };
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"type":"reply","reply":{"ok":true,"build":{"release":"0.1.0"}}}"#);
        let e = Msg::Event {
            event: Status {
                state: "locked".into(),
                auth: "password".into(),
                url: String::new(),
                ttl: None,
                keys: vec![KeyInfo { kid: "00".into(), comment: "c".into() }],
                expires_at: None,
                pending: None,
                last: None,
            },
        };
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"type":"event","event":{"state":"locked","auth":"password","keys":[{"kid":"00","comment":"c"}]}}"#
        );
        let q: Request = serde_json::from_str(r#"{"op":"token","build":{"release":"x"},"token":"t"}"#).unwrap();
        assert_eq!(q.op, Op::Token);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn requests_refused() {
        // Nothing but a token crosses: an extra field is not ignored.
        assert!(serde_json::from_str::<Request>(r#"{"op":"token","token":"t","password":"p"}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"op":"start"}"#).is_err());
        let no_build: Request = serde_json::from_str(r#"{"op":"token","token":"t"}"#).unwrap();
        assert!(no_build.validate().is_err());
        let empty: Request = serde_json::from_str(r#"{"op":"token","token":"","build":{"release":"x"}}"#).unwrap();
        assert!(empty.validate().is_err());
        let lock_tok: Request = serde_json::from_str(r#"{"op":"lock","token":"t"}"#).unwrap();
        assert!(lock_tok.validate().is_err());
    }

    #[tokio::test]
    async fn framing_round_trip_and_limit() {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        write_msg(&mut a, &Request { op: Op::Lock, build: None, token: None }).await.unwrap();
        let got = read_msg(&mut b).await.unwrap().unwrap();
        assert_eq!(got, br#"{"op":"lock"}"#);
        // A length over the limit is refused before the body is read.
        a.write_all(&((MAX_MESSAGE as u32) + 1).to_be_bytes()).await.unwrap();
        assert!(read_msg(&mut b).await.is_err());
        drop(a);
        assert!(read_msg(&mut b).await.unwrap().is_none());
    }
}
