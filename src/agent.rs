//! The agent protocol answered from the HEM. No platform code here.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use hem_sdk::{jwt_parse, AuthOptions, Hem, HemError, RemoteOptions, Scope, SignOptions, Uv};
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, PublicCredential, SignRequest};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{Algorithm, PublicKey, Signature};
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::control::{KeyInfo, Last, Pending, Status};
use crate::note::{computer_name, note};

/// One HEM key served by the agent: its kid and the public half.
#[derive(Clone, Debug)]
pub struct AgentKey {
    pub kid: String,
    pub public: KeyData,
    /// The comment `ssh-add -l` shows (the HEM label, or the config line's).
    pub comment: String,
}

impl AgentKey {
    /// The key as an OpenSSH public key line (`authorized_keys`, GitHub, `allowed_signers`).
    pub fn openssh(&self) -> String {
        PublicKey::new(self.public.clone(), &self.comment)
            .to_openssh()
            .expect("an Ed25519 public key always encodes")
    }
}

/// The token scopes the agent needs for its keys: one `keymgmt:use:<kid>` each.
/// One token carries them all (the device takes up to 8 scopes).
pub fn key_scopes<S: AsRef<str>>(kids: &[S]) -> Vec<String> {
    kids.iter().map(|k| format!("keymgmt:use:{}", k.as_ref())).collect()
}

/// Reads a key's public half from the HEM. Only Ed25519 for now.
///
/// `token` needs `keymgmt:use:<kid>` (or `keymgmt:get`).
pub async fn load_key(hem: &Hem, token: &str, kid: &str) -> hem_sdk::Result<AgentKey> {
    let info = hem.get_key_public_info(token, kid).await?;
    if info.key_type != "ED25519" {
        return Err(HemError::new(
            "invalid_arg",
            format!("key {kid} is {}; only ED25519 is supported", info.key_type),
        ));
    }
    let pk: [u8; 32] = info
        .pubkey
        .and_then(|p| p.try_into().ok())
        .ok_or_else(|| HemError::new("bad_response", format!("key {kid}: no 32-byte public key")))?;
    Ok(AgentKey { kid: kid.to_owned(), public: KeyData::Ed25519(Ed25519PublicKey(pk)), comment: info.label })
}

/// How the agent gets its tokens.
#[derive(Clone, Debug)]
pub enum Auth {
    /// The HEM password, given once to unlock (`ssh-add -X`, or `run --login`).
    /// The derived key is kept until `ssh-add -x`, and mints a token of
    /// `ttl` seconds whenever the last one has expired.
    Password { ttl: u32 },
    /// The paired phone approves each token (lifetime = the phone's answer).
    /// No password on this computer. `timeout`: how long to wait for the phone.
    Remote { uv: Option<Uv>, timeout: std::time::Duration },
}

#[derive(Default)]
struct State {
    /// Password mode: the derived key is in `Hem`.
    unlocked: bool,
    /// The last token and its `exp`: reused while valid, so a sign within the
    /// lifetime needs no check-in, no device login and no phone.
    token: Option<(String, i64)>,
    /// Kids whose configured public key was compared with the HEM's.
    verified: HashSet<String>,
    /// The approval the phone is showing now (for the GUI).
    pending: Option<Pending>,
    /// The last sign request and how it ended (for the GUI).
    last: Option<Last>,
}

impl State {
    fn token_valid(&self) -> bool {
        self.token.as_ref().is_some_and(|(_, exp)| *exp > now() + 5)
    }
}

/// The agent: one per process, cloned into every client connection.
#[derive(Clone)]
pub struct HemAgent {
    hem: Arc<Hem>,
    keys: Arc<Vec<AgentKey>>,
    scopes: Arc<Vec<String>>,
    auth: Auth,
    /// Also serialises getting a token, so parallel signs ask the phone once.
    state: Arc<tokio::sync::Mutex<State>>,
    computer: Option<String>,
    /// The state as the control channel shows it (`watch`).
    status: watch::Sender<Status>,
    /// The HEM's address, shown to the window (`with_url`).
    url: Arc<str>,
}

impl HemAgent {
    /// Starts locked in password mode (no keys listed until unlocked).
    pub fn new(hem: Arc<Hem>, keys: Vec<AgentKey>, auth: Auth) -> Self {
        let scopes = key_scopes(&keys.iter().map(|k| k.kid.as_str()).collect::<Vec<_>>());
        let (status, _) = watch::channel(Status {
            state: String::new(),
            auth: String::new(),
            url: String::new(),
            ttl: None,
            keys: Vec::new(),
            expires_at: None,
            pending: None,
            last: None,
        });
        let agent = Self {
            hem,
            keys: Arc::new(keys),
            scopes: Arc::new(scopes),
            auth,
            state: Arc::default(),
            computer: computer_name(),
            status,
            url: Arc::from(""),
        };
        agent.publish(&State::default());
        agent
    }

    /// The HEM's address the window logs in to (the configuration's `url`;
    /// `Hem` does not expose the one it was made with).
    pub fn with_url(mut self, url: &str) -> Self {
        self.url = Arc::from(url);
        self.publish(&State::default());
        self
    }

    pub fn keys(&self) -> &[AgentKey] {
        &self.keys
    }

    /// The state now and on every change (the control channel's `watch`).
    pub fn subscribe(&self) -> watch::Receiver<Status> {
        self.status.subscribe()
    }

    fn password_mode(&self) -> bool {
        matches!(self.auth, Auth::Password { .. })
    }

    fn snapshot(&self, st: &State) -> Status {
        let state = if st.pending.is_some() {
            "waiting"
        } else if self.password_mode() && !st.unlocked && !st.token_valid() {
            "locked"
        } else {
            "ready"
        };
        let now = now();
        Status {
            state: state.into(),
            auth: if self.password_mode() { "password" } else { "remote" }.into(),
            url: self.url.to_string(),
            ttl: match self.auth {
                Auth::Password { ttl } => Some(ttl),
                Auth::Remote { .. } => None,
            },
            keys: self.keys.iter().map(|k| KeyInfo { kid: k.kid.clone(), comment: k.comment.clone() }).collect(),
            expires_at: st.token.as_ref().map(|(_, exp)| *exp).filter(|exp| *exp > now),
            pending: st.pending.clone(),
            last: st.last.clone(),
        }
    }

    /// Tells the control channel, when something it shows has changed.
    fn publish(&self, st: &State) {
        let next = self.snapshot(st);
        self.status.send_if_modified(|s| {
            let changed = *s != next;
            if changed {
                *s = next;
            }
            changed
        });
    }

    /// Shows the state again once the token is no longer used (5 s before
    /// its `exp`, as the cache): nothing else happens at that moment.
    fn publish_at_expiry(&self, exp: i64) {
        let me = self.clone();
        let wait = (exp - 5 - now()).max(0) as u64 + 1;
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
            let st = me.state.lock().await;
            me.publish(&st);
        });
    }

    /// The control channel's `token`: a token the window got itself (the
    /// window logged in to the HEM; only the token crosses). It must not have
    /// expired, must hold `keymgmt:use:<kid>` for every key served, and the
    /// HEM must accept it (the configured public keys are checked with it,
    /// once per key). Returns its `exp`.
    pub async fn accept_token(&self, token: &str) -> hem_sdk::Result<i64> {
        let payload = jwt_parse(token).ok_or_else(|| HemError::new("invalid_arg", "not a token"))?;
        let exp = payload
            .get("exp")
            .and_then(|e| e.as_i64())
            .ok_or_else(|| HemError::new("invalid_arg", "the token has no exp"))?;
        if exp <= now() + 5 {
            return Err(HemError::new("invalid_arg", "the token has expired"));
        }
        let granted: Scope = payload
            .get("scope")
            .cloned()
            .and_then(|s| serde_json::from_value(s).ok())
            .ok_or_else(|| HemError::new("invalid_arg", "the token has no scope"))?;
        let granted = granted.values();
        if let Some(missing) = self.scopes.iter().find(|s| !granted.contains(&s.as_str())) {
            return Err(HemError::new("invalid_arg", format!("the token does not hold {missing}")));
        }
        let mut st = self.state.lock().await;
        self.verify_keys(&mut st, token).await?;
        st.token = Some((token.to_owned(), exp));
        self.publish(&st);
        drop(st);
        self.publish_at_expiry(exp);
        Ok(exp)
    }

    /// Password mode: log in to the HEM and keep the derived key.
    pub async fn unlock_with_password(&self, password: &str) -> hem_sdk::Result<()> {
        let Auth::Password { ttl } = self.auth else {
            return Err(HemError::new("invalid_arg", "unlock: the agent is in remote mode"));
        };
        let mut st = self.state.lock().await;
        self.hem.clear_keys();
        self.hem.clear_cache();
        st.token = None;
        if let Err(e) = self.hem.hem_checkin().await {
            log::warn!("check-in failed, logging in without it: {} ({e})", e.code);
        }
        let opts = AuthOptions { exp_seconds: ttl, remember: true, ctx: None };
        let token = self.hem.authorize_password(Some(password), self.scopes.to_vec(), opts).await?;
        if let Err(e) = self.verify_keys(&mut st, &token).await {
            self.hem.clear_keys();
            return Err(e);
        }
        st.unlocked = true;
        let exp = jwt_parse(&token).and_then(|p| p.get("exp").and_then(|e| e.as_i64())).unwrap_or(0);
        st.token = Some((token, exp));
        self.publish(&st);
        log::info!("unlocked");
        Ok(())
    }

    /// Drop the derived key and every token: the next sign needs the password
    /// (password mode) or a new approval on the phone (remote mode).
    pub async fn lock(&self) {
        let mut st = self.state.lock().await;
        st.unlocked = false;
        st.token = None;
        self.hem.clear_keys();
        self.hem.clear_cache();
        self.publish(&st);
        log::info!("locked");
    }

    /// Password mode with neither the derived key (`ssh-add -X`) nor a valid
    /// token (from the window): no keys listed, as a locked OpenSSH agent.
    async fn locked(&self) -> bool {
        if !self.password_mode() {
            return false;
        }
        let st = self.state.lock().await;
        !st.unlocked && !st.token_valid()
    }

    fn find(&self, credential: &PublicCredential) -> Option<&AgentKey> {
        let PublicCredential::Key(wanted) = credential else { return None };
        self.keys.iter().find(|k| &k.public == wanted)
    }

    /// A token for every key scope: cached, or minted from the kept key, or
    /// approved on the phone (with `note` shown there).
    ///
    /// Every new token is preceded by a check-in, which also sets the HEM
    /// clock: required in remote mode (the broker is needed anyway), tried in
    /// password mode (a HEM behind an air gap still works without it).
    async fn token(&self, note: String) -> hem_sdk::Result<String> {
        let mut st = self.state.lock().await;
        if st.token_valid() {
            return Ok(st.token.as_ref().expect("valid").0.clone());
        }
        let token = match &self.auth {
            Auth::Password { ttl } => {
                if !st.unlocked {
                    return Err(HemError::new("auth_password_required", "agent locked: ssh-add -X or the window"));
                }
                if let Err(e) = self.hem.hem_checkin().await {
                    log::warn!("check-in failed, logging in without it: {} ({e})", e.code);
                }
                let opts = AuthOptions { exp_seconds: *ttl, remember: true, ctx: None };
                self.hem.authorize_password(None, self.scopes.to_vec(), opts).await?
            }
            Auth::Remote { uv, timeout } => {
                st.pending = Some(Pending { note: note.clone(), since: now() });
                self.publish(&st);
                let approved = async {
                    self.hem.hem_checkin().await?;
                    let opts =
                        RemoteOptions { require: *uv, note: Some(note), poll_timeout: *timeout, ..Default::default() };
                    self.hem.authorize_remote(self.scopes.to_vec(), opts).await
                }
                .await;
                st.pending = None; // published with the sign's result
                approved?
            }
        };
        self.verify_keys(&mut st, &token).await?;
        let exp = jwt_parse(&token).and_then(|p| p.get("exp").and_then(|e| e.as_i64())).unwrap_or(0);
        st.token = Some((token.clone(), exp));
        drop(st);
        self.publish_at_expiry(exp);
        Ok(token)
    }

    /// Records how a sign ended, for the control channel.
    async fn record(&self, what: &str, result: &str) {
        let mut st = self.state.lock().await;
        st.last = Some(Last { note: what.to_owned(), result: result.to_owned(), at: now() });
        self.publish(&st);
    }

    /// Once per key: the configured public key must be the HEM's, or the
    /// agent would offer servers a key it cannot sign for.
    async fn verify_keys(&self, st: &mut State, token: &str) -> hem_sdk::Result<()> {
        for k in self.keys.iter() {
            if st.verified.contains(&k.kid) {
                continue;
            }
            let hem_key = load_key(&self.hem, token, &k.kid).await?;
            if hem_key.public != k.public {
                return Err(HemError::new(
                    "invalid_arg",
                    format!("key {}: the configured public key is not the HEM's", k.kid),
                ));
            }
            st.verified.insert(k.kid.clone());
        }
        Ok(())
    }
}

#[async_trait]
impl Session for HemAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        if self.locked().await {
            return Ok(Vec::new()); // as a locked OpenSSH agent
        }
        Ok(self
            .keys
            .iter()
            .map(|k| Identity { credential: PublicCredential::Key(k.public.clone()), comment: k.comment.clone() })
            .collect())
    }

    async fn sign(&mut self, req: SignRequest) -> Result<Signature, AgentError> {
        let Some(key) = self.find(&req.credential) else {
            log::info!("sign: key not served by this agent");
            return Err(AgentError::Failure);
        };
        let what = note(&req.data, &key.comment, self.computer.as_deref());
        log::info!("sign: {} - {what}", key.kid);
        let token = match self.token(what.clone()).await {
            Ok(t) => t,
            Err(e) => {
                self.record(&what, outcome(&e)).await;
                return Err(failed(&key.kid, "token", e));
            }
        };
        let sig = match self.hem.exdsa_sign(&token, &key.kid, &req.data, SignOptions::default()).await {
            Ok(s) => s,
            Err(e) => {
                self.record(&what, "failed").await;
                return Err(failed(&key.kid, "sign", e));
            }
        };
        log::info!("sign: {} done, {} bytes", key.kid, req.data.len());
        self.record(&what, "signed").await;
        Signature::new(Algorithm::Ed25519, sig).map_err(AgentError::other)
    }

    /// `ssh-add -x`. The lock passphrase is not used: unlocking needs the
    /// HEM password (password mode) or the phone (remote mode) anyway.
    async fn lock(&mut self, _passphrase: String) -> Result<(), AgentError> {
        HemAgent::lock(self).await;
        Ok(())
    }

    /// `ssh-add -X`: the passphrase is the HEM password (password mode).
    async fn unlock(&mut self, passphrase: String) -> Result<(), AgentError> {
        let passphrase = Zeroizing::new(passphrase);
        match self.auth {
            Auth::Password { .. } => self.unlock_with_password(&passphrase).await.map_err(|e| {
                log::warn!("unlock failed: {} ({e})", e.code);
                AgentError::Failure
            }),
            Auth::Remote { .. } => Ok(()), // nothing to unlock: the phone approves
        }
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// `Last::result` for a token that could not be had.
fn outcome(e: &HemError) -> &'static str {
    match e.code.as_str() {
        "denied" => "denied",
        "timeout" => "timeout",
        "auth_password_required" => "locked",
        _ => "failed",
    }
}

fn failed(kid: &str, step: &str, e: HemError) -> AgentError {
    log::warn!("sign: {kid}: {step} failed: {} ({e})", e.code);
    AgentError::other(e)
}
