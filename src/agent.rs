//! The agent protocol answered from the HEM. No platform code here.

use std::sync::Arc;

use async_trait::async_trait;
use hem_sdk::{AuthOptions, Hem, HemError, SignOptions};
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, PublicCredential, SignRequest};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{Algorithm, PublicKey, Signature};

/// One HEM key served by the agent: its kid and the public half, read at start.
#[derive(Clone, Debug)]
pub struct AgentKey {
    pub kid: String,
    pub public: KeyData,
    /// The key label on the HEM; the comment `ssh-add -l` shows.
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

/// The agent: one per process, cloned into every client connection.
///
/// Tokens come from `Hem::authorize_password(None, ..)`: the derived key kept
/// from the start-up login (`AuthOptions::remember`) mints a new token when
/// the cached one has expired, so the token lifetime can be short.
#[derive(Clone)]
pub struct HemAgent {
    hem: Arc<Hem>,
    keys: Arc<Vec<AgentKey>>,
    scopes: Arc<Vec<String>>,
    auth: AuthOptions,
}

impl HemAgent {
    /// `hem` must already hold the derived key (a password login with
    /// `remember`), `auth` is used for every token after that.
    pub fn new(hem: Arc<Hem>, keys: Vec<AgentKey>, auth: AuthOptions) -> Self {
        let scopes = key_scopes(&keys.iter().map(|k| k.kid.as_str()).collect::<Vec<_>>());
        Self { hem, keys: Arc::new(keys), scopes: Arc::new(scopes), auth }
    }

    pub fn keys(&self) -> &[AgentKey] {
        &self.keys
    }

    fn find(&self, credential: &PublicCredential) -> Option<&AgentKey> {
        let PublicCredential::Key(wanted) = credential else { return None };
        self.keys.iter().find(|k| &k.public == wanted)
    }
}

#[async_trait]
impl Session for HemAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
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
        let token = self
            .hem
            .authorize_password(None, self.scopes.to_vec(), self.auth.clone())
            .await
            .map_err(|e| failed(&key.kid, "token", e))?;
        let sig = self
            .hem
            .exdsa_sign(&token, &key.kid, &req.data, SignOptions::default())
            .await
            .map_err(|e| failed(&key.kid, "sign", e))?;
        log::info!("sign: {} ({}), {} bytes", key.kid, key.comment, req.data.len());
        Signature::new(Algorithm::Ed25519, sig).map_err(AgentError::other)
    }
}

fn failed(kid: &str, step: &str, e: HemError) -> AgentError {
    log::warn!("sign: {kid}: {step} failed: {} ({e})", e.code);
    AgentError::other(e)
}
