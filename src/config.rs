//! The configuration file (TOML).
//!
//! Windows: `%APPDATA%\hem-ssh-agent\config.toml`;
//! Linux / macOS: `$XDG_CONFIG_HOME/hem-ssh-agent/config.toml` or
//! `~/.config/hem-ssh-agent/config.toml`.
//!
//! ```toml
//! url  = "https://my.ence.do"
//! auth = "remote"        # "password" (default) | "remote" | "remote+password"
//! uv   = "bio"           # remote: "bio" (default) | "pin" | "none"
//! ttl  = 300             # password: token lifetime in seconds
//! approve_timeout = 90   # remote: seconds to wait for the phone
//! # listen = '\\.\pipe\openssh-ssh-agent'
//! # control = '\\.\pipe\hem-ssh-agent-control'   # the GUI's channel
//! # pageant = true       # Windows: also serve PuTTY / plink / WinSCP as Pageant
//!
//! [[key]]
//! kid    = "9904cd6be703202a186dd8a2d1bfdb74"
//! pubkey = "ssh-ed25519 AAAA... label"   # the output of `hem-ssh-agent pubkey`
//! ```

use std::path::{Path, PathBuf};

use serde::Deserialize;
use ssh_key::public::KeyData;
use ssh_key::PublicKey;

use crate::agent::AgentKey;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// The HEM password, given once (`ssh-add -X` or `run --login`).
    #[default]
    Password,
    /// The paired phone (encedo-authenticator) approves each token.
    Remote,
    /// The phone first; the HEM password when the phone is not at hand: "Use
    /// password" while the phone is asked (the window), or `ssh-add -X` /
    /// `run --login` beforehand (until Lock).
    #[serde(rename = "remote+password")]
    RemotePassword,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UvSetting {
    #[default]
    Bio,
    Pin,
    None,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    pub kid: String,
    pub pubkey: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub url: String,
    #[serde(default)]
    pub auth: AuthMode,
    #[serde(default)]
    pub uv: UvSetting,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    /// Remote: how long to wait for the phone, in seconds (sshd waits 120 s
    /// for a login by default).
    #[serde(default = "default_approve_timeout")]
    pub approve_timeout: u32,
    #[serde(default)]
    pub listen: Option<String>,
    /// The control channel (`src/control.rs`); default `listen::default_control_address`.
    #[serde(default)]
    pub control: Option<String>,
    /// Windows: also answer as Pageant, for PuTTY, plink, WinSCP
    /// (`src/pageant.rs`); off while a Pageant runs.
    #[serde(default)]
    pub pageant: bool,
    #[serde(default, rename = "key")]
    pub keys: Vec<KeyConfig>,
}

fn default_ttl() -> u32 {
    300
}

fn default_approve_timeout() -> u32 {
    90
}

/// Where the configuration file is looked for.
pub fn default_path() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(unix)]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    base.map(|b| b.join("hem-ssh-agent").join("config.toml"))
}

pub fn load(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

impl KeyConfig {
    /// The key as the agent serves it. Only `ssh-ed25519` for now; the kid
    /// must be 32 hex characters. The comment is the one in the line.
    pub fn agent_key(&self) -> Result<AgentKey, String> {
        if self.kid.len() != 32 || !self.kid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("key {}: kid is 32 hex characters", self.kid));
        }
        let pk = PublicKey::from_openssh(self.pubkey.trim()).map_err(|e| format!("key {}: pubkey: {e}", self.kid))?;
        if !matches!(pk.key_data(), KeyData::Ed25519(_)) {
            return Err(format!("key {}: only ssh-ed25519 is supported", self.kid));
        }
        Ok(AgentKey { kid: self.kid.to_lowercase(), public: pk.key_data().clone(), comment: pk.comment().to_owned() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGpF0XlEga7eszVIQwwt1RrxFbEeAunDtECC1opkDvPV hem-ssh-agent live test";

    #[test]
    fn parses_example() {
        let c: Config = toml::from_str(&format!(
            "url = \"https://x\"\nauth = \"remote\"\n[[key]]\nkid = \"9904cd6be703202a186dd8a2d1bfdb74\"\npubkey = \"{LINE}\"\n"
        ))
        .unwrap();
        assert_eq!(c.auth, AuthMode::Remote);
        assert_eq!(c.uv, UvSetting::Bio);
        assert_eq!(c.ttl, 300);
        assert_eq!(c.approve_timeout, 90);
        let k = c.keys[0].agent_key().unwrap();
        assert_eq!(k.comment, "hem-ssh-agent live test");
        assert_eq!(k.openssh(), LINE);
    }

    #[test]
    fn refuses_bad_keys() {
        let bad_kid = KeyConfig { kid: "xyz".into(), pubkey: LINE.into() };
        assert!(bad_kid.agent_key().is_err());
        let bad_line = KeyConfig { kid: "9904cd6be703202a186dd8a2d1bfdb74".into(), pubkey: "ssh-ed25519 !!".into() };
        assert!(bad_line.agent_key().is_err());
        assert!(toml::from_str::<Config>("url = \"x\"\nauth = \"telepathy\"").is_err());
        let both: Config = toml::from_str("url = \"x\"\nauth = \"remote+password\"").unwrap();
        assert_eq!(both.auth, AuthMode::RemotePassword);
    }
}
