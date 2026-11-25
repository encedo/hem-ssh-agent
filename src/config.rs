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
//!
//! `url` and `[[key]]` fix the HEM and the keys. Either may be left out: the
//! window then lets the person enter the address and pick keys from the
//! HEM's list, and writes that choice to `chosen.toml` beside this file (same
//! `url` / `[[key]]` shape), which the agent reads at start and on the
//! control channel's `reload`. What this file names always wins.

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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    pub kid: String,
    pub pubkey: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The HEM, `https://` only (DEV-532: the agent refuses plain http).
    /// Absent: the window's choice (`chosen.toml`).
    #[serde(default)]
    pub url: Option<String>,
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

impl Default for Config {
    /// No configuration file: password mode, the HEM and keys from the window.
    fn default() -> Self {
        toml::from_str("").expect("every field has a default")
    }
}

/// The window's choice of HEM and keys, for what the configuration leaves
/// open. The window writes it; the agent only reads it.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chosen {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default, rename = "key")]
    pub keys: Vec<KeyConfig>,
}

/// `chosen.toml` beside the configuration file.
pub fn chosen_path(config: &Path) -> PathBuf {
    config.with_file_name("chosen.toml")
}

/// The window's choice; none made yet when the file is not there.
pub fn load_chosen(path: &Path) -> Result<Chosen, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Chosen::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// What the agent serves: the configuration first, the window's choice for
/// what it leaves open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Merged {
    pub url: Option<String>,
    pub keys: Vec<KeyConfig>,
    pub url_fixed: bool,
    pub keys_fixed: bool,
}

/// The chosen keys count only with the address they were picked from: an
/// address the configuration fixed later, or a new one typed in the window,
/// leaves no keys until they are picked again.
pub fn merge(cfg: &Config, chosen: &Chosen) -> Merged {
    let url_fixed = cfg.url.is_some();
    let keys_fixed = !cfg.keys.is_empty();
    let url = cfg.url.clone().or_else(|| chosen.url.clone());
    let keys = if keys_fixed {
        cfg.keys.clone()
    } else if chosen.url.is_some() && chosen.url == url {
        chosen.keys.clone()
    } else {
        Vec::new()
    };
    Merged { url, keys, url_fixed, keys_fixed }
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

    #[test]
    fn the_configuration_wins_over_the_choice() {
        let key = |kid: &str| KeyConfig { kid: kid.into(), pubkey: LINE.into() };
        let chosen = Chosen { url: Some("https://a".into()), keys: vec![key("c")] };
        // Nothing in the file: the window's choice.
        let m = merge(&Config::default(), &chosen);
        assert_eq!((m.url.as_deref(), m.keys.clone(), m.url_fixed, m.keys_fixed), (Some("https://a"), vec![key("c")], false, false));
        // The file fixes the same address: the chosen keys stay.
        let same = Config { url: Some("https://a".into()), ..Config::default() };
        assert_eq!(merge(&same, &chosen).keys, vec![key("c")]);
        // Another address in the file: keys picked on the old one do not count.
        let other = Config { url: Some("https://b".into()), ..Config::default() };
        let m = merge(&other, &chosen);
        assert_eq!((m.url.as_deref(), m.keys.is_empty(), m.url_fixed), (Some("https://b"), true, true));
        // Keys in the file: those, whatever was chosen.
        let fixed = Config { keys: vec![key("f")], ..Config::default() };
        let m = merge(&fixed, &chosen);
        assert_eq!((m.keys.clone(), m.keys_fixed, m.url.as_deref()), (vec![key("f")], true, Some("https://a")));
        // Nothing chosen, nothing configured.
        let m = merge(&Config::default(), &Chosen::default());
        assert_eq!((m.url, m.keys.len()), (None, 0));
        assert!(toml::from_str::<Chosen>("url = \"x\"\nauth = \"remote\"").is_err());
    }
}
