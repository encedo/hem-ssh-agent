//! An SSH agent whose keys live in an Encedo HEM. See `docs/DESIGN.md`.
//!
//! `agent` is the platform-independent core (the agent protocol answered from
//! the HEM); `listen` is the only platform-specific part (named pipe on
//! Windows, unix socket elsewhere).

pub mod agent;
pub mod listen;

pub use agent::{key_scopes, load_key, AgentKey, HemAgent};
