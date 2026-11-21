//! An SSH agent whose keys live in an Encedo HEM. See `docs/DESIGN.md`.
//!
//! `agent` is the platform-independent core (the agent protocol answered from
//! the HEM, lock / unlock, password or phone approval); `listen` is the only
//! platform-specific part (named pipe on Windows, unix socket elsewhere).

pub mod agent;
pub mod app;
pub mod config;
pub mod listen;
pub mod note;

pub use agent::{key_scopes, load_key, AgentKey, Auth, HemAgent};
