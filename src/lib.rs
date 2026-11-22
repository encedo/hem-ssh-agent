//! An SSH agent whose keys live in an Encedo HEM. See `docs/DESIGN.md`.
//!
//! `agent` is the platform-independent core (the agent protocol answered from
//! the HEM, lock / unlock, password or phone approval); `listen` is the only
//! platform-specific part (named pipe on Windows, unix socket elsewhere);
//! `control` is the channel the GUI drives the agent through.

pub mod agent;
pub mod app;
pub mod config;
pub mod control;
pub mod listen;
pub mod note;
#[cfg(windows)]
pub mod pageant;

pub use agent::{key_scopes, load_key, AgentKey, Auth, HemAgent};
