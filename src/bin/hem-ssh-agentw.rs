//! hem-ssh-agentw: the agent in the background, without a console window
//! (Windows GUI subsystem); `run` only, logging to
//! %LOCALAPPDATA%\hem-ssh-agent\agent.log. Started at logon by
//! `hem-ssh-agent install`.

#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() -> std::process::ExitCode {
    hem_ssh_agent::app::main_background()
}
