//! hem-ssh-agent: the console executable (keys, pubkey, run, install, uninstall).

fn main() -> std::process::ExitCode {
    hem_ssh_agent::app::main_console()
}
