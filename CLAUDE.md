# CLAUDE.md - hem-ssh-agent

Instructions for AI agents working in this repository. Design decisions:
[docs/DESIGN.md](docs/DESIGN.md) - read it first.

## Ground rules

- **Everything that talks to the HEM lives in hem-sdk-rust** (submodule
  `hem-sdk-rust/`), not here. A missing SDK call is added there, following
  its own `CLAUDE.md`, committed there, and the moved submodule pointer is
  committed here. Never work around the SDK in this repo.
- **Never invent payloads or formats.** The SSH side: the agent protocol
  (draft-ietf-sshm-ssh-agent), RFC 4253 / RFC 8709 key and signature
  formats, OpenSSH PROTOCOL.sshsig. The HEM side: the firmware API reference
  (`encedo_firmware/docs/HEM_API_reference_1.3.x.md`) and hem-sdk-js.
- **Commits:** no `Co-Authored-By` or any other AI attribution trailer.
  Author `Krzysztof Rutecki <krzysztof@encedo.com>` (pass it with
  `-c user.name/-c user.email`; the global identity on the dev machine is a
  placeholder).
- **Push only on the owner's explicit go.** The owner usually pushes.
- Keep platform code in the transport layer; the rest builds and tests on
  Windows, Linux and macOS.

## Build and test

```bash
git submodule update --init
cargo build
cargo test                                   # offline
HEM_URL=https://ssh-agent-tester.playground.ence.do HEM_PASSWORD=... cargo test --test live
cargo clippy --all-targets -- -D warnings
```

Windows (GNU toolchain): `~/.cargo/bin` and `C:\mingw64\bin` must be on PATH.

## Test device

`https://ssh-agent-tester.playground.ence.do` - a HEM simulator for this
project. Not a secret; it is here temporarily. Initialised as hem-api-tester
T-2 does: the user passphrase is the tester's (`config.php`). The live test
key (description `hem-ssh-agent-test`, label "hem-ssh-agent live test") is
created on the first run and reused.

Test machines: Windows (the development machine), Linux in a VM on macOS,
macOS.
