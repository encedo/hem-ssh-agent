# hem-ssh-agent - design

Status: experiment, started 2026-11-21. Design decisions and open questions.

## Goal

Developers use SSH keys that live in an Encedo HEM for `ssh`, `git` over SSH
and git commit signing, with every existing client unchanged. The private key
never leaves the HEM; the agent only forwards signing requests.

## Decisions

1. **An SSH agent**, not a PKCS#11 module or an SSH wrapper. One process holds
   the HEM session; every client that speaks to an agent works: OpenSSH `ssh`,
   `scp`, `git`, `ssh-keygen -Y sign` (commit signing), VS Code Remote,
   PuTTY / plink / WinSCP / TortoiseGit through Pageant.
2. **PKCS#11 is a separate, independent path** (the HEM PKCS#11 library, after
   firmware 1.3 testing). The agent does not depend on it.
3. **Rust**, on [hem-sdk-rust](https://github.com/encedo/hem-sdk-rust), taken
   as a git submodule (`hem-sdk-rust/`). Everything that talks to the HEM goes
   in the SDK, not here; this repo holds the agent protocol, the platform
   transports and the configuration.
4. **Three platforms**: Windows, Linux, macOS, with as much common code as
   possible: only the transport layer (and, if one is needed, the prompt) is
   platform-specific. Development and first tests on the Windows machine,
   then Linux (a VM on macOS), then macOS.
5. **GUI reused, not new: encedo-wg-hsm's** (Go + Fyne; decided
   2026-11-21 over onchato's Tauri). A separate process in `gui/`; the agent
   stays headless and gets a control channel (below).
6. **Key type first: Ed25519** (`ssh-ed25519`). The HEM signs pure Ed25519
   (`POST /api/crypto/exdsa/sign`, `alg: "Ed25519"`, RFC 8032), exactly what
   SSH needs. ECDSA P-256 (`ecdsa-sha2-nistp256`) later: the HEM signs a
   digest with `alg: "ECDSA"` and returns `r || s`, which SSH wraps as two mpints.
7. **MIT licence.**

## How it works

```
ssh / git / ssh-keygen / plink
        |  ssh-agent protocol (draft-ietf-sshm-ssh-agent)
        v
hem-ssh-agent  --- transport: unix socket | Windows named pipe | Pageant
        |  hem-sdk-rust (HTTPS, JSON)
        v
HEM: GET  /api/keymgmt/get/<kid>      public key        (scope keymgmt:use:<kid>)
     POST /api/crypto/exdsa/sign      signature         (scope keymgmt:use:<kid>)
```

Agent protocol messages handled:

| Request | Answer |
|---|---|
| `REQUEST_IDENTITIES` (11) | `IDENTITIES_ANSWER` (12): the configured HEM keys, public keys cached at login |
| `SIGN_REQUEST` (13) | `SIGN_RESPONSE` (14): `string "ssh-ed25519"` + `string sig(64)` |
| anything else (add / remove / lock / extensions) | `FAILURE` (5) - keys are managed on the HEM, not through the agent |

Size: an SSH user-auth blob is a few hundred bytes and `ssh-keygen -Y sign`
signs an SSHSIG structure holding a hash of the message, so the HEM's
2048-byte `msg` limit is never reached.

## Authorisation and tokens

Every sign needs a token with scope `keymgmt:use:<kid>` (role M is refused).
Two ways to get one, both from hem-sdk-rust:

- **Password** (`auth = "password"`, `authorize_password`): the agent starts
  **locked** (no keys listed, as a locked OpenSSH agent). `ssh-add -X` sends
  the HEM password over the agent socket / pipe (OpenSSH's own prompt, no UI
  of ours); the agent keeps the derived X25519 key (not the password) and
  mints a token of `ttl` seconds whenever the last one has expired.
  `ssh-add -x` drops the derived key and the token (the lock passphrase is
  not used). `run --login` asks on the terminal instead. Works air-gapped.
- **Phone approval** (`auth = "remote"`, `authorize_remote`, broker +
  encedo-authenticator): no password on the computer. When a sign needs a
  new token the phone shows a note and asks for biometrics (`uv=bio`, or
  `pin`); the token lifetime is the phone's answer (1 h seen), so the phone
  asks once per token, not per sign. `ssh-add -x` drops the token. The
  agent waits `approve_timeout` seconds (default 90; hem-sdk-js 60 s was
  too short in tests - approvals took 20-44 s and two ran out); sshd's
  default `LoginGraceTime` is 120 s.

The note is read from the data to sign, nothing invented (`src/note.rs`):
an SSH user-auth request (RFC 4252 section 7) gives
`ssh login as <user> · <key label> · <computer>`, an SSHSIG (PROTOCOL.sshsig)
`sign (<namespace>) · ...`, e.g. `sign (git)`, anything else `sign · ...`.
The server's host name is not in the signed data, so it cannot be shown.

One token carries the scopes of all configured keys (up to 8 keys).
The agent keeps the last token while it is valid: a sign within its lifetime
needs no check-in, no login and no phone. Parallel signs wait for one token,
so the phone asks once.

**Check-in before every new token** (`hem_checkin`, it also sets the HEM
clock): required in remote mode, tried in password mode and skipped with a
warning when the broker is unreachable (air gap).

On the first token the agent compares each configured public key with the
HEM's and refuses to sign on a mismatch.

## Control channel (the GUI)

The GUI (`gui/`, Go + Fyne, from encedo-wg-hsm) is a separate process; the
agent stays headless and is driven over a second pipe / socket
(`src/control.rs`): `\\.\pipe\hem-ssh-agent-control` (Windows, the same
access list as the agent's pipe) or `hem-ssh-agent-control.sock` next to the
agent's socket (unix, 0600); `control` in `config.toml` or `run --control`
overrides it. The framing and message shape are encedo-wg-hsm
`internal/ipc`'s: a four-byte big-endian length, then JSON, at most 64 KiB.

| Request | Answer |
|---|---|
| `{"op":"whoami"}` | `reply` with `build` and `who` (the caller's SID and pid on Windows, uid and pid on unix) |
| `{"op":"watch"}` | `reply`, then an `event` snapshot now and on every change |
| `{"op":"token","build":{...},"token":"..."}` | `reply` ok, or `kind` `build` / `invalid_arg` / a hem-sdk code |
| `{"op":"lock"}` | `reply`; drops the token and the derived key |

The snapshot (`Status`): `state` (`locked` / `ready` / `waiting` for the
phone), `auth`, `url` (the HEM the window logs in to), `ttl` (password
mode: the lifetime to ask for), `keys` (kid, comment), `expires_at` (unix seconds, read from
the token), `pending` (the note on the phone and since when), `last` (the
last sign's note, `signed` / `denied` / `timeout` / `locked` / `failed`, and
when). A whole snapshot every time, never a delta.

**Only the token crosses.** The window logs in to the HEM itself (password,
via hem-sdk-go, check-in first) and hands over a token holding
`keymgmt:use:<kid>` for every served key; the agent checks `exp`, the
scopes and, through the HEM, the configured public keys. No password and no
derived key are ever sent (`Request` refuses unknown fields). When the token
expires, new signs fail until the window - or `ssh-add -X` - gives another;
the agent has nothing to renew it with. A window from a different build is
refused a `token` (`build` names both).

**Remember the password** (a check box in the window, off by default, the
person's choice, kept as a preference): the window then keeps the key
derived from the password - never the password - in its own memory and
hands the agent a fresh token (check-in, no token cache) a fifth of the
lifetime before each expires (10 s .. 1 min), at once after an agent
restart. It forgets the key on Lock (tray or window), on a lock before the
token ran out (`ssh-add -x`), when the HEM asks for the password again, and
on Quit. Still only tokens cross the channel.

**The window starts the agent.** When the control channel does not answer
at its start, the window runs the agent beside it (`hem-ssh-agentw.exe run`
on Windows, `hem-ssh-agent run --log-file ...` on unix; `-config` is passed
on), detached, so the agent outlives the window; later a tray item does it
again. `-no-start` turns it off. `install` (Windows) puts the window in the
Run key when it sits next to `hem-ssh-agent.exe`, else the agent; Linux
and macOS log on through `gui/linux` (XDG autostart) and `gui/macos`
(LaunchAgent).

## Pageant (Windows)

`pageant = true` in `config.toml` also answers PuTTY, plink, WinSCP and
TortoiseGit (`src/pageant.rs`): a hidden top-level window of class and
title `Pageant`, `WM_COPYDATA` with a file mapping, exactly as PuTTY 0.85's
client and server do (windows/agent-client.c, windows/pageant.c): the
mapping must be owned by this user's SID or by the owner of the agent's
process, a length beyond the mapping is answered `FAILURE` unread, the
request is copied out before it is parsed. PuTTY 0.75+ tries Pageant's
named pipe first and falls back to the window, so the window serves old
and new clients. **It stays off while a Pageant runs** (logged): two
windows of that name and neither is reliably found, and the person's
Pageant is never displaced. Forwarding other keys to a running Pageant is
not done.

## Configuration

`config.toml` in `%APPDATA%\hem-ssh-agent\` (Windows) or
`~/.config/hem-ssh-agent/` (Linux, macOS); `--config` overrides. Format in
`src/config.rs`: `url`, `auth`, `uv`, `ttl`, `approve_timeout`, `listen`,
`control`, `pageant`, and `[[key]]` entries
with `kid` and `pubkey` (the line `hem-ssh-agent pubkey` prints). The public
key is in the file so the agent lists keys without a token: no phone prompt
just to list.

## Security notes

- Socket / pipe accessible to the current user only. Windows: the pipe's
  access list is `D:P(A;;GA;;;SY)(A;;GA;;;<user SID>)`, remote clients
  refused; checked with .NET `GetAccessControl` (2026-11-21). Unix: 0600
  socket in a 0700 directory, created 0600 (umask 0177 around bind), removed
  on Ctrl-C, SIGTERM and SIGHUP.
- The log names keys, users and hosts: on Linux / macOS the file is 0600 and
  a directory it creates 0700. ssh-agent-lib's debug and trace records (every
  request, the `ssh-add -X` password and the data to sign among them) are
  dropped whatever `RUST_LOG` says (found on the Linux test, 2026-11-22).
- Agent forwarding (`ssh -A`) lets a remote host ask for signatures while the
  session lasts - document it; optional confirm-per-sign.
- The agent holds a derived key or a token in memory, never the password;
  zeroized on drop. The window holds a derived key only while "Remember the
  password" is on (above).
- Pageant: any process on the desktop can send the window a message; only
  a mapping owned by this user is answered (PuTTY's check).
- Every signature is in the HEM audit log.

## Code layout

```
src/agent.rs    HemAgent: the agent protocol answered from the HEM, lock / unlock,
                password or phone tokens (no platform code)
src/note.rs     the note shown on the phone, read from the data to sign
src/config.rs   config.toml
src/control.rs  the GUI's control channel: framing, requests, snapshots
src/listen.rs   transports: Windows named pipe (own listener with an access
                list, the caller's SID) / unix socket
src/pageant.rs  Windows: the Pageant window (WM_COPYDATA + file mapping)
                - listen.rs and pageant.rs hold the unsafe and #[cfg] code
src/app.rs      CLI: keys, pubkey, run, install, uninstall; logging
src/main.rs     hem-ssh-agent.exe (console)
src/bin/hem-ssh-agentw.rs   hem-ssh-agentw.exe (Windows, no console: run in the background)
tests/live.rs   end to end through the real transport and an agent client (HEM_URL)
tests/control.rs  the control channel through the real transport, offline
tests/pageant.rs  the Pageant window as PuTTY's client calls it, offline
gui/            the GUI (Go + Fyne); hem-sdk-go as a submodule
gui/windows/    build.sh (zip), install.ps1 / uninstall.ps1 (per user), icon
gui/linux/      build.sh (tar.gz), install.sh / uninstall.sh (~/.local, XDG autostart)
gui/macos/      build.sh (.app, ad hoc signed), install.sh / uninstall.sh (LaunchAgent)
.github/workflows/  ci.yml (every push: ASCII check + build.yml with bundles uploaded),
                build.yml (linux, macos, windows x amd64, arm64 - on runners of
                that kind, macOS amd64 cross-built on arm64: clippy, tests,
                gui vet/test, gui/<platform>/build.sh); Windows signing to come
```

Agent protocol: `ssh-agent-lib` 0.6 (MIT/Apache-2.0; framing, messages,
named pipe and unix socket listeners). Messages not implemented in
`HemAgent` answer `FAILURE`, as the library does by default.

## Windows findings (prototype, 2026-11-21)

Tested against the HEM simulator with Windows OpenSSH 8.1p1 and Git for
Windows 2.56 (bundled OpenSSH 10.5p1):

- `ssh-add -L` / `-l` list the HEM key; `ssh.exe` logs in to a macOS sshd
  with it; a sign after the token expired minted a new token silently.
- `ssh-keygen -Y sign` (8.1) signs with the key from the agent; both 8.1 and
  10.5 verify the SSHSIG.
- Git commit signing works with
  `gpg.format=ssh`, `user.signingkey=<file with the public key line>`,
  `gpg.ssh.program=C:/Windows/System32/OpenSSH/ssh-keygen.exe`.
  Verifying (`git log --show-signature`) needs a newer `ssh-keygen`: 8.1
  rejects the `verify-time` option git passes; Git's bundled one works.
- Git's bundled `ssh.exe` (msys) does not use the named pipe (it reads
  `SSH_AUTH_SOCK`); for `git` over SSH set
  `core.sshCommand=C:/Windows/System32/OpenSSH/ssh.exe`.
- The Windows `ssh-agent` service must be stopped (it owns the same pipe);
  `run` fails with a clear message when the pipe is taken.
- Phone approval (encedo-authenticator 2.0.0-dev.19, Android, `uv=bio`):
  `ssh` to the macOS host waited for the approval (about 20 s) and logged in;
  a second `ssh` within the token lifetime did not ask the phone. A refusal
  on the phone (`denied`), or no answer in 60 s, makes the agent refuse the
  sign: `ssh` reports "agent refused operation" and is not logged in. The
  token's `actx` carried `uvm: bio`.

## Plan

1. Windows, development machine: CLI `pubkey` (authorized_keys line), then
   the agent on the OpenSSH named pipe `\\.\pipe\openssh-ssh-agent`; test with
   Windows `ssh.exe`, `git push`, commit signing. **Prototype done** (above);
   `git push` to a real remote not tried yet.
   Then: config file, start locked + `ssh-add -X`, phone approval, pipe
   access list - **done** (2026-11-21).
2. Windows: autostart at logon without a console window - **done**
   (2026-11-21): `hem-ssh-agentw.exe` (GUI subsystem, `run` only, log to
   `%LOCALAPPDATA%\hem-ssh-agent\agent.log`, moved to `.old` over 1 MB);
   `install [--start]` / `uninstall` set the `hem-ssh-agent` value under
   `HKCU\...\CurrentVersion\Run` (per user, no administrator rights - a
   Task Scheduler logon trigger usually needs them) and warn when the
   Windows OpenSSH agent service can run. A second instance exits with a
   log line (pipe taken).
3. The GUI, control channel, "remember the password", the window starting
   the agent and at logon, packaging per platform, Pageant - **done**
   (2026-11-22; Pageant stays off beside a running Pageant).
4. Linux: unix socket (`SSH_AUTH_SOCK`), then macOS. macOS checked
   2026-11-22 (CLI, ssh, SSHSIG, git signing, the GUI's live test).
5. Confirm-per-sign, signed binaries (Authenticode, Developer ID).

## Open

- Pageant beside a running Pageant: forward the other keys to it, or the
  named pipe (`\\.\pipe\pageant.<user>.<hash>`) - not done.
- The control address in `config.toml` must also be given to the window
  (`-control`): the window does not read the agent's file.
