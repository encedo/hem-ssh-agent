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
5. **GUI only if needed, reused, not new.** A password prompt or a sign
   approval window comes from what Encedo already has: onchato
   (encedo-chat, Tauri app `impl/src-tauri`) or encedo-wg. The agent itself
   stays a headless process.
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

## Configuration

`config.toml` in `%APPDATA%\hem-ssh-agent\` (Windows) or
`~/.config/hem-ssh-agent/` (Linux, macOS); `--config` overrides. Format in
`src/config.rs`: `url`, `auth`, `uv`, `ttl`, `approve_timeout`, `listen`, and `[[key]]` entries
with `kid` and `pubkey` (the line `hem-ssh-agent pubkey` prints). The public
key is in the file so the agent lists keys without a token: no phone prompt
just to list.

## Security notes

- Socket / pipe accessible to the current user only. Windows: the pipe's
  access list is `D:P(A;;GA;;;SY)(A;;GA;;;<user SID>)`, remote clients
  refused; checked with .NET `GetAccessControl` (2026-11-21). Unix: 0600
  socket in a 0700 directory.
- Agent forwarding (`ssh -A`) lets a remote host ask for signatures while the
  session lasts - document it; optional confirm-per-sign.
- The agent holds a derived key or a token in memory, never the password;
  zeroized on drop.
- Every signature is in the HEM audit log.

## Code layout

```
src/agent.rs    HemAgent: the agent protocol answered from the HEM, lock / unlock,
                password or phone tokens (no platform code)
src/note.rs     the note shown on the phone, read from the data to sign
src/config.rs   config.toml
src/listen.rs   transports: Windows named pipe (own listener with an access
                list, the only unsafe code) / unix socket - the only #[cfg] code
src/main.rs     CLI: keys, pubkey, run
tests/live.rs   end to end through the real transport and an agent client (HEM_URL)
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
2. Windows: autostart at logon without a console window (Task Scheduler,
   log to a file); Pageant transport (plink, PuTTY, TortoiseGit) with
   forwarding of other keys to the real Pageant / OpenSSH agent.
3. Linux: unix socket (`SSH_AUTH_SOCK`), then macOS.
4. Confirm-per-sign, packaging (signed binaries).

## Open

- Password mode: keep the derived key until `ssh-add -x` (now) or drop it
  with each token and ask again.
- A GUI prompt (onchato / encedo-wg) instead of `ssh-add -X`, if needed.
