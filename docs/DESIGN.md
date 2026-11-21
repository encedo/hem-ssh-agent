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

- **Password** (`authorize_password`): asked once at login; the agent keeps
  the derived X25519 key (not the password) for the session and mints
  short-lived tokens as they expire. Works offline / air-gapped.
- **Phone approval** (`authorize_remote`, broker + encedo-authenticator): no
  password on the computer; the phone shows a note such as
  `ssh: git@gitlab.com` and can require biometrics (`uv=bio`). Approval per
  token, so the token lifetime sets how often the phone asks.

One token can carry up to 8 scopes, so all configured keys share one token.

Tokens are short-lived on purpose (`run --ttl`, default 300 s). Prototype
(v0.1): the password is asked once at `run`, the derived key is kept
(`AuthOptions::remember`), and a new token is minted on the first sign after
expiry, without asking again. Whether a session should instead end with the
token (ask again: terminal, `ssh-add -X` unlock, or the phone) is open.

## Configuration (planned)

A TOML file in the platform config directory: HEM URL, keys (by kid or by a
label prefix), auth mode, token lifetime, confirm-per-sign. The HEM URL may
come from the environment for tests.

## Security notes

- Socket / pipe accessible to the current user only.
- Agent forwarding (`ssh -A`) lets a remote host ask for signatures while the
  session lasts - document it; optional confirm-per-sign.
- The agent holds a derived key or a token in memory, never the password;
  zeroized on drop.
- Every signature is in the HEM audit log.

## Code layout

```
src/agent.rs    HemAgent: the agent protocol answered from the HEM (no platform code)
src/listen.rs   transports: Windows named pipe / unix socket (the only #[cfg] code)
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

## Plan

1. Windows, development machine: CLI `pubkey` (authorized_keys line), then
   the agent on the OpenSSH named pipe `\\.\pipe\openssh-ssh-agent`; test with
   Windows `ssh.exe`, `git push`, commit signing. **Prototype done** (above);
   `git push` to a real remote not tried yet.
2. Pageant transport (plink, PuTTY, TortoiseGit).
3. Linux: unix socket (`SSH_AUTH_SOCK`), then macOS.
4. Phone approval, confirm-per-sign, config file, packaging (signed binaries).

## Open

- How the background agent asks for the password: a terminal `login`
  command talking to the running agent, `ssh-add -X` (agent unlock carries a
  passphrase), or a prompt reused from onchato / encedo-wg (decision 5).
- Token expiry: keep the derived key and refresh silently (prototype) or end
  the session with the token and ask again (see Authorisation and tokens).
- Named pipe access list: the prototype uses the tokio default (remote
  clients refused, default DACL); restrict it to the current user.
