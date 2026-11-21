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

## Plan

1. Windows, development machine: CLI `pubkey` (authorized_keys line), then
   the agent on the OpenSSH named pipe `\\.\pipe\openssh-ssh-agent`; test with
   Windows `ssh.exe`, `git push`, commit signing.
2. Pageant transport (plink, PuTTY, TortoiseGit).
3. Linux: unix socket (`SSH_AUTH_SOCK`), then macOS.
4. Phone approval, confirm-per-sign, config file, packaging (signed binaries).

## Open

- Agent-protocol library: `ssh-agent-lib` (unix socket and Windows named pipe)
  or a small own implementation of the four messages. To decide on the first
  prototype.
- How the background agent asks for the password: a terminal `login`
  command talking to the running agent, or a prompt reused from onchato /
  encedo-wg (decision 5).
- Coexistence with a running OpenSSH agent service on Windows (same pipe name).
