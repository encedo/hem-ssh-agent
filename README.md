# hem-ssh-agent

An SSH agent whose keys live in an [Encedo HEM](https://encedo.com). Use a
non-exportable Ed25519 key for `ssh`, `git` over SSH and git commit signing,
with your usual clients: OpenSSH, Git, PuTTY / plink (Pageant).

Status: experiment; works on Windows and macOS (Ed25519): password unlock
through `ssh-add -X` or the tray window, or approval on the phone
(encedo-authenticator, biometrics). Linux: being tested.
See [docs/DESIGN.md](docs/DESIGN.md).

## Install

Bundles are built per platform by `gui/<platform>/build.sh` (the agent, the
tray window, installers); each installs for the current user, no
administrator / root, and starts the window at logon - the window starts
the agent:

- Windows: `install.ps1` (`%LOCALAPPDATA%\Programs\hem-ssh-agent`, Start
  menu, Run key); `uninstall.ps1`.
- Linux: `install.sh` (`~/.local`, menu entry, XDG autostart); `uninstall.sh`.
- macOS: `install.sh` (`~/Applications`, LaunchAgent); `uninstall.sh`.

The configuration (below) is made first; the installers never write it.

The tray window shows the agent's state and the phone's requests; in
password mode *Unlock...* logs in to the HEM and hands the agent a token.
*Remember the password until Lock* (off by default) keeps the key derived
from it in the window, which then renews the token by itself; off, unlock
again when the token expires.

Built on [hem-sdk-rust](https://github.com/encedo/hem-sdk-rust).

## Try it

```bash
git clone --recurse-submodules https://github.com/encedo/hem-ssh-agent
cd hem-ssh-agent && cargo build --release

hem-ssh-agent keys   --url https://my.ence.do            # Ed25519 keys: kid + label
hem-ssh-agent pubkey --url https://my.ence.do --kid <kid> # line for config / authorized_keys / GitHub
```

`config.toml` in `%APPDATA%\hem-ssh-agent\` (Windows) or
`~/.config/hem-ssh-agent/` (Linux, macOS):

```toml
url  = "https://my.ence.do"
auth = "remote"        # "password": unlock with `ssh-add -X`; "remote": approve on the phone
uv   = "bio"           # remote: "bio" | "pin" | "none"
ttl  = 300             # password: token lifetime, seconds
approve_timeout = 90   # remote: seconds to wait for the phone
pageant = false        # Windows: also serve PuTTY / plink / WinSCP (off while a Pageant runs)

[[key]]
kid    = "<kid>"
pubkey = "ssh-ed25519 AAAA... label"   # the pubkey output
```

```bash
hem-ssh-agent run      # password mode starts locked: ssh-add -X; ssh-add -x locks
```

Windows, start at logon without a console window (current user, no
administrator rights; `hem-ssh-agentw.exe` must sit next to `hem-ssh-agent.exe`):
the tray window `hem-ssh-agent-gui.exe` when it sits there too (it starts
the agent), else the agent itself (`--no-gui`):

```
hem-ssh-agent install --start     # log: %LOCALAPPDATA%\hem-ssh-agent\agent.log
hem-ssh-agent uninstall           # then: taskkill /IM hem-ssh-agent-gui.exe /IM hem-ssh-agentw.exe
```

PuTTY, plink, WinSCP, TortoiseGit: `pageant = true` makes the agent answer
as Pageant too - only while no Pageant runs; it never displaces one.

`run` listens on the Windows OpenSSH pipe (`\\.\pipe\openssh-ssh-agent`, for
the current user only; stop the Windows `ssh-agent` service first) or, on
Linux / macOS, on a socket it prints as `export SSH_AUTH_SOCK=...`.

Windows with Git: use the system OpenSSH, not Git's bundled one:

```
git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe
# commit signing
git config --global gpg.format ssh
git config --global gpg.ssh.program C:/Windows/System32/OpenSSH/ssh-keygen.exe
git config --global user.signingkey C:/path/to/key.pub   # the pubkey output
```

## Licence

MIT, see [LICENSE](LICENSE).
