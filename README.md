# hem-ssh-agent

An SSH agent whose keys live in an [Encedo HEM](https://encedo.com). Use a
non-exportable Ed25519 key for `ssh`, `git` over SSH and git commit signing,
with your usual clients: OpenSSH, Git, PuTTY / plink (Pageant).

Status: experiment; a first prototype works on Windows (Ed25519, password
login). See [docs/DESIGN.md](docs/DESIGN.md).

Built on [hem-sdk-rust](https://github.com/encedo/hem-sdk-rust).

## Try it

```bash
git clone --recurse-submodules https://github.com/encedo/hem-ssh-agent
cd hem-ssh-agent && cargo build --release
export HEM_URL=https://my.ence.do          # your HEM

hem-ssh-agent keys                         # Ed25519 keys in the HEM: kid + label
hem-ssh-agent pubkey --kid <kid>           # line for authorized_keys / GitHub
hem-ssh-agent run --kid <kid> [--ttl 300]  # asks for the HEM password once
```

`run` listens on the Windows OpenSSH pipe (`\\.\pipe\openssh-ssh-agent`; stop
the Windows `ssh-agent` service first) or, on Linux / macOS, on a socket it
prints as `export SSH_AUTH_SOCK=...`.

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
