# hem-ssh-agent

An SSH agent whose keys live in an [Encedo HEM](https://encedo.com). Use a
non-exportable Ed25519 key for `ssh`, `git` over SSH and git commit signing,
with your usual clients: OpenSSH, Git, PuTTY / plink (Pageant).

Status: experiment, nothing to install yet. See [docs/DESIGN.md](docs/DESIGN.md).

Built on [hem-sdk-rust](https://github.com/encedo/hem-sdk-rust).

## Licence

MIT, see [LICENSE](LICENSE).
