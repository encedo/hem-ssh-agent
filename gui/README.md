# hem-ssh-agent GUI

The tray window for hem-ssh-agent: Go + [Fyne](https://fyne.io), built on
encedo-wg-hsm's GUI (MIT, same author). A separate process; the agent (Rust,
`../src`) stays headless and is driven over its control channel
(`../src/control.rs`, `../docs/DESIGN.md`).

What it does:

- Shows the agent's state in the tray menu: locked, ready (until when),
  waiting for the phone; or that the agent is not running.
- Notifies when the phone is asked to approve a token (with the note it
  shows) and how that ended: approved, refused, no answer.
- Password mode: *Unlock...* asks for the HEM password, logs in to the HEM
  itself (check-in first, then a token for every key the agent serves) and
  hands the agent only the token. The derived key is dropped at once; when
  the token expires the agent is locked again.
- *Lock*, *Show log*, *Quit*.

## Build

Needs Go (1.26.5 or later) and a C compiler for cgo (Fyne uses OpenGL):
on Windows the MinGW-w64 gcc.

```bash
git submodule update --init          # hem-sdk-go
cd gui
go build -trimpath -ldflags "-H=windowsgui" -o ../target/gui/hem-ssh-agent-gui.exe .   # Windows
go build -trimpath -o ../target/gui/hem-ssh-agent-gui .                                # Linux, macOS
```

`version` in `ipc.go` must equal the agent's build (`Build::current` in
`../src/control.rs`, the crate version plus `HEM_SSH_AGENT_COMMIT` when
stamped): the agent refuses a token from a window of another build.

Per-platform packaging (icons, installers, autostart entries) goes in
`windows/`, `linux/`, `macos/` when it is added.
