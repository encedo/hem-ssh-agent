# hem-ssh-agent GUI

The tray window for hem-ssh-agent: Go + [Fyne](https://fyne.io), built on
encedo-wg-hsm's GUI (MIT, same author: the tray, the single-instance
doorbell, the pipe dial, the Encedo theme, the Linux tray and scale checks).
A separate process; the agent (Rust, `../src`) stays headless and is driven
over its control channel (`../src/control.rs`, `../docs/DESIGN.md`).

What it does:

- Starts the agent when it is not running (beside the window:
  `hem-ssh-agentw.exe` on Windows, `hem-ssh-agent` on unix, else from PATH),
  detached; `-no-start` turns that off, `-config` is passed on.
- Shows the agent's state in the tray menu: locked, ready (until when),
  waiting for the phone; or that the agent is not running (*Start the agent*).
- Notifies when the phone is asked to approve a token (with the note it
  shows) and how that ended: approved, refused, no answer.
- Password mode: *Unlock...* asks for the HEM password, logs in to the HEM
  itself (check-in first, then a token for every key the agent serves) and
  hands the agent only the token. By default the derived key is dropped at
  once; *Remember the password until Lock* keeps it in this window and hands
  over a fresh token before each expires, until Lock, `ssh-add -x` or Quit.
- *Lock*, *Show log*, *Quit*. Without a tray (GNOME without an extension)
  the window stays open and closing it quits.

Flags: `-control`, `-config`, `-no-start`, `-theme auto|dark|light`, `-version`.

## Build

Needs Go (1.26.5 or later) and a C compiler for cgo (Fyne uses OpenGL):
on Windows the MinGW-w64 gcc; Linux also the GL/X11 headers
(`libgl1-mesa-dev xorg-dev`). `-tags migrated_fynedo` tells Fyne every UI
call from another goroutine goes through `fyne.Do` (`FyneApp.toml` says the
same to `fyne package`).

```bash
git submodule update --init          # hem-sdk-go
cd gui
go build -trimpath -tags migrated_fynedo -ldflags "-H=windowsgui" -o ../target/gui/hem-ssh-agent-gui.exe .   # Windows
go build -trimpath -tags migrated_fynedo -o ../target/gui/hem-ssh-agent-gui .                                # Linux, macOS
go test .                                                       # offline
HEM_CONTROL=<control address> HEM_PASSWORD=... go test -run Live -v .   # against an agent in password mode
```

`version` in `ipc.go` must equal the agent's build (`Build::current` in
`../src/control.rs`, the crate version plus `HEM_SSH_AGENT_COMMIT` when
stamped): the agent refuses a token from a window of another build. The
bundle scripts stamp both with `<version>+<commit>`.

## Packaging

`windows/`, `linux/`, `macos/`: `build.sh` builds both halves stamped
alike and the bundle in `../target/dist/`; `install` / `uninstall`
scripts per user, autostart at logon included (`--no-autostart` on unix).
The icons come from encedo-wg-hsm (`icon.svg`, `icon.png`,
`windows/icon.ico`).
