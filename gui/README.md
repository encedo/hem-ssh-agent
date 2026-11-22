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
- `auth = "remote+password"`: the phone first; while it is asked the tray
  menu offers *Use password*, which stops asking the phone and opens the
  Unlock window - the waiting `ssh` / `git` sign takes the token it hands
  over; closing the window ends that sign unsigned. *Unlock...* also works
  beforehand, while there is no token.
- *Lock*, *Show log*, *Quit*. Without a tray (GNOME without an extension)
  the window stays open and closing it quits.

Flags: `-control`, `-config`, `-no-start`, `-theme auto|dark|light`, `-version`.

Linux (tested on Ubuntu 24.04 GNOME, Wayland session):

- The window runs on X11 - XWayland under Wayland - whenever `DISPLAY` is
  set (`FYNE_PLATFORM=x11`, as Fyne itself does on GNOME). On native Wayland
  (`FYNE_PLATFORM=wayland`, or a session without XWayland) a window cannot
  centre or raise itself without an xdg-activation token, which a tray click
  does not carry: *Unlock...* may open behind other windows, anywhere
  (GNOME: `gsettings set org.gnome.mutter center-new-windows true` at least
  centres it). The display-scale correction (`scale_linux.go`) is skipped
  there: the compositor scales.
- With GNOME's *Do Not Disturb* on, the phone-approval notification is not
  shown as a banner: the request is in the tray menu (*Waiting for a phone*)
  and in the notification list.

## Build

Needs Go (1.26.5 or later) and a C compiler for cgo (Fyne uses OpenGL):
on Windows the MinGW-w64 gcc; Linux also the GL, X11 and Wayland headers -
GLFW builds both backends into one binary and picks one at run time
(Debian/Ubuntu: `libgl1-mesa-dev xorg-dev libxxf86vm-dev libwayland-dev
libxkbcommon-dev wayland-protocols`, the list CI installs; without the
Wayland ones: `wayland-client-core.h: No such file`). `-tags migrated_fynedo` tells Fyne every UI
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
