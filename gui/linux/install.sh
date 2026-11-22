#!/bin/sh
# Installs hem-ssh-agent for the current user (no root):
#
#     ./install.sh [--no-autostart] [<directory with hem-ssh-agent and hem-ssh-agent-gui>]
#
# The programs go to ~/.local/bin, the icon and the menu entry under
# ~/.local/share, and an autostart entry to ~/.config/autostart: logging on
# starts the window, the window starts the agent. PREFIX=/usr/local with sudo
# installs the programs and the menu entry for everybody (autostart stays
# per user). The configuration (~/.config/hem-ssh-agent/config.toml) is never
# written here.
set -eu

autostart=1
if [ "${1:-}" = "--no-autostart" ]; then
	autostart=0
	shift
fi
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
bin=${1:-$here}
PREFIX=${PREFIX:-$HOME/.local}

for f in hem-ssh-agent hem-ssh-agent-gui; do
	if [ ! -f "$bin/$f" ]; then
		echo "$bin/$f is missing (usage: $0 [--no-autostart] [<directory with the programs>])" >&2
		exit 2
	fi
done
icon="$here/icon.svg"
[ -f "$icon" ] || icon="$here/../icon.svg"

# A running copy of the window is replaced at the next start; the agent
# keeps running from memory until it is stopped.
install -Dm755 "$bin/hem-ssh-agent" "$PREFIX/bin/hem-ssh-agent"
install -Dm755 "$bin/hem-ssh-agent-gui" "$PREFIX/bin/hem-ssh-agent-gui"
install -Dm644 "$icon" "$PREFIX/share/icons/hicolor/scalable/apps/hem-ssh-agent.svg"

# Full path in Exec: ~/.local/bin is not on PATH on every desktop.
install -d "$PREFIX/share/applications"
sed "s|^Exec=.*|Exec=$PREFIX/bin/hem-ssh-agent-gui|" "$here/hem-ssh-agent.desktop" \
	> "$PREFIX/share/applications/hem-ssh-agent.desktop"
chmod 644 "$PREFIX/share/applications/hem-ssh-agent.desktop"

if [ "$autostart" = 1 ]; then
	auto="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"
	install -d "$auto"
	cp "$PREFIX/share/applications/hem-ssh-agent.desktop" "$auto/hem-ssh-agent.desktop"
	echo "X-GNOME-Autostart-enabled=true" >> "$auto/hem-ssh-agent.desktop"
fi

# Advisory caches; not every system has them.
update-desktop-database "$PREFIX/share/applications" 2>/dev/null || true
gtk-update-icon-cache -f -t "$PREFIX/share/icons/hicolor" 2>/dev/null || true

# Where the agent listens (src/listen.rs runtime_dir).
if [ -n "${XDG_RUNTIME_DIR:-}" ]; then sock=$XDG_RUNTIME_DIR; else sock=$HOME/.hem-ssh-agent; fi
cat <<EOF
Installed to $PREFIX.$( [ "$autostart" = 1 ] && printf ' Starts at logon (%s).' "$auto/hem-ssh-agent.desktop")

Point ssh at the agent - in ~/.ssh/config:
    Host *
        IdentityAgent $sock/hem-ssh-agent.sock
or for every program (git signing too), in ~/.profile:
    export SSH_AUTH_SOCK=$sock/hem-ssh-agent.sock

The configuration: ~/.config/hem-ssh-agent/config.toml (README.md).
Start now: $PREFIX/bin/hem-ssh-agent-gui &
GNOME without a tray extension shows the window instead of a tray icon.
EOF
