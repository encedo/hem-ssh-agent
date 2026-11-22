#!/bin/sh
# Installs hem-ssh-agent for the current user (no administrator):
#
#     ./install.sh [--no-autostart] [<directory holding "HEM SSH agent.app">]
#
# Copies the app to ~/Applications and adds a LaunchAgent
# (~/Library/LaunchAgents/com.encedo.hem-ssh-agent.plist) that starts the
# window at logon; the window starts the agent. The configuration
# (~/.config/hem-ssh-agent/config.toml) is never written here.
set -eu

autostart=1
if [ "${1:-}" = "--no-autostart" ]; then
	autostart=0
	shift
fi
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${1:-$here}
name="HEM SSH agent.app"
label=com.encedo.hem-ssh-agent
if [ ! -d "$src/$name" ]; then
	echo "$src/$name is missing (usage: $0 [--no-autostart] [<directory>])" >&2
	exit 2
fi

apps="$HOME/Applications"
plist="$HOME/Library/LaunchAgents/$label.plist"
gui="$apps/$name/Contents/MacOS/hem-ssh-agent-gui"

# A running copy holds the old files: stop it first.
launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
pkill -f "$apps/$name/Contents/MacOS/" 2>/dev/null || true

mkdir -p "$apps"
rm -rf "$apps/$name"
ditto "$src/$name" "$apps/$name"

if [ "$autostart" = 1 ]; then
	mkdir -p "$HOME/Library/LaunchAgents"
	cat > "$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$label</string>
	<key>ProgramArguments</key>
	<array>
		<string>$gui</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
EOF
	launchctl bootstrap "gui/$(id -u)" "$plist"
fi

cat <<EOF
Installed: $apps/$name$( [ "$autostart" = 1 ] && printf ' - starts at logon (%s), running now.' "$plist")

The command line is inside the app:
    ln -s "$apps/$name/Contents/MacOS/hem-ssh-agent" ~/.local/bin/hem-ssh-agent

Point ssh at the agent (macOS's own agent keeps SSH_AUTH_SOCK) - in ~/.ssh/config:
    Host *
        IdentityAgent ~/.hem-ssh-agent/hem-ssh-agent.sock
Git commit signing reads SSH_AUTH_SOCK: export SSH_AUTH_SOCK=~/.hem-ssh-agent/hem-ssh-agent.sock

The configuration: ~/.config/hem-ssh-agent/config.toml (README.md).
EOF
