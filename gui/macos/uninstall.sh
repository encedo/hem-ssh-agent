#!/bin/sh
# Removes what install.sh put in place. The configuration
# (~/.config/hem-ssh-agent) and the log (~/.local/state/hem-ssh-agent) are
# kept; the keys are in the HEM and stay there.
set -eu

name="HEM SSH agent.app"
label=com.encedo.hem-ssh-agent
apps="$HOME/Applications"

launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
pkill -f "$apps/$name/Contents/MacOS/" 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/$label.plist"
rm -rf "$apps/$name"

echo "Removed. Kept: ~/.config/hem-ssh-agent (configuration), ~/.local/state/hem-ssh-agent (log)."
