#!/bin/sh
# Removes what install.sh put in place (same PREFIX). The configuration
# (~/.config/hem-ssh-agent) and the log (~/.local/state/hem-ssh-agent) are
# kept; the keys are in the HEM and stay there.
set -eu

PREFIX=${PREFIX:-$HOME/.local}

# Only the installed copies.
pkill -x -f "$PREFIX/bin/hem-ssh-agent-gui.*" 2>/dev/null || true
pkill -f "^$PREFIX/bin/hem-ssh-agent( |$)" 2>/dev/null || true

rm -f "$PREFIX/bin/hem-ssh-agent" "$PREFIX/bin/hem-ssh-agent-gui" \
	"$PREFIX/share/icons/hicolor/scalable/apps/hem-ssh-agent.svg" \
	"$PREFIX/share/applications/hem-ssh-agent.desktop" \
	"${XDG_CONFIG_HOME:-$HOME/.config}/autostart/hem-ssh-agent.desktop"
update-desktop-database "$PREFIX/share/applications" 2>/dev/null || true

echo "Removed. Kept: ~/.config/hem-ssh-agent (configuration), ~/.local/state/hem-ssh-agent (log)."
