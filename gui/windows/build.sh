#!/usr/bin/env bash
# Builds the Windows bundle (Git Bash, GNU toolchain: cargo, go, MinGW gcc on
# PATH): dist/hem-ssh-agent-<version>-windows-amd64.zip with the agent, its
# background twin, the window, the icon and install.ps1 / uninstall.ps1.
#
# Both halves are stamped with the same build (<version>+<commit>): the agent
# refuses a token from a window of another build (src/control.rs).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
version=$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)
gui_version=$(sed -n 's/^var version = "\(.*\)"/\1/p' "$root/gui/ipc.go")
if [ "$version" != "$gui_version" ]; then
	echo "Cargo.toml says $version, gui/ipc.go says $gui_version" >&2
	exit 1
fi
commit=$(git -C "$root" rev-parse --short HEAD)
if [ -n "$(git -C "$root" status --porcelain --untracked-files=no)" ]; then
	commit="$commit-dirty"
fi
build="$version+$commit"

echo "==> agent $build"
HEM_SSH_AGENT_COMMIT="$commit" cargo build --release --manifest-path "$root/Cargo.toml"
echo "==> window $build"
(cd "$root/gui" && go build -trimpath -tags migrated_fynedo \
	-ldflags "-H=windowsgui -s -w -X main.version=$build" \
	-o "$root/target/release/hem-ssh-agent-gui.exe" .)

name="hem-ssh-agent-$version-windows-amd64"
stage="$root/target/dist/$name"
rm -rf "$stage"
mkdir -p "$stage"
cp "$root/target/release/hem-ssh-agent.exe" "$root/target/release/hem-ssh-agentw.exe" \
	"$root/target/release/hem-ssh-agent-gui.exe" "$stage/"
cp "$here/icon.ico" "$here/install.ps1" "$here/uninstall.ps1" "$stage/"
cp "$root/LICENSE" "$stage/LICENSE.txt"
sed "s/@BUILD@/$build/" "$here/README.txt" > "$stage/README.txt"

zip_dir() { # zip_dir <stage dir> <zip>
	rm -f "$2"
	powershell.exe -NoProfile -Command \
		"Compress-Archive -Path '$(cygpath -w "$1")' -DestinationPath '$(cygpath -w "$2")'"
	echo "==> ${2#"$root"/}"
}
zip_dir "$stage" "$root/target/dist/$name.zip"

# The command line alone: the agent and its background twin, no window.
cli="hem-ssh-agent-cli-$version-windows-amd64"
cstage="$root/target/dist/$cli"
rm -rf "$cstage"
mkdir -p "$cstage"
cp "$root/target/release/hem-ssh-agent.exe" "$root/target/release/hem-ssh-agentw.exe" "$cstage/"
cp "$root/LICENSE" "$cstage/LICENSE.txt"
cp "$root/README.md" "$cstage/"
zip_dir "$cstage" "$root/target/dist/$cli.zip"
