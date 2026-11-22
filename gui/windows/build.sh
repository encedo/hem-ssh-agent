#!/usr/bin/env bash
# Builds the Windows bundle (Git Bash; cargo, go and a MinGW C compiler for the
# window's cgo - gcc on PATH, or CC: on arm64 an aarch64 one, e.g. llvm-mingw,
# and then CC_aarch64_pc_windows_msvc=clang (LLVM) for the agent's ring, or
# cc-rs takes CC too):
# dist/hem-ssh-agent-<version>-windows-<amd64|arm64>.zip with the agent, its
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

# amd64 or arm64 - the architecture rustc builds for here, named as Go names
# it (not uname: Git Bash may be an x64 program on an arm64 machine). No cross
# build: run this on the kind of machine the bundle is for (ARCH, when set,
# must agree).
host=$(rustc -vV | sed -n 's/^host: //p')
case "$host" in
x86_64-*) arch=amd64 ;;
aarch64-*) arch=arm64 ;;
*) echo "no bundle for $host" >&2; exit 1 ;;
esac
if [ -n "${ARCH:-}" ] && [ "$ARCH" != "$arch" ]; then
	echo "ARCH=$ARCH, but this machine builds $arch ($host)" >&2
	exit 1
fi

echo "==> agent $build ($arch)"
HEM_SSH_AGENT_COMMIT="$commit" cargo build --release --manifest-path "$root/Cargo.toml"
echo "==> window $build ($arch)"
(cd "$root/gui" && CGO_ENABLED=1 GOARCH=$arch go build -trimpath -tags migrated_fynedo \
	-ldflags "-H=windowsgui -s -w -X main.version=$build" \
	-o "$root/target/release/hem-ssh-agent-gui.exe" .)

name="hem-ssh-agent-$version-windows-$arch"
stage="$root/target/dist/$name"
rm -rf "$stage"
mkdir -p "$stage"
cp "$root/target/release/hem-ssh-agent.exe" "$root/target/release/hem-ssh-agentw.exe" \
	"$root/target/release/hem-ssh-agent-gui.exe" "$stage/"
cp "$here/icon.ico" "$here/install.ps1" "$here/uninstall.ps1" "$stage/"
cp "$root/LICENSE" "$stage/LICENSE.txt"
sed -e "s/@BUILD@/$build/" -e "s/@ARCH@/$arch/" "$here/README.txt" > "$stage/README.txt"

zip_dir() { # zip_dir <stage dir> <zip>
	rm -f "$2"
	powershell.exe -NoProfile -Command \
		"Compress-Archive -Path '$(cygpath -w "$1")' -DestinationPath '$(cygpath -w "$2")'"
	echo "==> ${2#"$root"/}"
}
zip_dir "$stage" "$root/target/dist/$name.zip"

# The command line alone: the agent and its background twin, no window.
cli="hem-ssh-agent-cli-$version-windows-$arch"
cstage="$root/target/dist/$cli"
rm -rf "$cstage"
mkdir -p "$cstage"
cp "$root/target/release/hem-ssh-agent.exe" "$root/target/release/hem-ssh-agentw.exe" "$cstage/"
cp "$root/LICENSE" "$cstage/LICENSE.txt"
cp "$root/README.md" "$cstage/"
zip_dir "$cstage" "$root/target/dist/$cli.zip"
