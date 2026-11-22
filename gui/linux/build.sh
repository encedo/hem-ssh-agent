#!/bin/sh
# Builds the Linux bundle: target/dist/hem-ssh-agent-<version>-linux-<amd64|arm64>.tar.gz
# with both programs, the menu entry, the icon and install.sh / uninstall.sh.
# Needs cargo, go, gcc and the GL/X11 headers Fyne builds against
# (Debian/Ubuntu: libgl1-mesa-dev xorg-dev).
#
# Both halves are stamped with the same build (<version>+<commit>): the agent
# refuses a token from a window of another build (src/control.rs).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
version=$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)
gui_version=$(sed -n 's/^var version = "\(.*\)"/\1/p' "$root/gui/ipc.go")
if [ "$version" != "$gui_version" ]; then
	echo "Cargo.toml says $version, gui/ipc.go says $gui_version" >&2
	exit 1
fi
commit=$(git -C "$root" rev-parse --short HEAD)
[ -z "$(git -C "$root" status --porcelain --untracked-files=no)" ] || commit="$commit-dirty"
build="$version+$commit"

# amd64 or arm64 - the architecture rustc builds for here, named as Go names
# it, so the bundles of every platform are named alike. No cross build: run
# this on the kind of machine the bundle is for (ARCH, when set, must agree).
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
	-ldflags "-s -w -X main.version=$build" -o "$root/target/release/hem-ssh-agent-gui" .)

name="hem-ssh-agent-$version-linux-$arch"
stage="$root/target/dist/$name"
rm -rf "$stage"
mkdir -p "$stage"
cp "$root/target/release/hem-ssh-agent" "$root/target/release/hem-ssh-agent-gui" "$stage/"
cp "$here/install.sh" "$here/uninstall.sh" "$here/hem-ssh-agent.desktop" "$root/gui/icon.svg" \
	"$root/README.md" "$root/LICENSE" "$stage/"
tar -C "$root/target/dist" -czf "$root/target/dist/$name.tar.gz" "$name"
echo "==> target/dist/$name.tar.gz"

# The command line alone, no window.
cli="hem-ssh-agent-cli-$version-linux-$arch"
rm -rf "$root/target/dist/$cli"
mkdir -p "$root/target/dist/$cli"
cp "$root/target/release/hem-ssh-agent" "$root/README.md" "$root/LICENSE" "$root/target/dist/$cli/"
tar -C "$root/target/dist" -czf "$root/target/dist/$cli.tar.gz" "$cli"
echo "==> target/dist/$cli.tar.gz"
