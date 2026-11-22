#!/bin/sh
# Builds the macOS bundle (Xcode command line tools, cargo, go):
# target/dist/hem-ssh-agent-<version>-macos-<arch>.zip holding
# "HEM SSH agent.app" (the window and the agent in Contents/MacOS: the window
# starts the agent beside it) and install.sh / uninstall.sh.
#
# Both halves are stamped with the same build (<version>+<commit>): the agent
# refuses a token from a window of another build (src/control.rs). The app is
# signed ad hoc only; a copy made on another Mac needs a Developer ID
# signature and notarisation, or `xattr -dr com.apple.quarantine`.
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
arch=$(uname -m)

echo "==> agent $build"
HEM_SSH_AGENT_COMMIT="$commit" cargo build --release --manifest-path "$root/Cargo.toml"
echo "==> window $build"
(cd "$root/gui" && go build -trimpath -tags migrated_fynedo \
	-ldflags "-s -w -X main.version=$build" -o "$root/target/release/hem-ssh-agent-gui" .)

name="hem-ssh-agent-$version-macos-$arch"
stage="$root/target/dist/$name"
app="$stage/HEM SSH agent.app"
rm -rf "$stage"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$root/target/release/hem-ssh-agent-gui" "$root/target/release/hem-ssh-agent" "$app/Contents/MacOS/"
sed -e "s/@VERSION@/$version/" -e "s/@BUILD@/$build/" "$here/Info.plist.in" > "$app/Contents/Info.plist"

# icon.icns from the 1024 px icon.
iconset="$root/target/dist/icon.iconset"
rm -rf "$iconset"
mkdir -p "$iconset"
for s in 16 32 128 256 512; do
	sips -z $s $s "$root/gui/icon.png" --out "$iconset/icon_${s}x${s}.png" >/dev/null
	sips -z $((s * 2)) $((s * 2)) "$root/gui/icon.png" --out "$iconset/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/icon.icns"
rm -rf "$iconset"

codesign --force --deep --sign - "$app"

cp "$here/install.sh" "$here/uninstall.sh" "$root/README.md" "$root/LICENSE" "$stage/"
rm -f "$root/target/dist/$name.zip"
(cd "$root/target/dist" && ditto -c -k --keepParent "$name" "$name.zip")
echo "==> target/dist/$name.zip"
