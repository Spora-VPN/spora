#!/bin/sh
# Installs the Spora CLI on Linux and macOS.
#
#   curl -fsSL https://spora.to/docs/install.sh | sh
#
# It finds the latest release on GitHub, downloads the archive for this
# system, checks it against the release's SHA256SUMS and puts the `spora`
# binary in /usr/local/bin, asking sudo for that one step when it has to.
# Run it again to upgrade.
#
# Environment:
#   SPORA_VERSION       install this release tag (say v0.3.3), not the latest
#   SPORA_INSTALL_DIR   install into this directory, not /usr/local/bin
#   SPORA_RELEASES_URL  fetch from a mirror of
#                       https://github.com/Spora-VPN/spora/releases
#
# Windows has its own script: https://spora.to/docs/install.ps1
# Guide: https://spora.to/docs/quickstart.html

set -eu

GUIDE=https://spora.to/docs/quickstart.html

say() { printf '%s\n' "$*"; }
fail() {
    printf 'spora install: %s\n' "$*" >&2
    exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

# fetch <url> <file>
fetch() {
    if have curl; then
        curl -fsSL --retry 3 -o "$2" "$1"
    else
        wget -q -O "$2" "$1"
    fi
}

# sha256 <file>: the file's SHA-256 in hex
sha256() {
    if have sha256sum; then
        sha256sum "$1" | cut -d' ' -f1
    elif have shasum; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        openssl dgst -sha256 -r "$1" | cut -d' ' -f1
    fi
}

as_root() {
    if [ -n "$elevate" ]; then
        "$elevate" "$@"
    else
        "$@"
    fi
}

# Everything runs from here, called on the last line: a download cut short
# runs nothing instead of half a script.
main() {
    releases=${SPORA_RELEASES_URL:-https://github.com/Spora-VPN/spora/releases}
    releases=${releases%/}

    case $(uname -s) in
        Linux) os=linux ;;
        Darwin) os=macos ;;
        MINGW* | MSYS* | CYGWIN*)
            fail "on Windows, run this in PowerShell instead: irm https://spora.to/docs/install.ps1 | iex"
            ;;
        *) fail "there is no release for $(uname -s). To build from source, see $GUIDE" ;;
    esac

    case $(uname -m) in
        x86_64 | amd64) arch=x86_64 ;;
        aarch64 | arm64) arch=aarch64 ;;
        *) fail "there is no release for $(uname -m) processors. To build from source, see $GUIDE" ;;
    esac
    # A shell running under Rosetta says x86_64 on Apple silicon.
    if [ "$os" = macos ] && [ "$arch" = x86_64 ] &&
        [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
        arch=aarch64
    fi

    have curl || have wget || fail "curl or wget is needed to download the release"
    have sha256sum || have shasum || have openssl ||
        fail "sha256sum, shasum or openssl is needed to check the download"
    have tar || fail "tar is needed to unpack the release"

    # The release's SHA256SUMS names every archive, so it tells both which
    # release is the latest and what its archive must hash to.
    tag=${SPORA_VERSION:-}
    case $tag in
        '')
            sums_url=$releases/latest/download/SHA256SUMS
            want="spora-v*-$os-$arch.tar.gz"
            ;;
        *[!A-Za-z0-9._-]*) fail "SPORA_VERSION is not a release tag: $tag" ;;
        *)
            sums_url=$releases/download/$tag/SHA256SUMS
            want="spora-$tag-$os-$arch.tar.gz"
            ;;
    esac

    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    trap 'exit 1' HUP INT TERM

    fetch "$sums_url" "$tmp/SHA256SUMS" || fail "could not download $sums_url"

    asset=
    expected=
    while read -r sum name; do
        name=${name#\*}
        # shellcheck disable=SC2254  # $want is a pattern on purpose
        case $name in
            $want)
                asset=$name
                expected=$sum
                break
                ;;
        esac
    done <"$tmp/SHA256SUMS"
    [ -n "$asset" ] || fail "the release has no build for $os $arch. See $releases"

    tag=${asset#spora-}
    tag=${tag%"-$os-$arch.tar.gz"}
    case $tag in
        *[!A-Za-z0-9._-]*) fail "unexpected archive name in SHA256SUMS: $asset" ;;
    esac

    say "Downloading spora $tag for $os $arch"
    fetch "$releases/download/$tag/$asset" "$tmp/spora.tar.gz" ||
        fail "could not download $releases/download/$tag/$asset"

    actual=$(sha256 "$tmp/spora.tar.gz")
    [ "$actual" = "$expected" ] ||
        fail "$asset does not match its checksum (expected $expected, got $actual). Nothing was installed."

    tar -xzf "$tmp/spora.tar.gz" -C "$tmp" spora || fail "could not unpack $asset"

    dir=${SPORA_INSTALL_DIR:-/usr/local/bin}
    elevate=
    if mkdir -p "$dir" 2>/dev/null && [ -w "$dir" ]; then
        say "Installing to $dir/spora"
    elif [ "$(id -u)" = 0 ]; then
        fail "cannot write to $dir"
    elif have sudo; then
        elevate=sudo
    elif have doas; then
        elevate=doas
    else
        fail "cannot write to $dir, and there is no sudo. Run this as root, or set SPORA_INSTALL_DIR to a directory you can write to."
    fi
    if [ -n "$elevate" ]; then
        say "Installing to $dir/spora ($elevate may ask for your password)"
        as_root mkdir -p "$dir" || fail "could not create $dir"
    fi
    dir=$(CDPATH='' cd -- "$dir" && pwd)
    dest=$dir/spora

    # Renamed into place, so a spora that is running is replaced safely
    # and keeps running until it is restarted.
    as_root install -m 755 "$tmp/spora" "$dest.new.$$" || fail "could not write to $dir"
    as_root mv -f "$dest.new.$$" "$dest" || fail "could not write $dest"

    "$dest" --version >/dev/null || fail "$dest was installed but does not run on this system"
    say "Installed spora $tag"

    found=$(command -v spora || true)
    if [ -z "$found" ]; then
        say "Note: $dir is not on your PATH. Add it, or run $dest."
    elif [ "$found" != "$dest" ]; then
        say "Note: another spora comes first on your PATH: $found"
    fi

    say ""
    say "Next: run 'spora share' on the machine that shares its connection,"
    say "then 'sudo spora use <link>' on the one that connects."
    say "Guide: $GUIDE"
}

main "$@"
