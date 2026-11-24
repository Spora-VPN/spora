#!/bin/sh
# Tests src/install.sh against releases made up on the spot and read over
# file://, so nothing is downloaded and nothing is written outside a scratch
# directory. Needs curl (wget cannot read file://).
#
#   sh docs-site/install-test.sh
#   TEST_SHELL=bash sh docs-site/install-test.sh    # the installer under another shell

set -eu

script=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/src/install.sh
work=$(mktemp -d)
trap 'chmod -R u+w "$work"; rm -rf "$work"' EXIT
unset SPORA_VERSION SPORA_INSTALL_DIR SPORA_RELEASES_URL dir

case $(uname -s) in
    Darwin) os=macos ;;
    *) os=linux ;;
esac
case $(uname -m) in
    arm64 | aarch64) arch=aarch64 ;;
    *) arch=x86_64 ;;
esac

sha256() {
    if command -v sha256sum >/dev/null; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# sums <tag>: (re)write the release's SHA256SUMS from its archives
sums() {
    (
        cd "$work/releases/download/$1"
        for f in *.tar.gz; do
            printf '%s  %s\n' "$(sha256 "$f")" "$f"
        done >SHA256SUMS
    )
}

# release <tag>: a release whose `spora` prints its tag, next to a relay
# archive as in a real release (listed first, and never to be picked)
release() {
    mkdir -p "$work/stage" "$work/releases/download/$1"
    printf '#!/bin/sh\necho "spora %s"\n' "$1" >"$work/stage/spora"
    chmod 755 "$work/stage/spora"
    tar -C "$work/stage" -czf "$work/releases/download/$1/spora-$1-$os-$arch.tar.gz" spora
    printf '#!/bin/sh\necho relay\n' >"$work/stage/spora"
    tar -C "$work/stage" -czf "$work/releases/download/$1/spora-relay-$1-$os-$arch.tar.gz" spora
    sums "$1"
}

# latest <tag>: what releases/latest/download/SHA256SUMS answers with
latest() {
    mkdir -p "$work/releases/latest/download"
    cp "$work/releases/download/$1/SHA256SUMS" "$work/releases/latest/download/SHA256SUMS"
}

# run [VAR=value...]: the installer against the made-up releases, its
# output kept for the checks
run() {
    # shellcheck disable=SC2086  # TEST_SHELL may be two words ("busybox sh")
    env SPORA_RELEASES_URL="file://$work/releases" SPORA_INSTALL_DIR="${dir:-$work/bin}" "$@" \
        ${TEST_SHELL:-sh} "$script" >"$work/out" 2>&1
}

failed() {
    echo "FAILED: $*"
    sed 's/^/    /' "$work/out"
    exit 1
}

# expect <version> <what>: the install worked and left that version
expect() {
    got=$("${dir:-$work/bin}/spora" --version 2>&1) || got="(does not run)"
    [ "$got" = "spora $1" ] || failed "$2: installed '$got', expected 'spora $1'"
    echo "ok: $2"
}

# refused <text> <what>: the install failed saying <text>, and what was
# installed before is still there
refused() {
    grep -q "$1" "$work/out" || failed "$2: expected an error saying '$1'"
    got=$("$work/bin/spora" --version)
    [ "$got" = "spora v1.1.0" ] || failed "$2: left '$got' installed"
    echo "ok: $2"
}

release v1.0.0
latest v1.0.0
run || failed "the latest release, into a directory that does not exist yet"
expect v1.0.0 "installs the latest release"

release v1.1.0
latest v1.1.0
run || failed "an upgrade"
expect v1.1.0 "run again, it upgrades"

if [ "$(id -u)" != 0 ]; then
    # A directory the user cannot write to, and a sudo that can.
    mkdir -p "$work/locked" "$work/fakebin"
    chmod 555 "$work/locked"
    # shellcheck disable=SC2016  # "$@" is for the sudo being written, not for here
    printf '#!/bin/sh\nchmod u+w "%s"\nexec "$@"\n' "$work/locked" >"$work/fakebin/sudo"
    chmod 755 "$work/fakebin/sudo"
    dir=$work/locked
    run PATH="$work/fakebin:$PATH" || failed "an install that needs sudo"
    grep -q 'sudo may ask' "$work/out" || failed "an install that needs sudo did not say so"
    expect v1.1.0 "asks sudo where it cannot write"
    unset dir
fi

run SPORA_VERSION=v1.0.0 || failed "a pinned version"
expect v1.0.0 "SPORA_VERSION pins a release"
run || failed "back to the latest"
expect v1.1.0 "and without it, the latest again"

if run SPORA_VERSION=../v1.0.0; then failed "a SPORA_VERSION that is no tag was accepted"; fi
refused 'not a release tag' "refuses a SPORA_VERSION that is no tag"

if run SPORA_VERSION=v9.9.9; then failed "a release that does not exist was installed"; fi
refused 'could not download' "says so when the release does not exist"

release v1.2.0
latest v1.2.0
echo tampered >>"$work/releases/download/v1.2.0/spora-v1.2.0-$os-$arch.tar.gz"
if run; then failed "an archive that does not match SHA256SUMS was installed"; fi
refused 'does not match its checksum' "refuses an archive that does not match its checksum"

release v1.3.0
rm "$work/releases/download/v1.3.0/spora-v1.3.0-$os-$arch.tar.gz"
sums v1.3.0
latest v1.3.0
if run; then failed "a release without this system's archive was installed"; fi
refused 'no build for' "says so when the release has no build for this system"

echo "install.sh: all passed"
