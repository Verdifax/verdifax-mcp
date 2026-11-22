#!/bin/sh
# Optional installer for verdifax-verify, the open-source verifier the
# verify_record and verify_feed tools run. It downloads one named release
# for this machine from GitHub and installs it only if both checks pass:
#
#   1. SHA-256: the binary matches the checksum file published beside it,
#      which shows the download is whole. The checksum comes from the same
#      release, so on its own it does not show who built the binary.
#   2. Sigstore: cosign verifies the release's Sigstore bundle, which shows
#      the binary was signed by the verdifax-verify repository's GitHub
#      Actions identity and recorded on the public Sigstore log.
#
# usage: scripts/install-verifier.sh vX.Y.Z [install-folder]
#
# Use the tag of the latest release at
# https://github.com/Verdifax/verdifax-verify/releases/latest. The install
# folder defaults to $HOME/.local/bin. Needs curl and cosign.
set -eu

fail() {
  echo "install-verifier: $*" >&2
  exit 2
}

version=${1:-}
folder=${2:-"$HOME/.local/bin"}
case "$version" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "give the release tag, such as the tag at https://github.com/Verdifax/verdifax-verify/releases/latest" ;;
esac
case "$version" in
  *[!v0-9.]*) fail "the release tag holds characters a tag does not have" ;;
esac

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "no pre-built verifier for this system; build it with go install github.com/Verdifax/verdifax-verify@$version" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "no pre-built verifier for this processor" ;;
esac

command -v curl >/dev/null 2>&1 || fail "curl is needed"
command -v cosign >/dev/null 2>&1 || fail "cosign is needed to check the signature: https://docs.sigstore.dev/cosign/system_config/installation/"

asset="verdifax-verify-$os-$arch"
base="https://github.com/Verdifax/verdifax-verify/releases/download/$version"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for name in "$asset" "$asset.sha256" "$asset.bundle"; do
  curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$name" "$base/$name" || fail "could not download $base/$name"
done

expected=$(cut -d ' ' -f 1 "$work/$asset.sha256")
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$work/$asset" | cut -d ' ' -f 1)
else
  actual=$(shasum -a 256 "$work/$asset" | cut -d ' ' -f 1)
fi
[ -n "$expected" ] && [ "$expected" = "$actual" ] || fail "SHA-256 check failed: nothing was installed"

cosign verify-blob \
  --bundle "$work/$asset.bundle" \
  --certificate-identity-regexp '^https://github.com/Verdifax/verdifax-verify/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$work/$asset" >/dev/null 2>&1 || fail "Sigstore check failed: nothing was installed"

mkdir -p "$folder"
cp "$work/$asset" "$folder/verdifax-verify"
chmod 0755 "$folder/verdifax-verify"
echo "installed $("$folder/verdifax-verify" --version) at $folder/verdifax-verify"
echo "both checks passed: SHA-256 and the Sigstore bundle"
