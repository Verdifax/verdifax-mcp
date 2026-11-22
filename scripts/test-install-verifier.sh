#!/bin/sh
# Tests the verifier installer's refusals without any download: a missing or
# malformed tag, and a machine without cosign, are refused before anything is
# fetched or installed.
set -u
here=$(cd "$(dirname "$0")" && pwd)
folder=$(mktemp -d)
trap 'rm -rf "$folder"' EXIT
failures=0

expect_refusal() {
  label=$1
  shift
  if "$@" >/dev/null 2>&1; then
    echo "FAIL: $label was not refused"
    failures=$((failures + 1))
  elif [ -e "$folder/verdifax-verify" ]; then
    echo "FAIL: $label installed something"
    failures=$((failures + 1))
  else
    echo "ok: $label is refused"
  fi
}

expect_refusal "no tag" sh "$here/install-verifier.sh"
expect_refusal "the word latest" sh "$here/install-verifier.sh" latest "$folder"
expect_refusal "a tag with a shell character" sh "$here/install-verifier.sh" 'v1.2.3;rm' "$folder"
expect_refusal "a tag with a path" sh "$here/install-verifier.sh" 'v1.2.3/../x' "$folder"
nocosign=$(mktemp -d)
for tool in sh uname cut mktemp rm curl; do
  path=$(command -v "$tool") && ln -s "$path" "$nocosign/$tool"
done
expect_refusal "a machine without cosign" env PATH="$nocosign" sh "$here/install-verifier.sh" v0.0.1 "$folder"
rm -rf "$nocosign"

[ "$failures" -eq 0 ] || exit 1
echo "all installer refusals hold"
