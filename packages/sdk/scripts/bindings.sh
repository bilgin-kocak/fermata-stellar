#!/usr/bin/env bash
# Regenerates src/escrow/bindings.ts, the typed escrow client, from the contract Wasm with the
# Stellar CLI (`stellar contract bindings typescript`). The file is committed as generated, so
# `--check` (CI) fails when the contract changed and the client was not regenerated.
#
#   bash packages/sdk/scripts/bindings.sh            # regenerate
#   bash packages/sdk/scripts/bindings.sh --check    # compare with the committed file
set -euo pipefail
sdk="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "$sdk/../.." && pwd)"
wasm="$root/target/wasm32v1-none/release/fermata_escrow.wasm"
if [ ! -f "$wasm" ]; then
  (cd "$root" && stellar contract build --package fermata-escrow >/dev/null 2>&1) ||
    { echo "contract build failed" >&2; exit 1; }
fi
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
stellar contract bindings typescript --wasm "$wasm" --output-dir "$tmp/escrow" --overwrite >/dev/null 2>&1
generated="$tmp/escrow/src/index.ts"
target="$sdk/src/escrow/bindings.ts"
if [ "${1:-}" = --check ]; then
  if diff -u "$target" "$generated"; then
    echo "bindings: up to date with the contract"
  else
    echo "bindings: src/escrow/bindings.ts differs from the contract; run packages/sdk/scripts/bindings.sh" >&2
    exit 1
  fi
else
  cp "$generated" "$target"
  echo "bindings: wrote ${target#"$root"/}"
fi
