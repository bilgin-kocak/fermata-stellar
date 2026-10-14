#!/usr/bin/env bash
# Regenerates the typed contract clients from the contracts' Wasm with the Stellar CLI
# (`stellar contract bindings typescript`): src/escrow/bindings.ts and src/session/bindings.ts. The
# files are committed as generated, so `--check` (CI) fails when a contract changed and its client
# was not regenerated.
#
#   bash packages/sdk/scripts/bindings.sh            # regenerate
#   bash packages/sdk/scripts/bindings.sh --check    # compare with the committed files
set -euo pipefail
sdk="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "$sdk/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
status=0
for contract in escrow session; do
  wasm="$root/target/wasm32v1-none/release/fermata_$contract.wasm"
  if [ ! -f "$wasm" ]; then
    (cd "$root" && stellar contract build --package "fermata-$contract" >/dev/null 2>&1) ||
      { echo "contract build failed (fermata-$contract)" >&2; exit 1; }
  fi
  stellar contract bindings typescript --wasm "$wasm" --output-dir "$tmp/$contract" --overwrite >/dev/null 2>&1
  generated="$tmp/$contract/src/index.ts"
  target="$sdk/src/$contract/bindings.ts"
  if [ "${1:-}" = --check ]; then
    if [ -f "$target" ] && diff -u "$target" "$generated"; then
      echo "bindings: src/$contract/bindings.ts is up to date with the contract"
    else
      echo "bindings: src/$contract/bindings.ts differs from the contract; run packages/sdk/scripts/bindings.sh" >&2
      status=1
    fi
  else
    mkdir -p "$(dirname "$target")"
    cp "$generated" "$target"
    echo "bindings: wrote ${target#"$root"/}"
  fi
done
exit "$status"
