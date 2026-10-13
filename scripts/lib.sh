# shellcheck shell=bash
# Variables set here are used by the scripts that source this file.
# shellcheck disable=SC2034
# Helpers shared by deploy-testnet.sh and demo-cases.sh. Sourced, not executed.
#
# Keys live only in the Stellar CLI keystore (`stellar keys`), as identities named
# "$KEY_PREFIX-<role>". Secrets are never printed or written to the repository; the verifier's
# secret is passed to fermata-verdict through its environment for one command at a time.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Optional overrides (see .env.example); .env is git-ignored.
if [ -f "$ROOT/.env" ]; then
  set -a
  # shellcheck source=/dev/null
  . "$ROOT/.env"
  set +a
fi
NETWORK="${NETWORK:-testnet}"
KEY_PREFIX="${KEY_PREFIX:-fermata}"
DEPLOYMENT="${DEPLOYMENT:-$ROOT/deployments/$NETWORK.json}"
OUT_DIR="${OUT_DIR:-$ROOT/out}"
FV="$ROOT/target/release/fermata-verdict"
WASM="$ROOT/target/wasm32v1-none/release/fermata_escrow.wasm"

case "$NETWORK" in
testnet)
  PASSPHRASE="Test SDF Network ; September 2015"
  EXPLORER="https://stellar.expert/explorer/testnet"
  ;;
local)
  PASSPHRASE="Standalone Network ; February 2017"
  EXPLORER=""
  ;;
*)
  echo "NETWORK must be testnet or local, got '$NETWORK'" >&2
  exit 64
  ;;
esac

# Circle's USDC on Stellar testnet: issuer from Circle's and SDF's documentation; its Stellar
# Asset Contract id is derived, not hard-coded (`stellar contract id asset`).
USDC_ASSET="USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
USDC_FAUCET="https://faucet.circle.com"
# The fallback: a test asset this repository issues itself. It has no value.
TEST_ASSET_CODE="FERMATATEST"

log() { printf '%s\n' "$*" >&2; }
die() {
  log "error: $*"
  exit 1
}

need() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "missing '$c' (see README, Quick start)"
  done
}

key() { printf '%s-%s' "$KEY_PREFIX" "$1"; }
address_of() { stellar keys public-key "$(key "$1")"; }

# The CLI exits 0 with no entries for an account that does not exist.
account_exists() {
  stellar ledger entry fetch account --account "$1" --network "$NETWORK" 2>/dev/null |
    jq -e '.entries | length > 0' >/dev/null
}

# ensure_key ROLE [fund]: creates the identity if missing; with "fund", funds it with Friendbot
# unless the account already exists.
ensure_key() {
  local name
  name="$(key "$1")"
  if ! stellar keys public-key "$name" >/dev/null 2>&1; then
    stellar keys generate "$name" --network "$NETWORK" >/dev/null
    log "  created identity $name in the Stellar CLI keystore"
  fi
  if [ "${2:-}" = fund ] && ! account_exists "$(stellar keys public-key "$name")"; then
    stellar keys fund "$name" --network "$NETWORK" >/dev/null
    log "  funded $name with Friendbot"
  fi
}

# submit CMD...: runs a Stellar CLI command that sends a transaction. Sets OUT (its stdout) and
# LAST_TX (the hash of the last transaction it signed). On failure prints the CLI's output.
OUT=""
LAST_TX=""
submit() {
  local err
  err="$(mktemp)"
  if ! OUT="$("$@" 2>"$err")"; then
    cat "$err" >&2
    rm -f "$err"
    return 1
  fi
  LAST_TX="$(grep -o 'Signing transaction: [0-9a-f]\{64\}' "$err" | tail -1 | awk '{print $3}' || true)"
  rm -f "$err"
}

# invoke ROLE FN ARGS...: sends a transaction calling the escrow, signed by ROLE.
invoke() {
  local role="$1"
  shift
  submit stellar contract invoke --id "$ESCROW" --source "$(key "$role")" \
    --network "$NETWORK" -- "$@"
}

# view CONTRACT FN ARGS...: simulates a read-only call and prints the JSON result.
view() {
  local contract="$1"
  shift
  stellar contract invoke --id "$contract" --source "$(key relayer)" \
    --network "$NETWORK" --send=no -- "$@" 2>/dev/null
}

balance() { view "$TOKEN_SAC" balance --id "$1" | tr -d '"'; }

tx_link() {
  if [ -n "$EXPLORER" ]; then printf '%s/tx/%s' "$EXPLORER" "$1"; else printf '%s' "$1"; fi
}

contract_link() {
  if [ -n "$EXPLORER" ]; then printf '%s/contract/%s' "$EXPLORER" "$1"; else printf '%s' "$1"; fi
}

# The verifier's secret, from FERMATA_VERIFIER_SECRET if set, else from the keystore.
verifier_secret() {
  if [ -n "${FERMATA_VERIFIER_SECRET:-}" ]; then
    printf '%s' "$FERMATA_VERIFIER_SECRET"
  else
    stellar keys secret "$(key verifier)"
  fi
}

build_tools() {
  local out
  log "building the contract and the fermata-verdict CLI"
  if ! out="$(cd "$ROOT" && stellar contract build --package fermata-escrow 2>&1)"; then
    printf '%s\n' "$out" >&2
    die "contract build failed"
  fi
  (cd "$ROOT" && cargo build --quiet --release -p fermata-verdict)
  [ -f "$WASM" ] || die "no wasm at $WASM"
}

# sha256 of stdin as hex (sha256sum on Linux, shasum on macOS).
sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}
