# shellcheck shell=bash
# Variables set here are used by the scripts that source this file.
# shellcheck disable=SC2034
# Helpers shared by the scripts in this directory. Sourced, not executed.
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
SESSION_WASM="$ROOT/target/wasm32v1-none/release/fermata_session.wasm"
ATTEST="$ROOT/apps/attestor/target/release/fermata-attest"

# NET: the network flags every `stellar` command gets. A local quickstart network is named by its
# RPC URL and passphrase rather than the CLI's built-in `local`, because it may run with another
# passphrase: LOCAL_PASSPHRASE (CI starts it with testnet's, so that libraries that know only the
# testnet and mainnet passphrases run against it unmodified).
case "$NETWORK" in
testnet)
  PASSPHRASE="Test SDF Network ; September 2015"
  EXPLORER="https://stellar.expert/explorer/testnet"
  RPC="${RPC_URL:-https://soroban-testnet.stellar.org}"
  NET=(--network testnet)
  ;;
local)
  PASSPHRASE="${LOCAL_PASSPHRASE:-Standalone Network ; February 2017}"
  EXPLORER=""
  RPC="${RPC_URL:-http://localhost:8000/rpc}"
  NET=(--rpc-url "$RPC" --network-passphrase "$PASSPHRASE")
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
  stellar ledger entry fetch account --account "$1" "${NET[@]}" 2>/dev/null |
    jq -e '.entries | length > 0' >/dev/null
}

# ensure_key ROLE [fund]: creates the identity if missing; with "fund", funds it with Friendbot
# unless the account already exists.
ensure_key() {
  local name
  name="$(key "$1")"
  if ! stellar keys public-key "$name" >/dev/null 2>&1; then
    stellar keys generate "$name" "${NET[@]}" >/dev/null
    log "  created identity $name in the Stellar CLI keystore"
  fi
  if [ "${2:-}" = fund ] && ! account_exists "$(stellar keys public-key "$name")"; then
    stellar keys fund "$name" "${NET[@]}" >/dev/null
    log "  funded $name with Friendbot"
  fi
}

# A local quickstart's RPC sometimes fails a simulation with "could not query captive core" while
# core publishes a checkpoint. Nothing was signed or sent then, so the command is safe to repeat.
CAPTIVE_CORE_BUSY='could not query captive core'

# submit CMD...: runs a Stellar CLI command that sends a transaction. Sets OUT (its stdout) and
# LAST_TX (the hash of the last transaction it signed). On failure prints the CLI's output.
OUT=""
LAST_TX=""
submit() {
  local err attempt
  err="$(mktemp)"
  for attempt in 1 2 3; do
    if OUT="$("$@" 2>"$err")"; then
      LAST_TX="$(grep -o 'Signing transaction: [0-9a-f]\{64\}' "$err" | tail -1 | awk '{print $3}' || true)"
      rm -f "$err"
      return 0
    fi
    grep -q 'Signing transaction' "$err" && break
    grep -q "$CAPTIVE_CORE_BUSY" "$err" || break
    log "  the RPC could not query captive core (attempt $attempt); trying again"
    sleep 2
  done
  cat "$err" >&2
  rm -f "$err"
  return 1
}

# invoke ROLE FN ARGS...: sends a transaction calling the escrow, signed by ROLE.
invoke() {
  invoke_at "$ESCROW" "$@"
}

# invoke_at CONTRACT ROLE FN ARGS...: sends a transaction calling CONTRACT, signed by ROLE.
invoke_at() {
  local contract="$1" role="$2"
  shift 2
  submit stellar contract invoke --id "$contract" --source "$(key "$role")" \
    "${NET[@]}" -- "$@"
}

# view CONTRACT FN ARGS...: simulates a read-only call and prints the JSON result.
view() {
  local contract="$1" err attempt
  shift
  err="$(mktemp)"
  for attempt in 1 2 3; do
    if stellar contract invoke --id "$contract" --source "$(key relayer)" \
      "${NET[@]}" --send=no -- "$@" 2>"$err"; then
      rm -f "$err"
      return 0
    fi
    grep -q "$CAPTIVE_CORE_BUSY" "$err" || break
    sleep 2
  done
  rm -f "$err"
  return 1
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

# The agent's ticket key (signs session tickets, never a transaction), from FERMATA_TICKET_SECRET
# if set, else from the keystore.
ticket_secret() {
  if [ -n "${FERMATA_TICKET_SECRET:-}" ]; then
    printf '%s' "$FERMATA_TICKET_SECRET"
  else
    stellar keys secret "$(key ticket)"
  fi
}

build_tools() {
  local out package
  log "building the contracts and the fermata-verdict CLI"
  for package in fermata-escrow fermata-session; do
    if ! out="$(cd "$ROOT" && stellar contract build --package "$package" 2>&1)"; then
      printf '%s\n' "$out" >&2
      die "contract build failed ($package)"
    fi
  done
  (cd "$ROOT" && cargo build --quiet --release -p fermata-verdict)
  [ -f "$WASM" ] || die "no wasm at $WASM"
  [ -f "$SESSION_WASM" ] || die "no wasm at $SESSION_WASM"
}

# The attestor is its own workspace; building from its directory picks up the Rust 1.95.0 its
# rust-toolchain.toml pins (TLSNotary needs it). The first build takes a few minutes.
build_attestor() {
  log "building the attestor (Rust 1.95.0, TLSNotary)"
  (cd "$ROOT/apps/attestor" && cargo build --quiet --release) || die "attestor build failed"
  [ -x "$ATTEST" ] || die "no attestor at $ATTEST"
}

latest_ledger() { stellar ledger latest "${NET[@]}" --output json | jq -r .sequence; }

# rpc METHOD PARAMS_JSON: one Stellar RPC call; prints its result.
rpc() {
  curl -sS --noproxy localhost,127.0.0.1 -X POST -H 'content-type: application/json' \
    -d "$(jq -nc --arg m "$1" --argjson p "$2" '{jsonrpc: "2.0", id: 1, method: $m, params: $p}')" "$RPC" |
    jq -c .result
}

# The ledger a transaction landed in (while the RPC still has it).
tx_ledger() { rpc getTransaction "$(jq -nc --arg h "$1" '{hash: $h}')" | jq -r '.ledger // empty'; }

# sha256 of stdin as hex (sha256sum on Linux, shasum on macOS).
sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}
