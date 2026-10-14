#!/usr/bin/env bash
# Milestone 2: an agent pays a vendor through the gateway, with MPP and with x402, and every
# outcome reconciles from events. Every component is a real process, against the deployment in
# deployments/<network>.json:
#
#   demo vendors (ok, 500, hang) → notary → fermata-attest serve → gateway → agent
#
#   A1-A3  the `fermata` MPP method (sponsored, direct, sponsored) → ok, 500, hang
#   B1-B3  the `fermata` x402 scheme → ok, 500, hang
#          ok: verdict DELIVERED → released; 500: FAILED → refunded; hang: no proof → the gateway's
#          sweeper refunds the agent with claim_timeout after the window
#   C1-C2  Stellar's MPP Charge and x402 `exact` → ok: unprotected, the vendor is paid directly
#
# Then each escrowed call is checked against the gateway's record, reconciled from the indexed
# events (the escrow's and the token's), and its proof re-verified offline against the chain; the
# agent's and the vendor's token balances must move by exactly what the outcomes say, and the escrow
# must reconcile as a whole.
#
#   NETWORK=local LOCAL_PASSPHRASE="Test SDF Network ; September 2015" scripts/gateway-cases.sh
#   scripts/gateway-cases.sh                  # testnet (see the README)
#
# The gateway reads its settings from this environment too: with OZ_CHANNELS_URL and
# OZ_CHANNELS_API_KEY it submits the agents' holds through OpenZeppelin Channels instead of from the
# relayer's account, and with X402_FACILITATOR_URL (and X402_FACILITATOR_API_KEY, if it needs one)
# x402 `exact` goes through that facilitator instead of one in the gateway's process.
#
# Stellar's MPP Charge and x402 `exact` know only the testnet and mainnet passphrases, so on a local
# network started with the standalone passphrase they are not offered (C1-C2 are skipped). Stellar's
# MPP Charge also refuses a plain-HTTP RPC URL, so on a local network the gateway and the agent reach
# the RPC through scripts/lib/tls-proxy.mjs with a certificate made for this run.
#
# Secrets: the relayer's and the agent's keys come from the keystore and reach the gateway and the
# agent through their environment for this run only; the notary's key and the gateway's HMAC secret
# are generated for this run and kept in memory.
#
# Ported in spirit from Fermata scripts/e2e-gateway.sh @ d7cc642 (github.com/bilgin-kocak/fermata).

# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"
need stellar cargo jq openssl node curl

[ -f "$DEPLOYMENT" ] || die "no ${DEPLOYMENT#"$ROOT"/}; run scripts/deploy-testnet.sh first"
d() { jq -r "$1" "$DEPLOYMENT"; }
ESCROW="$(d .escrow.contract_id)"
TOKEN_SAC="$(d .token.sac)"
PRICE="$(d .service.price_per_call)"
WINDOW="$(d .service.settlement_window)"
VENDOR="$(d .service.owner)"
VERIFIER_KEY="$(d .service.verifier)"
START_LEDGER="$(d '.escrow.deploy_ledger // empty')"
AGENT="$(address_of agent)"
[ "$AGENT" = "$(d .accounts.agent)" ] || die "the keystore's $(key agent) is not the deployment's agent"
[ "$VENDOR" = "$(address_of vendor)" ] || die "the keystore's $(key vendor) is not the deployment's vendor"
[ "$(d .network_passphrase)" = "$PASSPHRASE" ] || die "deployment is for another network"

case "$PASSPHRASE" in
"Test SDF Network ; September 2015") CAIP2="stellar:testnet" FALLBACK=yes ;;
"Standalone Network ; February 2017") CAIP2="stellar:local" FALLBACK=no ;;
*) die "no CAIP-2 network id for \"$PASSPHRASE\"" ;;
esac

NEEDED=$((8 * PRICE))
HAVE="$(balance "$AGENT")"
[ "$HAVE" -ge "$NEEDED" ] ||
  die "the agent holds $HAVE of the $NEEDED base units needed (8 calls); fund $AGENT (USDC: $USDC_FAUCET)"

OK_PORT="${OK_PORT:-8743}"
E500_PORT="${E500_PORT:-8744}"
HANG_PORT="${HANG_PORT:-8745}"
NOTARY_PORT="${NOTARY_PORT:-7247}"
ATTESTOR_PORT="${ATTESTOR_PORT:-7248}"
GATEWAY_PORT="${GATEWAY_PORT:-4300}"
RPC_TLS_PORT="${RPC_TLS_PORT:-7443}" # not 8001-8004: the quickstart uses them
ATTESTOR="http://127.0.0.1:$ATTESTOR_PORT"
GATEWAY="http://127.0.0.1:$GATEWAY_PORT"
TARGET="/v1/quote?symbol=BTC-USD"
LOGS="$OUT_DIR/gateway-cases-$NETWORK"
GW="$ROOT/apps/gateway"
TSX="$GW/node_modules/.bin/tsx"
[ -x "$TSX" ] || die "run 'pnpm install' first (the gateway's dependencies)"

[ -x "$FV" ] || (cd "$ROOT" && cargo build --quiet --release -p fermata-verdict)
build_attestor
CA="$ROOT/apps/vendor/certs/ca.pem"
[ -f "$CA" ] || bash "$ROOT/apps/vendor/gen-certs.sh" >/dev/null
rm -rf "$LOGS"
mkdir -p "$LOGS"

pids=()
# Stopped in reverse order: the gateway before the RPC proxy it reads through.
cleanup() {
  local i
  for ((i = ${#pids[@]} - 1; i >= 0; i--)); do kill "${pids[i]}" 2>/dev/null || true; done
}
trap cleanup EXIT
wait_port() {
  local _
  for _ in $(seq 300); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
    sleep 0.1
  done
  die "nothing listening on port $1 (see ${LOGS#"$ROOT"/})"
}
api() { curl -sS --noproxy '*' "$@"; }
# A process left on one of these ports (an earlier run, say) would answer in place of this run's.
ports=("$OK_PORT" "$E500_PORT" "$HANG_PORT" "$NOTARY_PORT" "$ATTESTOR_PORT" "$GATEWAY_PORT")
[ "$NETWORK" != local ] || ports+=("$RPC_TLS_PORT")
for p in "${ports[@]}"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then die "port $p is already in use; stop what listens there"; fi
done

log "escrow $ESCROW on $NETWORK ($CAIP2), price $PRICE, window ${WINDOW}s"
log "starting the demo vendors, a notary and the attestor (logs in ${LOGS#"$ROOT"/})"
PORT=$OK_PORT node "$ROOT/apps/vendor/server.mjs" >"$LOGS/vendor-ok.log" 2>&1 &
pids+=($!)
PORT=$E500_PORT CHAOS=500 node "$ROOT/apps/vendor/server.mjs" >"$LOGS/vendor-500.log" 2>&1 &
pids+=($!)
PORT=$HANG_PORT CHAOS=hang node "$ROOT/apps/vendor/server.mjs" >"$LOGS/vendor-hang.log" 2>&1 &
pids+=($!)
NOTARY_PRIVATE_KEY="$(openssl rand -hex 32)" RUST_LOG=error \
  "$ATTEST" notary --listen "127.0.0.1:$NOTARY_PORT" --ca "$CA" >"$LOGS/notary.json" 2>"$LOGS/notary.log" &
pids+=($!)
for p in "$OK_PORT" "$E500_PORT" "$HANG_PORT" "$NOTARY_PORT"; do wait_port "$p"; done
NOTARY_KEY_HASH="$(jq -r .notaryKeyHash "$LOGS/notary.json")"

attestor_args=(--network "$NETWORK" --network-passphrase "$PASSPHRASE" --escrow "$ESCROW")
attestor_args+=(--rpc "$RPC")
FERMATA_VERIFIER_SECRET="$(verifier_secret)" "$ATTEST" serve "${attestor_args[@]}" \
  --listen "127.0.0.1:$ATTESTOR_PORT" --notary "127.0.0.1:$NOTARY_PORT" --ca "$CA" \
  --predicate "$ROOT/predicates" --storage "$LOGS/presentations" --attempt-timeout-secs 10 \
  --resolve "vendor.fermata.test:$OK_PORT=127.0.0.1:$OK_PORT" \
  --resolve "vendor.fermata.test:$E500_PORT=127.0.0.1:$E500_PORT" \
  --resolve "vendor.fermata.test:$HANG_PORT=127.0.0.1:$HANG_PORT" >"$LOGS/attestor.log" 2>&1 &
pids+=($!)
wait_port "$ATTESTOR_PORT"
[ "$(api "$ATTESTOR/healthz" | jq -r .signerKey)" = "$VERIFIER_KEY" ] ||
  die "the attestor does not sign with the deployment's verifier key"

SUFFIX="$(openssl rand -hex 2)"
PREDICATE_HASH="$("$FV" predicate-hash "$ROOT/predicates/quote-v1.json")"
register() { # name port
  local label="$1-$SUFFIX"
  invoke vendor register_service --owner "$VENDOR" --label "$("$FV" label "$label")" --payout "$VENDOR" \
    --token "$TOKEN_SAC" --price_per_call "$PRICE" --settlement_window "$WINDOW" \
    --verifier "$VERIFIER_KEY" --predicate_hash "$PREDICATE_HASH" \
    --origin_hash "$("$FV" origin-hash "https://vendor.fermata.test:$2")" \
    --notary_key_hash "$NOTARY_KEY_HASH"
  log "  registered $label → $(jq -r . <<<"$OUT")"
  jq -r . <<<"$OUT"
}
log "registering three services for this run's notary"
SID_OK="$(register gw-ok "$OK_PORT")"
SID_500="$(register gw-500 "$E500_PORT")"
SID_HANG="$(register gw-hang "$HANG_PORT")"

# The RPC URL the gateway and the agent use: HTTPS on a local network (see the header).
GW_RPC="$RPC"
if [ "$NETWORK" = local ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=localhost \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout "$LOGS/rpc-tls.key" -out "$LOGS/rpc-tls.pem" 2>/dev/null
  node "$ROOT/scripts/lib/tls-proxy.mjs" "$RPC_TLS_PORT" "${RPC%/rpc}" "$LOGS/rpc-tls.key" "$LOGS/rpc-tls.pem" \
    >"$LOGS/rpc-tls.log" 2>&1 &
  proxy=$!
  pids+=("$proxy")
  # It prints its address once it listens; another process on the port would make it exit.
  for _ in $(seq 100); do
    grep -q ' -> ' "$LOGS/rpc-tls.log" && break
    kill -0 "$proxy" 2>/dev/null || die "the RPC's TLS proxy did not start (see ${LOGS#"$ROOT"/}/rpc-tls.log)"
    sleep 0.1
  done
  GW_RPC="https://localhost:$RPC_TLS_PORT/rpc"
  export NODE_EXTRA_CA_CERTS="$LOGS/rpc-tls.pem"
fi

SECRET="Bearer gw-$(openssl rand -hex 12)"
jq -n --arg network "$CAIP2" --arg passphrase "$PASSPHRASE" --arg rpc "$GW_RPC" --arg escrow "$ESCROW" \
  --arg attestor "$ATTESTOR" --arg logs "$LOGS" --argjson port "$GATEWAY_PORT" \
  --arg start "$START_LEDGER" --arg fallback "$FALLBACK" --arg vendor "$VENDOR" \
  --arg ok "$SID_OK" --arg e500 "$SID_500" --arg hang "$SID_HANG" \
  --arg ok_port "$OK_PORT" --arg e500_port "$E500_PORT" --arg hang_port "$HANG_PORT" \
  'def svc($id; $port): {serviceId: $id, upstream: "https://vendor.fermata.test:\($port)",
       examplePath: "/v1/quote?symbol=BTC-USD", summary: "BTC/ETH/SOL spot quote",
       upstreamAuth: {header: "Authorization", env: "VENDOR_UPSTREAM_TOKEN"}};
   {port: $port, realm: "127.0.0.1:\($port)", network: $network, networkPassphrase: $passphrase,
    rpcUrl: $rpc, escrow: $escrow, attestorUrl: $attestor,
    storageDir: "\($logs)/calls", indexDir: "\($logs)/index",
    services: [
      (svc($ok; $ok_port) + (if $fallback == "yes" then {unprotected: {recipient: $vendor}} else {} end)),
      svc($e500; $e500_port), svc($hang; $hang_port)
    ]}
   + (if $start != "" then {startLedger: ($start | tonumber)} else {} end)' >"$LOGS/gateway.config.json"

log "starting the gateway on $GATEWAY"
resolve="vendor.fermata.test:$OK_PORT=127.0.0.1:$OK_PORT,vendor.fermata.test:$E500_PORT=127.0.0.1:$E500_PORT"
# exec, so the recorded pid is tsx's (it passes the signal on to the gateway) and cleanup stops it.
(cd "$GW" && GATEWAY_CONFIG="$LOGS/gateway.config.json" \
  FERMATA_RELAYER_SECRET="$(stellar keys secret "$(key relayer)")" \
  GATEWAY_SECRET_KEY="$(openssl rand -hex 32)" VENDOR_UPSTREAM_TOKEN="$SECRET" \
  GATEWAY_UPSTREAM_CA="$CA" GATEWAY_RESOLVE="$resolve" GATEWAY_SWEEP_MS=2000 GATEWAY_INDEX_MS=2000 \
  exec "$TSX" src/main.ts >"$LOGS/gateway.log" 2>&1) &
pids+=($!)
wait_port "$GATEWAY_PORT"
api "$GATEWAY/info" | jq -c . >&2

log ""
log "paying through the gateway (the hang cases wait out the ${WINDOW}s window)"
REPORT="$OUT_DIR/gateway-cases-$NETWORK.json"
set +e
(cd "$GW" && GATEWAY_URL="$GATEWAY" FERMATA_DEPLOYMENT="$DEPLOYMENT" STELLAR_RPC_URL="$GW_RPC" \
  STELLAR_NETWORK="$CAIP2" FERMATA_AGENT_SECRET="$(stellar keys secret "$(key agent)")" \
  SERVICES="$(jq -nc --arg ok "$SID_OK" --arg e500 "$SID_500" --arg hang "$SID_HANG" '{ok: $ok, e500: $e500, hang: $hang}')" \
  TARGET="$TARGET" WINDOW="$WINDOW" "$TSX" scripts/agent.ts >"$REPORT")
status=$?
set -e
[ -s "$REPORT" ] || die "the agent wrote no report (see ${LOGS#"$ROOT"/}/gateway.log)"
if [ "$FALLBACK" = no ]; then log "C1-C2 skipped: Stellar's MPP Charge and x402 exact need testnet's or mainnet's passphrase"; fi

if grep -qF "${SECRET#Bearer }" "$LOGS"/presentations/*.tlsn 2>/dev/null; then
  log "FAIL  the upstream Authorization value appears in a presentation"
  status=1
fi

printf '\n%-4s %-25s %-6s %-5s %-17s %s\n' "case" "paid with" "to" "HTTP" "outcome" "call"
jq -r '.cases[] | [.id, .pay, .service, (.http // "-" | tostring), (.outcome // "unprotected"), (.callId // "-")] | @tsv' "$REPORT" |
  while IFS=$'\t' read -r id pay svc http outcome call; do
    printf '%-4s %-25s %-6s %-5s %-17s %s\n' "$id" "$pay" "$svc" "$http" "$outcome" "$call"
  done
printf '\nreport %s\n' "${REPORT#"$ROOT"/}"
if [ "$status" -eq 0 ]; then
  printf '%s checks PASS\n' "$(jq '[.cases[].checks[]] + .balanceChecks + [.escrowCheck] | length' "$REPORT")"
else
  printf 'FAIL: %s check(s) failed (see the report and %s)\n' "$(jq .failures "$REPORT")" "${LOGS#"$ROOT"/}"
  exit 1
fi
