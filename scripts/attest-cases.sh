#!/usr/bin/env bash
# Milestone 1: Fermata's three canonical cases with real TLSNotary proofs, against the deployment
# in deployments/<network>.json. Every component is a real process:
#
#   demo vendors (ok, 500, hang) → notary → fermata-attest serve → the escrow on the network
#
#   1. DELIVERED  the vendor answers 200 JSON → attestor verdict DELIVERED → settle → released.
#                 The presentation, downloaded from the attestor, re-verifies offline against the
#                 hashes on chain; and it cannot settle a second hold for the same request.
#   2. FAILED     the vendor answers an authenticated 500 → verdict FAILED → settle → refunded
#   3. NO PROOF   the vendor never answers → no transcript, no verdict → claim_timeout refund
#
#   scripts/attest-cases.sh                   # testnet (run scripts/deploy-testnet.sh first)
#   NETWORK=local scripts/attest-cases.sh     # a local quickstart network
#
# The vendors, the notary and the attestor run on this machine; only the escrow is on the network.
# The notary's key is generated for this run and kept in this script's memory; the three services
# this run registers pin its hash. The verifier key comes from the keystore (fermata-verifier), as
# in scripts/demo-cases.sh, and reaches the attestor through its environment.
#
# Ported from Fermata scripts/e2e-attest.sh and scripts/attest-e2e.ts @ d7cc642
# (github.com/bilgin-kocak/fermata).

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
TREASURY="$(d .escrow.treasury)"
AGENT="$(address_of agent)"
[ "$AGENT" = "$(d .accounts.agent)" ] || die "the keystore's $(key agent) is not the deployment's agent"
[ "$VENDOR" = "$(address_of vendor)" ] || die "the keystore's $(key vendor) is not the deployment's vendor"
[ "$(d .network_passphrase)" = "$PASSPHRASE" ] || die "deployment is for another network"

NEEDED=$((4 * PRICE))
HAVE="$(balance "$AGENT")"
if [ "$HAVE" -lt "$NEEDED" ]; then
  die "the agent holds $HAVE of the $NEEDED base units needed (4 holds); fund $AGENT (USDC: $USDC_FAUCET)"
fi

OK_PORT="${OK_PORT:-8643}"
E500_PORT="${E500_PORT:-8644}"
HANG_PORT="${HANG_PORT:-8645}"
NOTARY_PORT="${NOTARY_PORT:-7147}"
ATTESTOR_PORT="${ATTESTOR_PORT:-7148}"
ATTESTOR="http://127.0.0.1:$ATTESTOR_PORT"
TARGET="/v1/quote?symbol=BTC-USD"
PREDICATE_FILE="$ROOT/predicates/quote-v1.json"
LOGS="$OUT_DIR/attest-cases-$NETWORK"
STATUS_NAMES=([1]=Held [2]=Released [3]=Refunded [4]=TimedOut)
RESULTS=()
FAILURES=0

[ -x "$FV" ] || (cd "$ROOT" && cargo build --quiet --release -p fermata-verdict)
build_attestor
CA="$ROOT/apps/vendor/certs/ca.pem"
[ -f "$CA" ] || bash "$ROOT/apps/vendor/gen-certs.sh" >/dev/null
rm -rf "$LOGS"
mkdir -p "$LOGS/downloads"

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
wait_port() {
  local _
  for _ in $(seq 100); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
    sleep 0.1
  done
  die "nothing listening on port $1 (see $LOGS)"
}
api() { curl -sS --noproxy '*' "$@"; }

log "escrow $ESCROW on $NETWORK, price $PRICE, window ${WINDOW}s"
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
HEALTH="$(api "$ATTESTOR/healthz")"
[ "$(jq -r .signerKey <<<"$HEALTH")" = "$VERIFIER_KEY" ] ||
  die "the attestor signs with $(jq -r .signerKey <<<"$HEALTH"), the deployment's verifier is $VERIFIER_KEY"
log "attestor ready: signer $(jq -r .signer <<<"$HEALTH"), notary key hash $NOTARY_KEY_HASH"

check() { # case description expected actual
  if [ "$3" = "$4" ]; then
    log "  ok    $2"
  else
    log "  FAIL  $2: expected $3, got $4"
    FAILURES=$((FAILURES + 1))
  fi
}

new_call() { openssl rand -hex 32; }

status_of() {
  local s
  s="$(view "$ESCROW" get_hold --call_id "$1" | jq -r .status)"
  printf '%s' "${STATUS_NAMES[$s]:-$s}"
}

# register PORT: a service for the vendor on PORT, pinning this run's notary. Prints its id.
SUFFIX="$(openssl rand -hex 2)"
PREDICATE_HASH="$("$FV" predicate-hash "$PREDICATE_FILE")"
register() { # name port
  local label_hex sid
  label_hex="$("$FV" label "$1-$SUFFIX")"
  invoke vendor register_service --owner "$VENDOR" --label "$label_hex" --payout "$VENDOR" \
    --token "$TOKEN_SAC" --price_per_call "$PRICE" --settlement_window "$WINDOW" \
    --verifier "$VERIFIER_KEY" --predicate_hash "$PREDICATE_HASH" \
    --origin_hash "$("$FV" origin-hash "https://vendor.fermata.test:$2")" \
    --notary_key_hash "$NOTARY_KEY_HASH"
  sid="$(jq -r . <<<"$OUT")"
  [ "$sid" = "$("$FV" service-id --owner "$VENDOR" --label "$1-$SUFFIX")" ] ||
    die "the contract's service id differs from fermata-verdict's derivation"
  log "  registered $1-$SUFFIX → $sid"
  printf '%s' "$sid"
}

hold() { # service_id call_id
  invoke agent hold --agent "$AGENT" --call_id "$2" --service_id "$1" \
    --request_hash "$("$FV" request-hash --service-id "$1" --method GET --target "$TARGET" --body "")"
  HOLD_TX="$LAST_TX"
}

# attest CALL PORT: asks the attestor to prove the call and sign. Sets ATTEST_JSON, ATTEST_HTTP.
SECRET="Bearer e2e-$(openssl rand -hex 12)"
attest() {
  local body
  body="$(jq -nc --arg call "$1" --arg url "https://vendor.fermata.test:$2$TARGET" --arg auth "$SECRET" \
    '{callId: $call, url: $url, method: "GET", headers: {accept: "application/json", authorization: $auth}}')"
  ATTEST_JSON="$(api -o - -w '\n%{http_code}' -X POST -H 'content-type: application/json' \
    --data "$body" "$ATTESTOR/v1/attest")"
  ATTEST_HTTP="${ATTEST_JSON##*$'\n'}"
  ATTEST_JSON="${ATTEST_JSON%$'\n'*}"
}

settle() { # call_id (with ATTEST_JSON)
  invoke relayer settle --call_id "$1" --verdict "$(jq -c .verdict.verdict <<<"$ATTEST_JSON")" \
    --signature "$(jq -r .verdict.signature <<<"$ATTEST_JSON")"
  SETTLE_TX="$LAST_TX"
}

event_param() { # from_ledger event_name call_id param
  stellar events "${NET[@]}" --id "$ESCROW" --start-ledger "$1" --count 100 \
    --output json 2>/dev/null |
    jq -r --arg name "$2" --arg call "$3" --arg p "$4" \
      'select(.event_name == $name and .params.call_id == $call) | .params[$p]' | head -1
}

record() { # case name status hold_tx final_tx call_id presentation_hash
  RESULTS+=("$(jq -n --arg case "$1" --arg name "$2" --arg status "$3" --arg hold "$4" \
    --arg final "$5" --arg call "$6" --arg presentation "$7" \
    '{case: $case, name: $name, status: $status, call_id: $call, hold_tx: $hold,
      final_tx: $final, presentation_hash: $presentation}')")
}

log ""
log "registering three services for this run's notary"
SID_OK="$(register ok "$OK_PORT")"
SID_500="$(register e500 "$E500_PORT")"
SID_HANG="$(register hang "$HANG_PORT")"
FEE=$((PRICE * $(d .escrow.fee_bps) / 10000))

log ""
log "case 1: verified delivery → release (the vendor answers 200)"
CALL_OK="$(new_call)"
payout_before="$(balance "$VENDOR")"
treasury_before="$(balance "$TREASURY")"
hold "$SID_OK" "$CALL_OK"
HOLD_OK_TX="$HOLD_TX"
attest "$CALL_OK" "$OK_PORT"
check 1 "attestor answers" 200 "$ATTEST_HTTP"
check 1 "verdict" DELIVERED "$(jq -r .verdict.outcome <<<"$ATTEST_JSON")"
check 1 "the attestor returns the proved response" 200 "$(jq -r .response.status <<<"$ATTEST_JSON")"
PRESENTATION_HASH="$(jq -r .presentationHash <<<"$ATTEST_JSON")"
FROM_LEDGER="$(latest_ledger)"
settle "$CALL_OK"
check 1 "vendor paid price − fee" "$((payout_before + PRICE - FEE))" "$(balance "$VENDOR")"
check 1 "treasury paid the fee" "$((treasury_before + FEE))" "$(balance "$TREASURY")"
STATUS="$(status_of "$CALL_OK")"
check 1 "status" Released "$STATUS"
check 1 "the released event carries the presentation hash" "$PRESENTATION_HASH" \
  "$(event_param "$FROM_LEDGER" Released "$CALL_OK" presentation_hash)"
record 1 "release (DELIVERED)" "$STATUS" "$HOLD_OK_TX" "$SETTLE_TX" "$CALL_OK" "$PRESENTATION_HASH"

log "  re-verifying the downloaded presentation offline, against the chain"
PROOF="$LOGS/downloads/$CALL_OK.tlsn"
api -o "$PROOF" "$ATTESTOR/v1/presentations/$CALL_OK"
SERVICE_JSON="$(view "$ESCROW" get_service --service_id "$SID_OK")"
HOLD_JSON="$(view "$ESCROW" get_hold --call_id "$CALL_OK")"
OFFLINE="$("$ATTEST" verify --offline --presentation "$PROOF" --ca "$CA" --call-id "$CALL_OK" \
  --predicate "$PREDICATE_FILE" --service-id "$SID_OK" \
  --request-hash "$(jq -r .request_hash <<<"$HOLD_JSON")" \
  --origin-hash "$(jq -r .origin_hash <<<"$SERVICE_JSON")" \
  --notary-key-hash "$(jq -r .notary_key_hash <<<"$SERVICE_JSON")" 2>"$LOGS/offline.log" || true)"
OFFLINE="${OFFLINE:-"{}"}"
check 1 "offline: no mismatch with the chain" true "$(jq -r .ok <<<"$OFFLINE")"
check 1 "offline: same outcome" DELIVERED "$(jq -r .outcome <<<"$OFFLINE")"
check 1 "offline: the downloaded file is the presentation on chain" "$PRESENTATION_HASH" \
  "$(jq -r .presentationHash <<<"$OFFLINE")"
if grep -qF "${SECRET#Bearer }" "$PROOF"; then leaked=yes; else leaked=no; fi
check 1 "the Authorization value is not in the public presentation" no "$leaked"

log "  replay: the same presentation for a new hold of the same request"
CALL_REPLAY="$(new_call)"
hold "$SID_OK" "$CALL_REPLAY"
HOLD_REPLAY_TX="$HOLD_TX"
replay_err="$(FERMATA_VERIFIER_SECRET="$(verifier_secret)" "$ATTEST" verify "${attestor_args[@]}" \
  --presentation "$PROOF" --ca "$CA" --call-id "$CALL_REPLAY" --predicate "$ROOT/predicates" \
  2>&1 >/dev/null || true)"
if grep -q "Call check failed" <<<"$replay_err"; then replay=refused; else replay="signed?"; fi
check 1 "an old proof cannot settle a new hold (Call check)" refused "$replay"

log ""
log "case 2: verified failure → refund (the vendor answers an authenticated 500)"
CALL_500="$(new_call)"
agent_before="$(balance "$AGENT")"
hold "$SID_500" "$CALL_500"
HOLD_500_TX="$HOLD_TX"
attest "$CALL_500" "$E500_PORT"
check 2 "attestor answers" 200 "$ATTEST_HTTP"
check 2 "verdict" FAILED "$(jq -r .verdict.outcome <<<"$ATTEST_JSON")"
log "  failures: $(jq -r '.verdict.failures | join("; ")' <<<"$ATTEST_JSON")"
PRESENTATION_500="$(jq -r .presentationHash <<<"$ATTEST_JSON")"
FROM_LEDGER="$(latest_ledger)"
settle "$CALL_500"
check 2 "agent refunded in full" "$agent_before" "$(balance "$AGENT")"
STATUS="$(status_of "$CALL_500")"
check 2 "status" Refunded "$STATUS"
check 2 "the refunded event carries the presentation hash" "$PRESENTATION_500" \
  "$(event_param "$FROM_LEDGER" Refunded "$CALL_500" presentation_hash)"
record 2 "refund (FAILED)" "$STATUS" "$HOLD_500_TX" "$SETTLE_TX" "$CALL_500" "$PRESENTATION_500"

log ""
log "case 3: no proof → timeout refund (the vendor never answers)"
CALL_HANG="$(new_call)"
agent_before="$(balance "$AGENT")"
hold "$SID_HANG" "$CALL_HANG"
HOLD_HANG_TX="$HOLD_TX"
attest "$CALL_HANG" "$HANG_PORT"
check 3 "attestor refuses: no transcript, no verdict" "502 no-transcript null" \
  "$ATTEST_HTTP $(jq -r '.error' <<<"$ATTEST_JSON") $(jq -r '.verdict' <<<"$ATTEST_JSON")"
if view "$ESCROW" claim_timeout --call_id "$CALL_HANG" >/dev/null; then
  check 3 "claim_timeout refused inside the window" refused accepted
else
  check 3 "claim_timeout refused inside the window" refused refused
fi
log "  waiting for the ${WINDOW}s settlement window to close (ledger time)…"
deadline=$((SECONDS + WINDOW + 300))
until view "$ESCROW" claim_timeout --call_id "$CALL_HANG" >/dev/null; do
  [ "$SECONDS" -lt "$deadline" ] || die "the window did not close in time"
  sleep 5
done
invoke relayer claim_timeout --call_id "$CALL_HANG"
CLAIM_TX="$LAST_TX"
check 3 "agent refunded in full" "$agent_before" "$(balance "$AGENT")"
STATUS="$(status_of "$CALL_HANG")"
check 3 "status" TimedOut "$STATUS"
record 3 "timeout refund (no proof)" "$STATUS" "$HOLD_HANG_TX" "$CLAIM_TX" "$CALL_HANG" ""

invoke relayer claim_timeout --call_id "$CALL_REPLAY"
check 1 "the replayed hold ends by timeout" TimedOut "$(status_of "$CALL_REPLAY")"

REPORT="$OUT_DIR/attest-cases-$NETWORK.json"
printf '%s\n' "${RESULTS[@]}" | jq -s --arg escrow "$ESCROW" --arg network "$NETWORK" \
  --arg explorer "$EXPLORER" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg replay_hold "$HOLD_REPLAY_TX" --arg notary_key_hash "$NOTARY_KEY_HASH" \
  --arg services "$SID_OK $SID_500 $SID_HANG" \
  '{network: $network, escrow: $escrow, explorer: $explorer, ran_at: $at,
    notary_key_hash: $notary_key_hash, services: ($services | split(" ")),
    replay_hold_tx: $replay_hold, cases: .}' >"$REPORT"

printf '\n%-28s %-9s %s\n' "case" "status" "transactions"
for r in "${RESULTS[@]}"; do
  printf '%-28s %-9s hold   %s\n' "$(jq -r '"\(.case) \(.name)"' <<<"$r")" \
    "$(jq -r .status <<<"$r")" "$(tx_link "$(jq -r .hold_tx <<<"$r")")"
  printf '%-28s %-9s final  %s\n' "" "" "$(tx_link "$(jq -r .final_tx <<<"$r")")"
done
printf '\nescrow %s\nreport %s\n' "$(contract_link "$ESCROW")" "${REPORT#"$ROOT"/}"

if [ "$FAILURES" -ne 0 ]; then
  die "$FAILURES check(s) failed"
fi
printf '3/3 PASS (real TLSNotary proofs; offline re-verification and replay checks passed)\n'
