#!/usr/bin/env bash
# Runs Fermata's three canonical cases against the deployment in deployments/<network>.json and
# prints a link for every transaction:
#
#   1. verified delivery → release   hold, DELIVERED verdict, vendor paid price − fee, treasury fee
#   2. verified failure  → refund    hold, FAILED verdict, agent refunded in full
#   3. no verdict        → timeout   hold, claim_timeout refused inside the window, then accepted
#
#   scripts/demo-cases.sh                   # testnet
#   NETWORK=local scripts/demo-cases.sh     # a local quickstart network
#
# Milestone 0: verdicts are signed directly with the verifier key (fermata-verdict); there is no
# TLSNotary proof yet, so the presentation and response hashes are labelled placeholders. The
# attestor that proves the vendor's HTTPS response arrives in Milestone 1.

# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"
need stellar cargo jq openssl

[ -f "$DEPLOYMENT" ] || die "no ${DEPLOYMENT#"$ROOT"/}; run scripts/deploy-testnet.sh first"
[ -x "$FV" ] || (cd "$ROOT" && cargo build --quiet --release -p fermata-verdict)

d() { jq -r "$1" "$DEPLOYMENT"; }
ESCROW="$(d .escrow.contract_id)"
TOKEN_SAC="$(d .token.sac)"
SERVICE_ID="$(d .service.id)"
PRICE="$(d .service.price_per_call)"
WINDOW="$(d .service.settlement_window)"
PAYOUT="$(d .service.payout)"
PREDICATE_HASH="$(d .service.predicate_hash)"
TREASURY="$(d .escrow.treasury)"
AGENT="$(address_of agent)"
[ "$AGENT" = "$(d .accounts.agent)" ] || die "the keystore's $(key agent) is not the deployment's agent"
[ "$(d .network_passphrase)" = "$PASSPHRASE" ] || die "deployment is for another network"

NEEDED=$((3 * PRICE))
HAVE="$(balance "$AGENT")"
if [ "$HAVE" -lt "$NEEDED" ]; then
  die "the agent holds $HAVE of the $NEEDED base units needed; fund $AGENT (USDC: $USDC_FAUCET)"
fi

TARGET="/v1/quote?symbol=BTC-USD"
STATUS_NAMES=([1]=Held [2]=Released [3]=Refunded [4]=TimedOut)
RESULTS=()
FAILURES=0

new_call() { openssl rand -hex 32; }

placeholder() { printf 'fermata-stellar M0 placeholder %s: no TLSNotary proof for call %s' "$1" "$2" | sha256_hex; }

status_of() {
  local s
  s="$(view "$ESCROW" get_hold --call_id "$1" | jq -r .status)"
  printf '%s' "${STATUS_NAMES[$s]:-$s}"
}

hold() {
  REQUEST_HASH="$("$FV" request-hash --service-id "$SERVICE_ID" --method GET --target "$TARGET" --body "")"
  invoke agent hold --agent "$AGENT" --call_id "$1" --service_id "$SERVICE_ID" \
    --request_hash "$REQUEST_HASH"
  HOLD_TX="$LAST_TX"
}

settle() { # call_id outcome
  local signed verdict signature
  signed="$(FERMATA_VERIFIER_SECRET="$(verifier_secret)" "$FV" sign \
    --network-passphrase "$PASSPHRASE" --contract "$ESCROW" \
    --call-id "$1" --service-id "$SERVICE_ID" --request-hash "$REQUEST_HASH" \
    --predicate-hash "$PREDICATE_HASH" --outcome "$2" \
    --presentation-hash "$(placeholder presentation "$1")" \
    --response-hash "$(placeholder response "$1")")"
  verdict="$(jq -c .verdict <<<"$signed")"
  signature="$(jq -r .signature <<<"$signed")"
  invoke relayer settle --call_id "$1" --verdict "$verdict" --signature "$signature"
  SETTLE_TX="$LAST_TX"
}

check() { # case description expected actual
  if [ "$3" = "$4" ]; then
    log "  ok    $2"
  else
    log "  FAIL  $2: expected $3, got $4"
    FAILURES=$((FAILURES + 1))
  fi
}

record() { # case name status hold_tx final_tx
  RESULTS+=("$(jq -n --arg case "$1" --arg name "$2" --arg status "$3" \
    --arg hold "$4" --arg final "$5" --arg call "$6" \
    '{case: $case, name: $name, status: $status, call_id: $call, hold_tx: $hold, final_tx: $final}')")
}

log "escrow $ESCROW on $NETWORK, service $SERVICE_ID, price $PRICE, window ${WINDOW}s"
FEE=$((PRICE * $(d .escrow.fee_bps) / 10000))

log ""
log "case 1: verified delivery → release"
CALL="$(new_call)"
payout_before="$(balance "$PAYOUT")"
treasury_before="$(balance "$TREASURY")"
hold "$CALL"
settle "$CALL" delivered
check 1 "vendor paid price − fee" "$((payout_before + PRICE - FEE))" "$(balance "$PAYOUT")"
check 1 "treasury paid the fee" "$((treasury_before + FEE))" "$(balance "$TREASURY")"
STATUS="$(status_of "$CALL")"
check 1 "status" Released "$STATUS"
record 1 "release (DELIVERED)" "$STATUS" "$HOLD_TX" "$SETTLE_TX" "$CALL"

log ""
log "case 2: verified failure → refund"
CALL="$(new_call)"
agent_before="$(balance "$AGENT")"
hold "$CALL"
settle "$CALL" failed
check 2 "agent refunded in full" "$agent_before" "$(balance "$AGENT")"
STATUS="$(status_of "$CALL")"
check 2 "status" Refunded "$STATUS"
record 2 "refund (FAILED)" "$STATUS" "$HOLD_TX" "$SETTLE_TX" "$CALL"

log ""
log "case 3: no verdict → timeout refund"
CALL="$(new_call)"
agent_before="$(balance "$AGENT")"
hold "$CALL"
if view "$ESCROW" claim_timeout --call_id "$CALL" >/dev/null; then
  check 3 "claim_timeout refused inside the window" refused accepted
else
  check 3 "claim_timeout refused inside the window" refused refused
fi
log "  waiting for the ${WINDOW}s settlement window to close (ledger time)…"
deadline=$((SECONDS + WINDOW + 300))
until view "$ESCROW" claim_timeout --call_id "$CALL" >/dev/null; do
  [ "$SECONDS" -lt "$deadline" ] || die "the window did not close in time"
  sleep 5
done
invoke relayer claim_timeout --call_id "$CALL"
CLAIM_TX="$LAST_TX"
check 3 "agent refunded in full" "$agent_before" "$(balance "$AGENT")"
STATUS="$(status_of "$CALL")"
check 3 "status" TimedOut "$STATUS"
record 3 "timeout refund" "$STATUS" "$HOLD_TX" "$CLAIM_TX" "$CALL"

mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/demo-cases-$NETWORK.json"
printf '%s\n' "${RESULTS[@]}" | jq -s --arg escrow "$ESCROW" --arg network "$NETWORK" \
  --arg explorer "$EXPLORER" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{network: $network, escrow: $escrow, explorer: $explorer, ran_at: $at, cases: .}' >"$REPORT"

printf '\n%-24s %-9s %s\n' "case" "status" "transactions"
for r in "${RESULTS[@]}"; do
  printf '%-24s %-9s hold   %s\n' "$(jq -r '"\(.case) \(.name)"' <<<"$r")" \
    "$(jq -r .status <<<"$r")" "$(tx_link "$(jq -r .hold_tx <<<"$r")")"
  printf '%-24s %-9s final  %s\n' "" "" "$(tx_link "$(jq -r .final_tx <<<"$r")")"
done
printf '\nescrow %s\nreport %s\n' "$(contract_link "$ESCROW")" "${REPORT#"$ROOT"/}"

if [ "$FAILURES" -ne 0 ]; then
  die "$FAILURES check(s) failed"
fi
printf '3/3 PASS\n'
