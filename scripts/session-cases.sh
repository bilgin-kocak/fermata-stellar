#!/usr/bin/env bash
# Runs the session cases (docs/session-escrow.md, phase 1: every call proved, k = 1) against the
# deployment in deployments/<network>.json and prints a link for every transaction:
#
#   1. open      the agent deposits 6 × price for the demo service; batches of up to 4 calls
#   2. batch 1   calls 1-3, DELIVERED, FAILED and UNANSWERED: the vendor is paid one call (price −
#                fee), the treasury the fee, and two calls go back to the agent
#   3. batch 2   call 4, DELIVERED
#   4. refused   a replayed batch, a statement by another key, a ticket by another key, entries
#                changed after signing and a non-zero seed: each is refused, nothing moves
#   5. cost      a batch of COST_CALLS calls (default 100), simulated and not sent: CPU instructions,
#                resource fee and transaction size on this network
#   6. close     refused before the deadline; after it, the calls not settled go back to the agent,
#                and a second close is refused
#
#   scripts/session-cases.sh                   # testnet
#   NETWORK=local scripts/session-cases.sh     # a local quickstart network
#   COST_CALLS=1000 scripts/session-cases.sh   # measure the largest batch (deposits 1,000 × price)
#
# As in demo-cases.sh, the verifier's statements are signed directly with its key (fermata-verdict)
# and the presentation and response hashes are labelled placeholders: no TLSNotary proof is made
# here. The agent's tickets are signed with its ticket key ($KEY_PREFIX-ticket in the keystore),
# which is not an account and never signs a transaction.

# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"
need stellar cargo jq openssl perl

[ -f "$DEPLOYMENT" ] || die "no ${DEPLOYMENT#"$ROOT"/}; run scripts/deploy-testnet.sh first"
[ -x "$FV" ] || (cd "$ROOT" && cargo build --quiet --release -p fermata-verdict)

d() { jq -r "$1" "$DEPLOYMENT"; }
SESSION="$(d '.session.contract_id // empty')"
[ -n "$SESSION" ] || die "the deployment has no session contract; run scripts/deploy-testnet.sh again"
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
ensure_key ticket
TICKET_KEY="$(FERMATA_TICKET_SECRET="$(ticket_secret)" "$FV" ticket-pubkey | jq -r .public_key)"

MAX_CALLS=6
BATCH=4
COST_CALLS="${COST_CALLS:-100}"
EXPIRES_IN="${EXPIRES_IN:-60}" # seconds of calls; batches are accepted for the window after that
ZERO=0000000000000000000000000000000000000000000000000000000000000000
NEEDED=$(((MAX_CALLS + COST_CALLS) * PRICE))
HAVE="$(balance "$AGENT")"
if [ "$HAVE" -lt "$NEEDED" ]; then
  die "the agent holds $HAVE of the $NEEDED base units needed; fund $AGENT (USDC: $USDC_FAUCET)"
fi

STATUS_NAMES=([1]=Open [2]=Closed)
FAILURES=0
TXS=()

check() { # description expected actual
  if [ "$2" = "$3" ]; then
    log "  ok    $1"
  else
    log "  FAIL  $1: expected $2, got $3"
    FAILURES=$((FAILURES + 1))
  fi
}

record() { TXS+=("$(jq -nc --arg step "$1" --arg tx "$2" '{step: $step, tx: $tx}')"); }

now() { rpc getLatestLedger '{}' | jq -r .closeTime; }

session_field() { view "$SESSION" get_session --session_id "$1" | jq -r ".$2"; }

placeholder() { printf 'fermata-stellar session placeholder %s: no TLSNotary proof for call %s' "$1" "$2" | sha256_hex; }

call_id() { "$FV" session-call-id --contract "$SESSION" --session-id "$1" --n "$2"; }

request_hash() { # session n
  "$FV" request-hash --service-id "$SERVICE_ID" --method GET \
    --target "/v1/quote?symbol=BTC-USD&session=$1&call=$2" --body ""
}

# entry RESULT SESSION N: one entry as JSON; proved results carry placeholder hashes.
entry() {
  local presentation="$ZERO" response="$ZERO" id
  if [ "$1" -le 2 ]; then
    id="$(call_id "$2" "$3")"
    presentation="$(placeholder presentation "$id")"
    response="$(placeholder response "$id")"
  fi
  jq -nc --argjson r "$1" --arg p "$presentation" --arg s "$response" \
    '{result: $r, presentation_hash: $p, response_hash: $s}'
}

# The entries as the contract takes them: each result as a big-endian u32, then the two hashes.
entries_hex() { jq -r '.[] | ("0000000" + (.result | tostring))[-8:] + .presentation_hash + .response_hash' | tr -d '\n'; }

open_session() { # session max_calls batch_size expires_at
  invoke_at "$SESSION" agent open_session --agent "$AGENT" --session_id "$1" \
    --service_id "$SERVICE_ID" --max_calls "$2" --ticket_key "$TICKET_KEY" --sample_k 1 \
    --batch_size "$3" --seed "$ZERO" --expires_at "$4"
}

# batch SESSION FROM RESULTS...: builds the batch of calls FROM+1.. with these results, the
# ticket for its last call and the verifier's statement. Sets the B_* variables.
batch() {
  local session="$1" from="$2" n entries=() requests=()
  shift 2
  B_TO=$((from + $#))
  for ((n = from + 1; n <= B_TO; n++)); do
    requests+=("$(request_hash "$session" "$n")")
    entries+=("$(entry "$1" "$session" "$n")")
    shift
  done
  B_CHAIN="$("$FV" chain --from "$(session_field "$session" chain)" --request-hash "${requests[@]}")"
  B_REQUESTS="$(printf '%s' "${requests[@]}")"
  B_ENTRIES_JSON="$(printf '%s\n' "${entries[@]}" | jq -sc .)"
  B_ENTRIES="$(entries_hex <<<"$B_ENTRIES_JSON")"
  B_TICKET="$(FERMATA_TICKET_SECRET="$(ticket_secret)" "$FV" ticket --network-passphrase "$PASSPHRASE" \
    --contract "$SESSION" --session-id "$session" --n "$B_TO" --chain "$B_CHAIN" | jq -r .signature)"
  B_STATEMENT="$(sign_statement "$(verifier_secret)" "$session" "$from" "$B_TO" "$B_CHAIN" "$B_ENTRIES_JSON")"
  B_SEED="$ZERO"
}

sign_statement() { # secret session from to chain entries_json
  FERMATA_VERIFIER_SECRET="$1" "$FV" statement --network-passphrase "$PASSPHRASE" \
    --contract "$SESSION" --session-id "$2" --service-id "$SERVICE_ID" \
    --predicate-hash "$PREDICATE_HASH" --from "$3" --to "$4" --chain "$5" --entries "$6" |
    jq -r .signature
}

batch_args() { # session
  printf '%s\n' settle_batch --session_id "$1" --to "$B_TO" --request_hashes "$B_REQUESTS" \
    --ticket "$B_TICKET" --seed "$B_SEED" --entries "$B_ENTRIES" --statement "$B_STATEMENT"
}

settle() { # session
  local args
  mapfile -t args < <(batch_args "$1")
  invoke_at "$SESSION" relayer "${args[@]}"
}

# refused DESCRIPTION PATTERN FN ARGS...: simulates a call to the session contract and checks that
# it fails with an error matching PATTERN (a contract error code, or the host's crypto error).
refused() {
  local what="$1" pattern="$2" err
  shift 2
  err="$(mktemp)"
  if stellar contract invoke --id "$SESSION" --source "$(key relayer)" "${NET[@]}" --send=no \
    -- "$@" >/dev/null 2>"$err"; then
    check "$what" refused accepted
  elif grep -q "$pattern" "$err"; then
    check "$what" refused refused
  else
    cat "$err" >&2
    check "$what" "refused with $pattern" "another error"
  fi
  rm -f "$err"
}

refused_batch() { # description pattern session
  local args
  mapfile -t args < <(batch_args "$3")
  refused "$1" "$2" "${args[@]}"
}

FEE_BPS="$(view "$ESCROW" fee_bps | tr -d '"')"
FEE=$((PRICE * FEE_BPS / 10000))
log "session contract $SESSION on $NETWORK (escrow $ESCROW)"
log "service $SERVICE_ID, price $PRICE, fee $FEE_BPS bps, window ${WINDOW}s"

log ""
log "1: open a session of $MAX_CALLS calls, batches of up to $BATCH"
contract_before="$(balance "$SESSION")"
SID="$(openssl rand -hex 32)"
EXPIRES_AT=$(($(now) + EXPIRES_IN))
agent_before="$(balance "$AGENT")"
open_session "$SID" "$MAX_CALLS" "$BATCH" "$EXPIRES_AT"
record "open" "$LAST_TX"
check "the agent deposited $MAX_CALLS × price" "$((agent_before - MAX_CALLS * PRICE))" "$(balance "$AGENT")"
check "status" Open "${STATUS_NAMES[$(session_field "$SID" status)]}"
DEADLINE="$(session_field "$SID" deadline)"
check "deadline = expiry + window" "$((EXPIRES_AT + WINDOW))" "$DEADLINE"
if [ "$COST_CALLS" -gt 0 ]; then
  # Opened now so that it shares the deadline; step 5 simulates a batch on it.
  CID="$(openssl rand -hex 32)"
  open_session "$CID" "$COST_CALLS" "$COST_CALLS" "$EXPIRES_AT"
  record "open (cost session)" "$LAST_TX"
fi

log ""
log "2: batch 1, calls 1-3: DELIVERED, FAILED, UNANSWERED"
batch "$SID" 0 1 2 4
BATCH1=("$B_TO" "$B_REQUESTS" "$B_TICKET" "$B_ENTRIES" "$B_STATEMENT")
payout_before="$(balance "$PAYOUT")"
treasury_before="$(balance "$TREASURY")"
agent_before="$(balance "$AGENT")"
settle "$SID"
record "batch 1 (calls 1-3)" "$LAST_TX"
check "vendor paid one call, price − fee" "$((payout_before + PRICE - FEE))" "$(balance "$PAYOUT")"
check "treasury paid one fee" "$((treasury_before + FEE))" "$(balance "$TREASURY")"
check "agent refunded two calls" "$((agent_before + 2 * PRICE))" "$(balance "$AGENT")"
check "settled" 3 "$(session_field "$SID" settled)"
check "chain(3)" "$B_CHAIN" "$(session_field "$SID" chain)"

log ""
log "3: refusals (simulated; nothing is sent)"
# The settled batch again.
B_TO="${BATCH1[0]}" B_REQUESTS="${BATCH1[1]}" B_TICKET="${BATCH1[2]}" B_ENTRIES="${BATCH1[3]}" B_STATEMENT="${BATCH1[4]}"
refused_batch "a replayed batch (InvalidBatch)" 'Error(Contract, #207)' "$SID"
# Batch 2, made wrong in one way at a time.
batch "$SID" 3 1
GOOD_STATEMENT="$B_STATEMENT"
B_STATEMENT="$(sign_statement "$(openssl rand -hex 32)" "$SID" 3 4 "$B_CHAIN" "$B_ENTRIES_JSON")"
refused_batch "a statement signed by another key" 'Error(Crypto' "$SID"
B_STATEMENT="$GOOD_STATEMENT"
GOOD_TICKET="$B_TICKET"
B_TICKET="$(FERMATA_TICKET_SECRET="$(openssl rand -hex 32)" "$FV" ticket --network-passphrase "$PASSPHRASE" \
  --contract "$SESSION" --session-id "$SID" --n 4 --chain "$B_CHAIN" | jq -r .signature)"
refused_batch "a ticket signed by another key" 'Error(Crypto' "$SID"
B_TICKET="$GOOD_TICKET"
GOOD_ENTRIES="$B_ENTRIES"
B_ENTRIES="00000002${B_ENTRIES:8}"
refused_batch "DELIVERED changed to FAILED after signing" 'Error(Crypto' "$SID"
B_ENTRIES="$GOOD_ENTRIES"
B_SEED="$(openssl rand -hex 32)"
refused_batch "a seed with k = 1 (InvalidSeed)" 'Error(Contract, #209)' "$SID"
B_SEED="$ZERO"

log ""
log "4: batch 2, call 4: DELIVERED"
payout_before="$(balance "$PAYOUT")"
settle "$SID"
record "batch 2 (call 4)" "$LAST_TX"
check "vendor paid one call" "$((payout_before + PRICE - FEE))" "$(balance "$PAYOUT")"
check "settled" 4 "$(session_field "$SID" settled)"

COST=null
if [ "$COST_CALLS" -gt 0 ]; then
  log ""
  log "5: the cost of a batch of $COST_CALLS calls (simulated, not sent)"
  tmp="$(mktemp -d)"
  # Random request and placeholder hashes: what they are does not change the cost.
  openssl rand -hex $((32 * COST_CALLS)) | fold -w 64 >"$tmp/requests"
  openssl rand -hex $((64 * COST_CALLS)) | fold -w 128 |
    jq -R '{result: 1, presentation_hash: .[0:64], response_hash: .[64:128]}' | jq -s . >"$tmp/entries.json"
  mapfile -t requests <"$tmp/requests"
  chain="$("$FV" chain --from "$CID" --request-hash "${requests[@]}")"
  tr -d '\n' <"$tmp/requests" | perl -ne 'print pack("H*", $_)' >"$tmp/requests.bin"
  entries_hex <"$tmp/entries.json" | perl -ne 'print pack("H*", $_)' >"$tmp/entries.bin"
  ticket="$(FERMATA_TICKET_SECRET="$(ticket_secret)" "$FV" ticket --network-passphrase "$PASSPHRASE" \
    --contract "$SESSION" --session-id "$CID" --n "$COST_CALLS" --chain "$chain" | jq -r .signature)"
  statement="$(sign_statement "$(verifier_secret)" "$CID" 0 "$COST_CALLS" "$chain" "@$tmp/entries.json")"
  # A large batch's transaction is longer than one command-line argument may be, so it goes
  # through files.
  stellar contract invoke --id "$SESSION" --source "$(key relayer)" "${NET[@]}" --build-only \
    -- settle_batch --session_id "$CID" --to "$COST_CALLS" --request_hashes-file-path "$tmp/requests.bin" \
    --ticket "$ticket" --seed "$ZERO" --entries-file-path "$tmp/entries.bin" --statement "$statement" \
    >"$tmp/built.xdr"
  jq -Rc '{jsonrpc: "2.0", id: 1, method: "simulateTransaction", params: {transaction: .}}' \
    <"$tmp/built.xdr" >"$tmp/simulate.json"
  sim="$(curl -sS --noproxy localhost,127.0.0.1 -X POST -H 'content-type: application/json' \
    --data @"$tmp/simulate.json" "$RPC" | jq -c .result)"
  if [ "$(jq -r '.error // empty' <<<"$sim")" != "" ]; then
    log "  $(jq -r .error <<<"$sim")"
    check "a batch of $COST_CALLS calls simulates" ok failed
  else
    instructions="$(jq -r .transactionData <<<"$sim" |
      stellar xdr decode --type SorobanTransactionData --output json | jq -r .resources.instructions)"
    bytes="$(stellar tx simulate --source-account "$(key relayer)" "${NET[@]}" <"$tmp/built.xdr" |
      tr -d '\n' | base64 -d | wc -c | tr -d ' ')"
    COST="$(jq -nc --argjson calls "$COST_CALLS" --argjson instructions "$instructions" \
      --argjson fee "$(jq -r .minResourceFee <<<"$sim")" --argjson bytes "$bytes" \
      '{calls: $calls, instructions: $instructions, min_resource_fee: $fee, transaction_bytes_unsigned: $bytes}')"
    log "  $COST_CALLS calls: $instructions CPU instructions, resource fee $(jq -r .min_resource_fee <<<"$COST") stroops, $bytes bytes unsigned"
    check "a batch of $COST_CALLS calls simulates" ok ok
  fi
  rm -rf "$tmp"
fi

log ""
log "6: close"
refused "close before the deadline (WindowOpen)" 'Error(Contract, #206)' close_session --session_id "$SID"
log "  waiting for the deadline (ledger time ${DEADLINE})…"
wait_until=$((SECONDS + EXPIRES_IN + WINDOW + 300))
until [ "$(now)" -gt "$DEADLINE" ]; do
  [ "$SECONDS" -lt "$wait_until" ] || die "the deadline did not pass in time"
  sleep 5
done
agent_before="$(balance "$AGENT")"
invoke_at "$SESSION" relayer close_session --session_id "$SID"
record "close" "$LAST_TX"
check "agent refunded the 2 calls not made" "$((agent_before + 2 * PRICE))" "$(balance "$AGENT")"
check "status" Closed "${STATUS_NAMES[$(session_field "$SID" status)]}"
refused "a second close (NotOpen)" 'Error(Contract, #204)' close_session --session_id "$SID"
if [ "$COST_CALLS" -gt 0 ]; then
  agent_before="$(balance "$AGENT")"
  invoke_at "$SESSION" relayer close_session --session_id "$CID"
  record "close (cost session)" "$LAST_TX"
  check "cost session refunded in full" "$((agent_before + COST_CALLS * PRICE))" "$(balance "$AGENT")"
fi
check "the session contract's balance is back where it started" "$contract_before" "$(balance "$SESSION")"

mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/session-cases-$NETWORK.json"
printf '%s\n' "${TXS[@]}" | jq -s --arg session "$SESSION" --arg network "$NETWORK" \
  --arg explorer "$EXPLORER" --arg sid "$SID" --argjson cost "$COST" \
  --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{network: $network, session_contract: $session, session_id: $sid, explorer: $explorer,
    ran_at: $at, cost: $cost, transactions: .}' >"$REPORT"

printf '\n%-24s %s\n' "step" "transaction"
for t in "${TXS[@]}"; do
  printf '%-24s %s\n' "$(jq -r .step <<<"$t")" "$(tx_link "$(jq -r .tx <<<"$t")")"
done
printf '\nsession contract %s\nreport %s\n' "$(contract_link "$SESSION")" "${REPORT#"$ROOT"/}"

if [ "$FAILURES" -ne 0 ]; then
  die "$FAILURES check(s) failed"
fi
printf 'session cases PASS\n'
