#!/usr/bin/env bash
# Deploys the Fermata escrow to Stellar testnet, registers a demo service and writes
# deployments/<network>.json.
#
#   scripts/deploy-testnet.sh                  # testnet, Circle's testnet USDC
#   TOKEN=test scripts/deploy-testnet.sh       # testnet, a self-issued FERMATATEST asset
#   NETWORK=local scripts/deploy-testnet.sh    # a local quickstart network (FERMATATEST)
#
# Needs the Stellar CLI (25.2 or newer), cargo with the pinned toolchain, jq and openssl.
# Identities are created in the Stellar CLI keystore as fermata-<role> (KEY_PREFIX changes the
# prefix) and funded with Friendbot. Every run deploys a new escrow and overwrites the file.
#
# With TOKEN=usdc, the agent needs testnet USDC from Circle's faucet (a web form with a captcha,
# so it cannot be scripted). The script adds the trustlines and tells you what to do.

# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"
need stellar cargo jq openssl

if [ "$NETWORK" = local ]; then TOKEN="${TOKEN:-test}"; else TOKEN="${TOKEN:-usdc}"; fi
PRICE="${PRICE:-100000}"   # 0.01 of a 7-decimal asset
WINDOW="${WINDOW:-120}"    # settlement window, seconds
FEE_BPS="${FEE_BPS:-50}"   # 0.5 %
LABEL="${LABEL:-quote}"
# Pinned for Milestone 1, when the attestor proves the demo vendor (Fermata's apps/vendor) over
# TLSNotary. In Milestone 0 nothing checks them: verdicts are signed directly by the verifier key.
ORIGIN="${ORIGIN:-https://vendor.fermata.test:8443}"
NOTARY_KEY_HASH="${NOTARY_KEY_HASH:-0000000000000000000000000000000000000000000000000000000000000000}"
TEST_FUNDS=1000000000      # 100 FERMATATEST to the agent

build_tools

log "identities on $NETWORK"
for role in owner treasury vendor agent relayer; do ensure_key "$role" fund; done
ensure_key verifier # signs verdicts only: never funded, never signs a transaction
OWNER="$(address_of owner)"
TREASURY="$(address_of treasury)"
VENDOR="$(address_of vendor)"
AGENT="$(address_of agent)"
RELAYER="$(address_of relayer)"

log "token: $TOKEN"
case "$TOKEN" in
usdc)
  [ "$NETWORK" = testnet ] || die "TOKEN=usdc exists only on testnet; use TOKEN=test"
  ASSET="$USDC_ASSET"
  ;;
test)
  ensure_key issuer fund
  ASSET="$TEST_ASSET_CODE:$(address_of issuer)"
  ;;
*) die "TOKEN must be usdc or test, got '$TOKEN'" ;;
esac
TOKEN_SAC="$(stellar contract id asset --asset "$ASSET" "${NET[@]}")"
if ! view "$TOKEN_SAC" decimals >/dev/null; then
  log "  deploying the Stellar Asset Contract for $ASSET"
  submit stellar contract asset deploy --asset "$ASSET" --source "$(key owner)" "${NET[@]}"
fi
# Classic accounts hold an issued asset only through a trustline: the agent pays, the vendor
# (the demo service's payout) and the treasury receive.
for role in agent vendor treasury; do
  submit stellar tx new change-trust --source "$(key "$role")" --line "$ASSET" "${NET[@]}"
done
if [ "$TOKEN" = test ]; then
  submit stellar tx new payment --source "$(key issuer)" --destination "$AGENT" \
    --asset "$ASSET" --amount "$TEST_FUNDS" "${NET[@]}"
fi

log "deploying the escrow (fee $FEE_BPS bps)"
submit stellar contract deploy --wasm "$WASM" --source "$(key owner)" "${NET[@]}" \
  -- --owner "$OWNER" --treasury "$TREASURY" --fee_bps "$FEE_BPS"
ESCROW="$OUT"
DEPLOY_TX="$LAST_TX"
WASM_HASH="$(sha256_hex <"$WASM")"

log "registering the demo service '$LABEL'"
VERIFIER_JSON="$(FERMATA_VERIFIER_SECRET="$(verifier_secret)" "$FV" pubkey)"
VERIFIER_KEY="$(jq -r .public_key <<<"$VERIFIER_JSON")"
VERIFIER_ADDRESS="$(jq -r .address <<<"$VERIFIER_JSON")"
LABEL_HEX="$("$FV" label "$LABEL")"
PREDICATE_FILE="predicates/quote-v1.json"
PREDICATE_HASH="$("$FV" predicate-hash "$ROOT/$PREDICATE_FILE")"
ORIGIN_HASH="$("$FV" origin-hash "$ORIGIN")"
invoke vendor register_service --owner "$VENDOR" --label "$LABEL_HEX" --payout "$VENDOR" \
  --token "$TOKEN_SAC" --price_per_call "$PRICE" --settlement_window "$WINDOW" \
  --verifier "$VERIFIER_KEY" --predicate_hash "$PREDICATE_HASH" --origin_hash "$ORIGIN_HASH" \
  --notary_key_hash "$NOTARY_KEY_HASH"
SERVICE_ID="$(jq -r . <<<"$OUT")"
REGISTER_TX="$LAST_TX"
[ "$SERVICE_ID" = "$("$FV" service-id --owner "$VENDOR" --label "$LABEL")" ] ||
  die "the contract's service id differs from fermata-verdict's derivation"

mkdir -p "$(dirname "$DEPLOYMENT")"
jq -n \
  --arg network "$NETWORK" --arg passphrase "$PASSPHRASE" --arg explorer "$EXPLORER" \
  --arg escrow "$ESCROW" --arg wasm_hash "$WASM_HASH" --arg deploy_tx "$DEPLOY_TX" \
  --arg deploy_ledger "$(tx_ledger "$DEPLOY_TX")" \
  --arg owner "$OWNER" --arg treasury "$TREASURY" --argjson fee_bps "$FEE_BPS" \
  --arg token_mode "$TOKEN" --arg asset "$ASSET" --arg sac "$TOKEN_SAC" \
  --arg service_id "$SERVICE_ID" --arg vendor "$VENDOR" --arg label "$LABEL" \
  --argjson price "$PRICE" --argjson window "$WINDOW" \
  --arg verifier "$VERIFIER_KEY" --arg verifier_address "$VERIFIER_ADDRESS" \
  --arg predicate_hash "$PREDICATE_HASH" --arg predicate_file "$PREDICATE_FILE" \
  --arg origin "$ORIGIN" --arg origin_hash "$ORIGIN_HASH" \
  --arg notary_key_hash "$NOTARY_KEY_HASH" --arg register_tx "$REGISTER_TX" \
  --arg agent "$AGENT" --arg relayer "$RELAYER" \
  --arg commit "$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)" \
  --arg deployed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    network: $network, network_passphrase: $passphrase, explorer: $explorer,
    escrow: {contract_id: $escrow, wasm_hash: $wasm_hash, deploy_tx: $deploy_tx,
             deploy_ledger: ($deploy_ledger | tonumber? // null),
             owner: $owner, treasury: $treasury, fee_bps: $fee_bps},
    token: {mode: $token_mode, asset: $asset, sac: $sac, decimals: 7},
    service: {id: $service_id, owner: $vendor, label: $label, payout: $vendor,
              price_per_call: $price, settlement_window: $window,
              verifier: $verifier, verifier_address: $verifier_address,
              predicate_hash: $predicate_hash, predicate_file: $predicate_file,
              origin: $origin, origin_hash: $origin_hash, notary_key_hash: $notary_key_hash,
              register_tx: $register_tx},
    accounts: {agent: $agent, relayer: $relayer},
    source_commit: $commit, deployed_at: $deployed_at
  }' >"$DEPLOYMENT"

log ""
log "escrow     $(contract_link "$ESCROW")"
log "deploy tx  $(tx_link "$DEPLOY_TX")"
log "service    $SERVICE_ID ($(tx_link "$REGISTER_TX"))"
log "token      $ASSET ($TOKEN_SAC)"
log "wrote      ${DEPLOYMENT#"$ROOT"/}"

NEEDED=$((3 * PRICE))
HAVE="$(balance "$AGENT")"
if [ "$HAVE" -lt "$NEEDED" ]; then
  log ""
  log "The agent holds $HAVE of the $NEEDED base units the three demo cases need."
  log "Get testnet USDC from $USDC_FAUCET (choose Stellar testnet) for:"
  log "  $AGENT"
  log "then run scripts/demo-cases.sh."
fi
