# Porting notes: Fermata from Tempo to Stellar

This file records how Fermata's Tempo implementation maps onto Stellar: what is kept, adapted,
replaced or deferred, and why. It was written in Milestone 0, step 1, before any Stellar code.
Items marked **proposed** depend on the open decisions in section 7. Every intentional
difference from `FermataEscrow.sol` is listed in section 4.

## Sources

| Source | Version read |
|---|---|
| Fermata (Tempo) | `bilgin-kocak/fermata` `main` @ `d7cc642` (2026-10-08). It contains `claude/keen-maxwell-1ly15p` @ `86e86fc`. `contracts/` is identical on both; `apps/attestor` differs only in `chain.rs`, `http_raw.rs` and `prove.rs`. |
| WebProof | `bilgin-kocak/webproof-solana` @ `609a654` |
| Stellar Rust SDK | `soroban-sdk` 29.0.1 and `soroban-env-host` 29.0.1, sources read from crates.io |
| Stellar CLI | 28.1.0 (`c0f4d0d`), release binary |
| SDF agent skill | `stellar/stellar-dev-skill` @ `a17a93a` (smart-contracts, assets, agentic-payments) |

### How facts were checked

This build environment's egress policy refuses developers.stellar.org, stellar.expert, Circle's
docs and faucet, and the testnet RPC, Horizon and Friendbot hosts (HTTP 403 at CONNECT,
2026-10-13). Fermata's `docs/FACTS.md` records the same situation for Tempo's hosts. The facts
below come from the SDK and host sources, the CLI binary, SDF's skill, and web search where noted.

| Fact | Value | Source |
|---|---|---|
| Live protocol | 29 on testnet (since 2026-09-29) and mainnet (since 2026-10-01) | developers.stellar.org "Software Versions", via web search |
| SDK and protocol | The `soroban-sdk` major version tracks the protocol. 29.0.0 was tagged 2026-10-07; 29.0.1 (2026-10-13) only bumps the env crates. | `rs-soroban-sdk` tags and commit log; SDF skill |
| Ed25519 verification | `env.crypto().ed25519_verify(pk, msg, sig)` panics when verification fails; the host calls `verify_strict` | `soroban-sdk` `src/crypto.rs:154`; `soroban-env-host` `src/crypto/mod.rs:89` |
| Network id | `env.ledger().network_id()` = sha256(network passphrase); testnet: `cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472` | `soroban-sdk` `src/ledger.rs:102`; computed locally |
| Contract id bytes | `Address::to_payload()` returns `ContractIdHash(BytesN<32>)`; it sits behind the `hazmat-address` feature | `soroban-sdk` `src/address.rs:400` |
| Contract value types | No `u8`; the smallest unsigned integer is `u32` | `soroban-sdk-macros` `src/map_type.rs` |
| Token transfer | SEP-41 `transfer(from: Address, to: MuxedAddress, amount: i128)`; a failure traps, nothing returns `false` | `soroban-sdk` `src/token.rs:154` |
| Re-entrancy | The host rejects re-entry into a contract that is already on the call stack | SDF skill, `smart-contracts/security.md` |
| Archival | At TTL expiry, persistent entries are archived, not deleted. Since protocol 23 an archived entry in a transaction's read-write footprint is restored automatically. Anyone can extend any entry's TTL. | SDF skill, `smart-contracts/development.md` |
| TTL scale | About 5 s per ledger (17,280 per day). The maximum entry TTL on mainnet is about 3,110,400 ledgers (about 180 days); it is network-configured. | SDF skill, `smart-contracts/development.md` |
| Events | Events are not ledger state; RPC providers typically keep them for about 7 days | SDF skill, `smart-contracts/development.md` |
| Testnet | Reset quarterly (all state deleted); passphrase `Test SDF Network ; September 2015` | SDF skill, `smart-contracts/testing.md` |
| Testnet USDC | Issuer `GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5`, SAC `CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA`, 7 decimals | SDF skill, `agentic-payments/SKILL.md` lines 74 and 114. The SAC id was re-derived locally with `stellar contract id asset --network testnet`. Circle's "USDC contract addresses" page lists the same issuer (via web search). |
| Testnet USDC faucet | faucet.circle.com: a web form with a captcha, no API | SDF skill, `agentic-payments/SKILL.md` line 99 |

## 1. Component table

| Fermata (Tempo) | Decision | On Stellar | When | Reason |
|---|---|---|---|---|
| `contracts/src/FermataEscrow.sol` | adapt | `contracts/escrow` (Soroban) | M0 | Keeps the state machine, roles, fee, check order and events. The payment pull, signature scheme and storage change with the chain (section 4). |
| `contracts/test/FermataEscrow.t.sol` (41 unit + 2 fuzz) | adapt | Rust tests in `contracts/escrow` | M0 | Each case is ported, adapted, or marked not applicable with a reason (section 6). |
| `contracts/test/FermataEscrow.invariant.t.sol` | adapt | Randomized action sequences with ghost state (proptest) | M0 | Same three invariants and the non-vacuity check |
| `contracts/test/Vectors.t.sol`, `fixtures/verdict-vector.json` | replace | `test-vectors/`, asserted by the contract tests and by `fermata-verdict` | M0 | EIP-712/secp256k1 vectors become Ed25519 vectors over the same verdict field values. |
| `contracts/test/AttestVector.t.sol`, `fixtures/attest-vector.json` | defer | Regenerated by the ported attestor | M1 | Needs real TLSNotary presentations with verdicts signed for Stellar |
| `contracts/test-tempo/` (real TIP-20 precompile, TIP-403 registry) | replace | Unit tests run against the real Stellar Asset Contract (SAC) code in the soroban test environment, plus the testnet run | M0 | The test environment runs the host's actual SAC implementation. |
| `contracts/test/mocks/MockTIP20.sol`, `HostileTIP20.sol` | replace | SAC test assets, and a hostile SEP-41 token contract in the tests | M0 | |
| `contracts/script/Deploy.s.sol`, `scripts/deploy-escrow.sh`, `scripts/export-deployment.ts` | replace | `scripts/deploy-testnet.sh`, `deployments/testnet.json` | M0 | The Stellar CLI replaces Foundry and viem. |
| `scripts/escrow-roundtrip.ts` | adapt | `scripts/demo-cases.sh` | M0 | Same three outcomes. As in Fermata's own Milestone 1, verdicts are signed by a script-held verifier key over placeholder presentation and response hashes, with no TLSNotary. |
| `scripts/demo/cases.ts` (`demo:cases` through the full stack) | defer | | M1 | Needs the attestor, and the gateway from M2 |
| `apps/attestor/src/eip712.rs` | replace | `crates/fermata-verdict` (canonical encoding, Ed25519 signing, CLI) | M0; used by the attestor in M1 | Stellar verifies Ed25519 natively. |
| `apps/attestor` TLSNotary parts: `prove.rs`, `notary.rs`, `verify.rs` (binding checks 1–7), `predicate.rs`, `http_raw.rs`, `tunnel.rs`, `serve.rs`, `verify --offline` | keep | `apps/attestor`, in its own workspace pinned to Rust 1.95.0 | M1 | Chain-agnostic. TLSNotary proving, the binding checks and the predicates stay as they are. |
| `apps/attestor/src/hashes.rs` | keep | `request_hash` (and its vector) in `fermata-verdict` now; the rest in M1 | M0 / M1 | The escrow treats these hashes as opaque 32-byte values, so their definitions do not change. |
| `apps/attestor/src/chain.rs` (hand-rolled `eth_call`) | replace | Soroban RPC reads of `get_hold`, `get_service` and the latest ledger time | M1 | |
| `apps/gateway` | defer | A `fermata` MPP method next to Stellar's MPP Charge, and an escrowed x402 scheme next to `exact` | M2 | Its `GatewayChain` interface is the seam. Routing, the call store, the SSRF guard, onboarding and the MCP plumbing are chain-agnostic. |
| `packages/sdk` | adapt, later | TypeScript bindings with golden-vector parity (M1); MPP and x402 client and server (M2) | M1 / M2 | `tip20.ts`, `escrow.ts`, `verdict.ts`, `serviceId.ts` and `chain.ts` are Tempo-specific. The hashes, the Wilson-score aggregator and `eventually` are reusable. |
| `apps/dashboard` | defer | Reads Soroban events through the gateway | M2 | It reads only the gateway API; the Tempo-specific strings will be replaced. |
| `apps/vendor` | keep | Reused unchanged | M1 | Chain-agnostic demo vendor (TLSNotary's TLS 1.2 profile, CHAOS failure modes) |
| `apps/mcp` (`fermata-mcp`) | defer | | after M2 | Depends on the gateway and the SDK |
| `deploy/`, `Dockerfile`, `docker-compose.yml`, `railway.json` | defer | | M2 or later | Hosting for the gateway stack |
| `spikes/` | not ported | | | Tempo go/no-go probes |
| `README.md`, `SECURITY.md`, the trust model | adapt | `README.md`, `docs/trust-model.md`, `docs/security.md` | M0 | Same claims, limited to what exists on Stellar |
| `docs/FACTS.md`, `docs/PLAN.md` | not copied | This file and `ROADMAP.md` | M0 | Tempo-specific. Numbers measured there are Tempo or Anvil numbers and are quoted only with that label. |

## 2. Tempo to Stellar mapping

| Concern | Tempo (Fermata) | Stellar (this repo) |
|---|---|---|
| Escrow | Solidity `FermataEscrow`: `registerService`, `hold`, `settle(verdict)`, `claimTimeout`, `setFeeBps`, `setTreasury`, views | Soroban contract with the same functions in snake_case and the same rules. **Statuses:** Held, Released, Refunded, TimedOut. **Role:** an immutable owner who can change only the fee and the treasury. **Fee:** at most 500 bps (50 in the demo), snapshotted per hold, rounded down, and no treasury transfer when it is zero. **Window:** `settle` while `now ≤ heldAt + window`, `claim_timeout` only after it. The check order is unchanged. |
| Pulling the payment | TIP-20 EIP-2612 `permit`, then `transferFromWithMemo(agent → escrow, price, callId)`. A failed permit is tolerated when an allowance already covers the price. | `agent.require_auth()` and a SAC `transfer(agent → escrow, price)` inside `hold`. The agent signs one authorization tree that covers `hold(...)` and the inner `transfer` with its exact amount; the host enforces the nonce and the expiry. There is no permit and no allowance, so the permit edge cases disappear. |
| Linking money to a call | Every transfer is a `…WithMemo` variant with memo = callId; reconciliation filters `TransferWithMemo` logs by memo. | Escrow events carry `call_id` as a topic. The SAC's own `transfer` events land in the same transaction; they have no 32-byte memo field. Reconciliation reads the escrow events and the token events of those transactions. |
| Verdict signature | EIP-712 over `Verdict(...)`, domain (name "Fermata", version "1", chainId, verifyingContract); secp256k1, 65-byte r‖s‖v, low-s, `ecrecover` | Ed25519 over `"FERMATA_STELLAR_VERDICT_V1" ‖ sha256(network passphrase) ‖ contract id ‖ canonical(verdict)`, verified natively with `ed25519_verify` (strict). The network id plays the role of chainId, the contract id that of verifyingContract, and the versioned tag that of name, version and type hash. Section 3 has the byte layout. |
| Verifier identity | A 20-byte address per service | A 32-byte Ed25519 public key per service (`BytesN<32>`). It can be generated with `stellar keys generate`; it should sign verdicts only, never transactions. |
| Service id | `bytes20(owner) ‖ bytes12(label)`; the prefix is checked against `msg.sender` | **proposed:** `sha256("FERMATA_STELLAR_SERVICE_V1" ‖ XDR(owner address) ‖ label[12])`, computed by the contract from the authenticated owner and returned by `register_service`. A Stellar address does not fit next to a label in 32 bytes. Hashing keeps the property that only the owner can register its ids. |
| Time | `block.timestamp` | `env.ledger().timestamp()`: ledger close time, in seconds |
| Amounts | `uint256`; pathUSD has 6 decimals | `i128` (SEP-41); classic USDC has 7 decimals. The price must be greater than 0 and at most `i128::MAX / 10_000`, so the fee product cannot overflow. |
| Recipient checks | Not zero, not the escrow, not a TIP-20 address (transfers to those revert) | Not the escrow and not the service's token contract (funds sent there would be stuck). Stellar has no zero address. |
| Blocked recipient | TIP-403 receive policy: the escrow reverts with `RecipientBlocked`, so the hold stays open. | A SAC transfer to an account with no trustline, or with a deauthorized trustline or balance, fails and reverts the whole invocation. The hold stays Held and can still be refunded by a FAILED verdict or a timeout. Same outcome, no extra code. |
| Re-entrancy | State is updated before transfers; tested with `ReentrantTIP20` | State is still updated before transfers, and the host blocks re-entry. The hostile-token test is ported. |
| Storage | Three slots per hold. `serviceId` and `requestHash` are cleared at finalisation to mint Tempo storage credits (TIP-1060). | One persistent entry per call id, kept in full after finalisation: there are no storage credits, and events are not durable state on Stellar. TTL management is described in section 5. |
| Upgradeability | None | None: no entry point calls `update_current_contract_wasm`. |
| Test chain | Anvil `--chain-id 42431`, Tempo emulation with real TIP-20 precompile semantics | The soroban-sdk test environment (native code, the real SAC implementation, auth, events and TTL); a local quickstart network if Docker works in the build environment; Stellar testnet |
| Fuzz and invariants | Foundry fuzz (512 runs); invariants (128 runs × depth 64, `fail_on_revert`) | proptest properties, and randomized action sequences with ghost state at the same run counts and depth |
| Cross-language vectors | Rust k256 signature equals Foundry's `vm.sign`, byte for byte | `test-vectors/` holds message bytes and signatures, asserted by the contract tests and by `fermata-verdict`. Ed25519 signatures are deterministic, so they are reproducible. |
| Payment protocol | The mppx `fermata` method on Tempo, plus plain `tempo` | Deferred to M2: a `fermata` MPP method next to Stellar's MPP Charge, and an escrowed x402 scheme next to `exact` |
| Explorer | explore.testnet.tempo.xyz | stellar.expert/explorer/testnet |
| Cost | Gas measured on Anvil and Moderato (Fermata FACTS §15) | Not comparable. Soroban resource fees will be measured on testnet; no Tempo number is presented as a Stellar result. |

## 3. The verdict on Stellar

**Fields.** The same eight fields as the EIP-712 `Verdict`, in the same order. `outcome` is a
`u32`, because Soroban has no `u8` value type; only 1 (DELIVERED) and 2 (FAILED) are accepted.

**Signed message** (294 bytes, every field fixed-width, integers big-endian):

| Offset | Length | Content |
|---|---|---|
| 0 | 26 | ASCII `FERMATA_STELLAR_VERDICT_V1` |
| 26 | 32 | network id = sha256(network passphrase) |
| 58 | 32 | escrow contract id (the 32 bytes inside its `C…` strkey) |
| 90 | 32 | `call_id` |
| 122 | 32 | `service_id` |
| 154 | 32 | `request_hash` |
| 186 | 32 | `predicate_hash` |
| 218 | 4 | `outcome` (u32) |
| 222 | 32 | `presentation_hash` |
| 254 | 32 | `response_hash` |
| 286 | 8 | `issued_at` (u64, unix seconds) |

**Why fixed-width bytes and not the XDR of a `#[contracttype]`.** Every field has a fixed width, so
plain concatenation is unambiguous without length prefixes. Any language can rebuild the message
with byte copies and two big-endian integers, with no XDR library or map-key ordering rules. The
contract builds the same bytes with `Bytes` operations and exposes them through a read-only
`verdict_message(verdict)` view (the counterpart of `verdictDigest`), so off-chain code can check
parity against a deployment.

**The message is signed directly, not a hash of it.** Ed25519 hashes internally, and the host
verifies the raw message, so a 294-byte message keeps the vectors readable.

**Separation from other Stellar signatures.** Transaction signatures and Soroban authorization
signatures cover 32-byte hashes. A verdict message is 294 bytes and starts with the tag, so the
two cannot be confused. The verifier key should still be dedicated to verdicts.

**Golden vectors (planned).** The same verdict values as Fermata's `verdict-vector.json` (callId
0x11…, requestHash 0x33…, …, issuedAt 1,700,000,000), the testnet passphrase, a fixed contract
id and a fixed Ed25519 seed. The vector's `service_id` is derived from a fixed owner and label, so
the derivation is covered too. A FAILED vector and a vector on another passphrase show that the
message changes with each input.

- **The contract tests assert:**
  - `verdict_message` equals the vector bytes;
  - the vector signature settles a hold on an escrow registered at the vector's contract id;
  - the same signature fails under another network id or contract id.
- **`fermata-verdict` asserts:**
  - its encoding equals the vector bytes;
  - signing with the seed reproduces the vector signature;
  - verification accepts it.

## 4. Intentional differences from `FermataEscrow.sol`

1. **Payment pull.** `permit` + `transferFromWithMemo` becomes `agent.require_auth()` + a SAC `transfer`. Soroban authorization covers the token call, so there is no permit or allowance to manage; the permit-tolerance branch and its tests go away.
2. **No memo.** The call id travels in the escrow's event topics instead (section 2).
3. **Ed25519 verdicts** with the encoding in section 3. `WrongVerifier` and `InvalidSignature` merge into one failure: `ed25519_verify` traps instead of returning a value, so a wrong key or a malformed signature fails the invocation with a host crypto error, not a contract error code. A wrong-length signature cannot be passed at all (`BytesN<64>`).
4. **`outcome` is `u32`.** Soroban has no `u8`. The accepted values (1, 2) are unchanged.
5. **Service id derived on-chain (proposed, decision Q1).** The `Service` record also stores the label, since it can no longer be read from the id.
6. **Verifier key, not address.** The zero-address check on the verifier becomes "the key is not 32 zero bytes".
7. **No zero-address checks** for owner, treasury, payout or token: a Stellar `Address` cannot be zero. The recipient checks keep "not the escrow" and replace the TIP-20 prefix check with "not the service's token contract".
8. **`i128` amounts** with an explicit upper bound on the price (section 2).
9. **Finalised holds keep their data.** On Tempo, `serviceId` and `requestHash` were cleared only to mint storage credits. Stellar has no such credits, and events expire from RPC. `amount` and `deadline` are still reported only while a hold is Held, as before. `get_hold` returns `Option<HoldView>`: `None` for an unknown call id, instead of a zeroed struct.
10. **Timeout event (proposed, decision Q2).** A distinct `timed_out` event instead of `Refunded` with a zero presentation hash. The status stays `TimedOut`, as on Tempo.
11. **Explicit TTL management** (section 5). Tempo has no state archival.
12. **Owner checks** use `owner.require_auth()`. A missing authorization is a host auth error rather than `NotOwner`.
13. **Event layout.** Snake_case names. An event has at most four topics including its name, so the topics are (name, `call_id`, `service_id`, counterparty), matching the three indexed parameters of the Solidity events.
14. **Constructor.** `__constructor(owner, treasury, fee_bps)` runs atomically with deployment, so there is no initialisation step to front-run.
15. **Hostile tokens.** The host blocks re-entry; the re-entrancy test is kept. A SEP-41 token cannot "return false", so the `FalseTIP20` test becomes "a token whose transfer traps".

## 5. Storage, TTL and state archival (planned behaviour)

- **Instance storage** (owner, treasury, fee) has its TTL extended on every call.
- **Service entries** (persistent) are extended at registration and on each `hold`, so a service in use stays live.
- **Hold entries** (persistent, one per call id) are extended at `hold` to cover the settlement window plus a grace period for `claim_timeout`. The window is converted to ledgers at 5 s per ledger and capped at the network's maximum TTL. They are not extended after finalisation.
- **Archived holds stay usable.** A hold whose TTL runs out is archived, not deleted. A later transaction that touches it restores it (automatically since protocol 23) and sees its real state. So a call id can never be held twice, and held funds can always be settled or refunded.
- **What archival can cost.** If the network's ledger time fell below 5 s, a hold could archive before its window ends; restoring it adds rent. This affects cost and convenience, never funds.
- **Not a security mechanism.** No security property depends on TTL expiry, because anyone can extend any entry's TTL. Deadlines are stored in the hold and checked against the ledger timestamp.

## 6. Test mapping

### `FermataEscrow.t.sol` (43)

| # | Solidity test | Stellar | Note |
|---|---|---|---|
| 1 | `test_register_storesServiceAndEmits` | port | Also checks the stored label and the returned id |
| 2 | `test_register_revertsOnDuplicate` | port | Same owner and label twice → `ServiceExists` |
| 3 | `test_register_revertsOnZeroId` | n/a | Ids are derived and cannot be zero (Q1). |
| 4 | `test_register_revertsWhenIdNotPrefixedBySender` | adapt | Registering for another owner without its authorization fails; the same label under two owners gives two different ids. |
| 5 | `test_register_revertsOnZeroAddresses` | adapt | Only the all-zero verifier key remains to reject. |
| 6 | `test_register_revertsOnBadPriceOrWindow` | port | Adds a negative price and a price above the overflow bound |
| 7 | `test_register_revertsOnUnpayablePayout` | adapt | Payout = escrow; payout = token |
| 8 | `test_hold_viaPermit` | adapt | The price is pulled under the agent's authorization. Asserts the exact auth tree, balances, the view, the event and exactly one token movement. |
| 9 | `test_hold_revertsOnUsedCallId` | port | |
| 10 | `test_hold_revertsOnUnknownService` | port | |
| 11 | `test_hold_revertsOnZeroCallIdOrRequest` | port | |
| 12 | `test_hold_thirdPartyCannotUseAgentsPermit` | adapt | A third party cannot hold from the agent's balance without the agent's authorization. |
| 13 | `test_hold_revertsWhenPermitValueDiffersFromPrice` | adapt | An authorization for a different amount does not cover the transfer. |
| 14 | `test_hold_revertsOnExpiredPermitWithRealError` | n/a | No permits; the host enforces authorization expiry. |
| 15 | `test_hold_succeedsWhenPermitWasFrontRun` | n/a | No permit to front-run |
| 16 | `test_hold_approvePathWithJunkSignature` | n/a | No allowance path |
| 17 | `test_hold_revertsWithoutPermitOrAllowance` | adapt | Missing agent authorization fails, as does an insufficient balance; nothing is recorded. |
| 18 | `test_settle_delivered_paysVendorMinusFee` | port | Exact split, event, two token movements, record after finalisation |
| 19 | `test_settle_delivered_feeRoundsToZero_singleTransfer` | port | |
| 20 | `test_settle_delivered_zeroFee` | port | |
| 21 | `test_settle_failed_refundsAgentInFull` | port | |
| 22 | `test_settle_revertsOnWrongVerifier` | port | Host crypto error instead of `WrongVerifier` (difference 3) |
| 23 | `test_settle_revertsOnMalformedSignatures` | adapt | Zeroed, bit-flipped and non-canonical-S signatures; a wrong length is rejected by the argument type. |
| 24 | `test_settle_revertsOnMismatchedFields` | port | Each mismatch error, plus each of the eight fields tampered with after signing |
| 25 | `test_settle_revertsForVerdictSignedForAnotherEscrow` | port | Another contract id |
| 26 | `test_settle_revertsForVerdictSignedForAnotherChain` | port | Other network passphrases (mainnet, futurenet, standalone) |
| 27 | `test_digestMatchesIndependentImplementation` | port | `verdict_message` = `fermata-verdict` encoding = golden vector |
| 28 | `test_settle_replayReverts` | port | |
| 29 | `test_settleAfterTimeout_andTimeoutAfterSettle_revert` | port | |
| 30 | `test_unknownCall_reverts` | port | |
| 31 | `test_settle_atWindowEndSucceeds` | port | |
| 32 | `test_settle_afterWindowReverts` | port | |
| 33 | `test_timeout_beforeOrAtWindowEndReverts` | port | |
| 34 | `test_timeout_refundsAgent_calledByStranger` | port | Event per Q2 |
| 35 | `test_constructor_validation` | adapt | Fee above 500; treasury = escrow |
| 36 | `test_admin_onlyOwner` | port | Owner authorization required |
| 37 | `test_admin_setters` | port | |
| 38 | `test_feeSnapshot_changeAfterHoldDoesNotApply` | port | |
| 39 | `test_reentrantToken_cannotDoubleSpend` | adapt | A hostile token tries to re-enter during the transfer; the host refuses. |
| 40 | `test_tokenReturningFalse_reverts` | adapt | A token whose transfer traps: `hold` fails atomically. |
| 41 | `test_holdsAcrossServicesAreIsolated` | port | Two SACs |
| 42 | `testFuzz_feeSplitIsExact` | port | proptest over price and fee |
| 43 | `testFuzz_foreignSignerNeverSettles` | port | proptest over random Ed25519 seeds |

### Invariant suite, vectors and Tempo-only tests

| Solidity | Stellar | Note |
|---|---|---|
| `invariant_escrowBalanceEqualsHeld` | port | Per token, the escrow balance equals the sum of open holds, from ghost state and from on-chain records. |
| `invariant_statusesMatchGhost` | adapt | Finalised records keep their data (difference 9). |
| `invariant_conservation` | port | Held plus paid out equals paid in; balances of the known holders sum to the minted supply. |
| `afterInvariant` (non-vacuity) | port | |
| `Vectors.t.sol` `test_rustSignedVerdictSettles` | port | The golden-vector signature settles a hold. |
| `Vectors.t.sol` `test_foundrySignatureEqualsRust` | adapt | `fermata-verdict` reproduces the vector signature (Ed25519 is deterministic). |
| `Vectors.t.sol` `test_requestHashMatchesRust` | port | `request_hash` vector `0xe8b23a0b…` in `fermata-verdict` |
| `AttestVector.t.sol` (4 tests) | defer to M1 | Needs the ported attestor |
| `test_tempo_holdViaPermit_thenDelivered`, `test_tempo_failedRefund_andTimeout` | replace | SAC-based unit tests, plus testnet cases 1–3 |
| `test_tempo_frontRunPermit_andApprovePath`, `test_tempo_badPermitBubblesPrecompileError` | n/a | No permits |
| `test_tempo_receivePolicyBlockedPayout_revertsThenTimesOut` | adapt | The payout's SAC balance is deauthorized: a DELIVERED settle fails, the hold stays Held, then times out to the agent. |

### New Stellar-specific tests

- **Authorization trees.** `hold` needs the agent's authorization, including the token `transfer` sub-invocation; `register_service` needs the owner's; `set_fee_bps` and `set_treasury` need the escrow owner's. `settle` and `claim_timeout` need none.
- **Events.** Exact topics and data for every event, and the number of SAC `transfer` events per step: one for `hold`; two for DELIVERED with a non-zero fee; one otherwise.
- **TTL.**
  - After `hold`, the hold's TTL covers the window plus the grace period.
  - Instance and service TTLs are extended.
  - An archived, finalised hold still blocks reuse of its call id.
- **Domain separation.** The same verdict signed for another network id or another contract id is rejected.
- **Golden vectors.** Message bytes, signature and service-id derivation.
- **Bounds.** A price at the overflow bound settles exactly.

### The brief's rejection matrix

| Rejection | Where it is tested |
|---|---|
| Unknown or rotated-out verifier key; a signature from another service's verifier | Tests 22 and 43. Under Q1 option A, "rotated out" means the key of the vendor's previous service. |
| A tampered verdict (each field separately) | Test 24 |
| Wrong call id, service id, request hash or pinned hashes | Test 24. Only `predicate_hash` is in the verdict; `origin_hash` and `notary_key_hash` are pinned in the service and checked off-chain by the attestor, as on Tempo. |
| Settling twice | Test 28 |
| Settling after the timeout | Tests 29 and 32 |
| Claiming the timeout before the window ends | Test 33 |
| A duplicate call id on hold | Test 9 |
| Missing buyer authorization | Tests 12, 13 and 17 |
| Bad amounts | Tests 6 and 17 |
| Non-admin service registration or updates | Tests 4 and 36, per Q1 |
| Replay across contracts or networks | Tests 25 and 26 |

## 7. Open decisions

These are places where the brief and the Fermata repo disagree. Nothing that depends on them is
built until they are decided.

**Q1. Who registers services, and can a service change?**
- **Fermata:** registration is permissionless and squat-proof (a Milestone 1 decision recorded in Fermata's `docs/PLAN.md`): the id must start with the registrant's address. Services are immutable once registered. The only role is an immutable owner who sets the fee and the treasury. There is no verifier rotation.
- **The brief:** its rejection matrix includes "rotated-out verifier key" and "non-admin service registration or updates".

The options:

- **A (recommended):** keep Fermata's model.
  - **Registration:** the vendor authorizes `register_service` itself, and the id is derived from the vendor's address and label.
  - **Rotation:** a vendor rotates its verifier by registering a new service.
  - **The matrix rows become:**
    - a signature by a key the service does not pin, including the vendor's previous key;
    - a registration attempted for another vendor's id or without its authorization;
    - a fee or treasury change attempted by someone other than the owner.
- **B:**
  - **Registration:** admin-gated.
  - **Rotation:** a per-service `rotate_verifier`, with the verifier key copied into each hold at `hold` time so open holds keep the key they were made under.
  - **Cost:** new code paths that Fermata does not have, and a new trust point: the admin decides who may list.

**Q2. Timeout event.**
- **Fermata (also a Milestone 1 decision in `docs/PLAN.md`):** a timeout emits `Refunded` with a zero presentation hash.
- **The brief:** lists a timeout event.
- **Recommendation:** a distinct `timed_out` event (status `TimedOut`, as before). On Stellar, reconciliation and vendor scores read events, and a named topic is clearer than a zero-hash convention.

**Q3. Branch.**
- **The brief:** push to `main`.
- **This cloud session:** set up to develop on `claude/affectionate-shannon-mbtrvx`, with instructions not to push elsewhere without your explicit OK. The repository has no commits yet.
- **Recommendation:** push to the session branch and you merge into `main`, or tell me to push to `main`.

## 8. Reuse and licensing

Fermata is MIT (© 2026 Bilgin Kocak). Its attestor is Apache-2.0 because it ports WebProof, which
is Apache-2.0. This repository is Apache-2.0. Each file copied or ported from either project keeps
a header naming the source repository, path and commit. `NOTICE` lists them.

Planned reuse in M0:

- **The verdict type.** The `Verdict` fields, the 0x-hex serde helpers, the outcome constants and the vector values, from Fermata `apps/attestor/src/eip712.rs` @ `d7cc642`.
- **`request_hash`.** The function and its vector, from Fermata `apps/attestor/src/hashes.rs` @ `d7cc642`.
- **The claim pattern.** A versioned ASCII tag followed by canonical bytes, with a text vector file checked by `include_str!`, from WebProof `crates/webproof-core/src/lib.rs` @ `609a654`.
- **Documentation text.** "What the proof does and does not establish", the trust model and the security policy, adapted from Fermata `README.md` and `SECURITY.md` @ `d7cc642`.
