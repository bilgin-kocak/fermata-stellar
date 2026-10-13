# Porting notes: Fermata from Tempo to Stellar

This file records how Fermata's Tempo implementation maps onto Stellar: what is kept, adapted,
replaced or deferred, and why. Section 4 lists every intentional difference from
`FermataEscrow.sol`.

It was written in Milestone 0, step 1, before any Stellar code. It was updated at the end of the
milestone with the decisions taken (section 7) and what the implementation showed.

## Sources

| Source | Version read |
|---|---|
| Fermata (Tempo) | `bilgin-kocak/fermata` `main` @ `d7cc642` (2026-10-08). It contains `claude/keen-maxwell-1ly15p` @ `86e86fc`. `contracts/` is identical on both; `apps/attestor` differs only in `chain.rs`, `http_raw.rs` and `prove.rs`. |
| WebProof | `bilgin-kocak/webproof-solana` @ `609a654` |
| Stellar Rust SDK | `soroban-sdk` 29.0.1 and `soroban-env-host` 29.0.1, sources read from crates.io |
| Stellar CLI | 28.1.0 (`c0f4d0d`), release binary |
| SDF agent skill | `stellar/stellar-dev-skill` @ `a17a93a` (smart-contracts, assets, agentic-payments) |

### How facts were checked

This build environment's network policy refuses developers.stellar.org, stellar.expert, Circle's
docs and faucet, and the testnet RPC, Horizon and Friendbot hosts (HTTP 403 at CONNECT,
2026-10-13). Fermata's `docs/FACTS.md` records the same situation for Tempo's hosts. The facts
below come from four places:

- the SDK and host sources, read locally;
- the CLI binary;
- SDF's skill;
- a local quickstart network (stellar-core 29.0.0) and web search, where noted.

| Fact | Value | Source |
|---|---|---|
| Live protocol | 29 on testnet (since 2026-09-29) and mainnet (since 2026-10-01) | developers.stellar.org "Software Versions", via web search |
| SDK and protocol | The `soroban-sdk` major version tracks the protocol. 29.0.0 was tagged 2026-10-07; 29.0.1 (2026-10-13) only bumps the env crates. SDK 29 refuses plain `cargo build` for Wasm: it must be built through `stellar contract build` (CLI 25.2 or newer). | `rs-soroban-sdk` tags and log; SDK build script |
| Ed25519 verification | `env.crypto().ed25519_verify(pk, msg, sig)` traps when verification fails; the host calls `verify_strict`. A caller of the failed contract sees `Error(Context, InvalidAction)`; the cause, `Error(Crypto, InvalidInput)`, appears in the diagnostics. | `soroban-sdk` `src/crypto.rs:154`; `soroban-env-host` `src/crypto/mod.rs:89`; escrow tests |
| Network id | `env.ledger().network_id()` = sha256(network passphrase); testnet: `cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472` | `soroban-sdk` `src/ledger.rs:102`; computed locally |
| Contract id bytes | `Address::to_payload()` returns `ContractIdHash(BytesN<32>)`; it sits behind the `hazmat-address` feature | `soroban-sdk` `src/address.rs:400` |
| Contract value types | No `u8`; the smallest unsigned integer is `u32` | `soroban-sdk-macros` `src/map_type.rs` |
| Token transfer | SEP-41 `transfer(from: Address, to: MuxedAddress, amount: i128)`; a failure traps, nothing returns `false`. A failing Stellar Asset Contract (SAC) transfer propagates the SAC's error codes 1–15 (10 = insufficient balance, 11 = deauthorized) through its caller. | `soroban-sdk` `src/token.rs:154`; `soroban-env-host` `builtin_contracts/contract_error.rs`; escrow tests |
| Re-entrancy | The host rejects re-entry into a contract that is already on the call stack; a `try_` call observes the rejection as an error | SDF skill, `smart-contracts/security.md`; escrow test 39 |
| Archival | At TTL expiry, persistent entries are archived, not deleted. Since protocol 23 an archived entry in a transaction's read-write footprint is restored automatically, and the test host emulates this. Anyone can extend any entry's TTL. | SDF skill, `smart-contracts/development.md`; `soroban-env-host` `src/storage.rs:800` |
| TTL scale | About 5 s per ledger (17,280 per day). The maximum entry TTL on mainnet is about 3,110,400 ledgers (about 180 days); it is network-configured. On protocol 29, `extend_ttl` beyond the maximum clamps to the maximum. | SDF skill; `soroban-sdk` `src/storage.rs` docs |
| Events | Events are not ledger state; RPC providers typically keep them for about 7 days | SDF skill, `smart-contracts/development.md` |
| Testnet | Reset quarterly (all state deleted); passphrase `Test SDF Network ; September 2015` | SDF skill, `smart-contracts/testing.md` |
| Testnet USDC | Issuer `GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5`, SAC `CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA`, 7 decimals | SDF skill, `agentic-payments/SKILL.md` lines 74 and 114. The SAC id was re-derived locally with `stellar contract id asset --network testnet`. Circle's "USDC contract addresses" page lists the same issuer (via web search). |
| Testnet USDC faucet | faucet.circle.com: a web form with a captcha, no API | SDF skill, `agentic-payments/SKILL.md` line 99 |
| Local network | `stellar/quickstart:latest` (built 2026-10-12) defaults to protocol 28; `--protocol-version 29` runs 29, which SDK-29 contracts need | the image's `/image.json` and `/start` |

## 1. Component table

| Fermata (Tempo) | Decision | On Stellar | When | Reason |
|---|---|---|---|---|
| `contracts/src/FermataEscrow.sol` | adapt | `contracts/escrow` (Soroban) | M0, done | Keeps the state machine, role, fee, check order and events. The payment pull, signature scheme and storage change with the chain (section 4). |
| `contracts/test/FermataEscrow.t.sol` (41 unit + 2 fuzz) | adapt | `contracts/escrow/src/tests/` | M0, done | Each case is ported, adapted, or marked not applicable with a reason (section 6). |
| `contracts/test/FermataEscrow.invariant.t.sol` | adapt | `tests/invariants.rs`: random action sequences with ghost state (proptest) | M0, done | Same three invariants and the non-vacuity check, at Foundry's 128 runs and depth 64 |
| `contracts/test/Vectors.t.sol`, `fixtures/verdict-vector.json` | replace | `test-vectors/verdict-v1.json`, asserted by the contract tests, `fermata-verdict` and a Python/OpenSSL checker | M0, done | EIP-712/secp256k1 vectors become Ed25519 vectors over the same verdict field values. |
| `contracts/test/AttestVector.t.sol`, `fixtures/attest-vector.json` | defer | Regenerated by the ported attestor | M1 | Needs real TLSNotary presentations with verdicts signed for Stellar. Its "cannot settle another call" case is already ported with a script-signed verdict. |
| `contracts/test-tempo/` (real TIP-20 precompile, TIP-403 registry) | replace | Unit tests run against the host's real SAC code, plus the local-network and testnet runs | M0, done (testnet run pending) | The soroban test environment runs the actual Stellar Asset Contract implementation. |
| `contracts/test/mocks/MockTIP20.sol`, `HostileTIP20.sol` | replace | SAC test assets, and a hostile SEP-41 token contract in `tests/tokens.rs` | M0, done | |
| `contracts/script/Deploy.s.sol`, `scripts/deploy-escrow.sh`, `scripts/export-deployment.ts` | replace | `scripts/deploy-testnet.sh`, `deployments/testnet.json` | M0, done | The Stellar CLI replaces Foundry and viem. |
| `scripts/escrow-roundtrip.ts` | adapt | `scripts/demo-cases.sh` | M0, done | Same three outcomes. As in Fermata's own Milestone 1, verdicts are signed by a script-held verifier key over placeholder presentation and response hashes, with no TLSNotary. |
| `scripts/demo/cases.ts` (`demo:cases` through the full stack) | defer | | M1 | Needs the attestor, and the gateway from M2 |
| `apps/attestor/src/eip712.rs` | replace | `crates/fermata-verdict` (canonical encoding, Ed25519 signing, CLI) | M0, done; used by the attestor in M1 | Stellar verifies Ed25519 natively. |
| `apps/attestor` TLSNotary parts: `prove.rs`, `notary.rs`, `verify.rs` (binding checks 1–7), `predicate.rs`, `http_raw.rs`, `tunnel.rs`, `serve.rs`, `verify --offline` | keep | `apps/attestor`, in its own workspace pinned to Rust 1.95.0 | M1 | Chain-agnostic. TLSNotary proving, the binding checks and the predicates stay as they are. |
| `apps/attestor/src/hashes.rs` | keep | `crates/fermata-verdict/src/hashes.rs`: request, predicate, origin and notary-key hashes with Fermata's vectors | M0, done | The escrow treats these hashes as opaque 32-byte values, so their definitions do not change. |
| `apps/attestor/src/chain.rs` (hand-rolled `eth_call`) | replace | Soroban RPC reads of `get_hold`, `get_service` and the latest ledger time | M1 | |
| `apps/gateway` | defer | A `fermata` MPP method next to Stellar's MPP Charge, and an escrowed x402 scheme next to `exact` | M2 | Its `GatewayChain` interface is the seam. Routing, the call store, the SSRF guard, onboarding and the MCP plumbing are chain-agnostic. |
| `packages/sdk` | adapt, later | TypeScript bindings with golden-vector parity (M1); MPP and x402 client and server (M2) | M1 / M2 | `tip20.ts`, `escrow.ts`, `verdict.ts`, `serviceId.ts` and `chain.ts` are Tempo-specific. The hashes, the Wilson-score aggregator and `eventually` are reusable. |
| `apps/dashboard` | defer | Reads Soroban events through the gateway | M2 | It reads only the gateway API; the Tempo-specific strings will be replaced. |
| `apps/vendor` | keep | Reused unchanged | M1 | Chain-agnostic demo vendor (TLSNotary's TLS 1.2 profile, CHAOS failure modes) |
| `apps/attestor/predicates/quote-v1.json` | keep | `predicates/quote-v1.json`, byte for byte (predicateHash `f9607cf2…`) | M0, done | Registered by the demo service now, enforced from M1 |
| `apps/mcp` (`fermata-mcp`) | defer | | after M2 | Depends on the gateway and the SDK |
| `deploy/`, `Dockerfile`, `docker-compose.yml`, `railway.json` | defer | | M2 or later | Hosting for the gateway stack |
| `spikes/` | not ported | | | Tempo go/no-go probes |
| `README.md`, `SECURITY.md`, the trust model | adapt | `README.md`, `docs/trust-model.md`, `docs/security.md` | M0, done | Same claims, limited to what exists on Stellar |
| `docs/FACTS.md`, `docs/PLAN.md` | not copied | This file and `ROADMAP.md` | M0 | Tempo-specific. Numbers measured there are Tempo or Anvil numbers and are quoted only with that label. |

## 2. Tempo to Stellar mapping

| Concern | Tempo (Fermata) | Stellar (this repo) |
|---|---|---|
| Escrow | Solidity `FermataEscrow`: `registerService`, `hold`, `settle(verdict)`, `claimTimeout`, `setFeeBps`, `setTreasury`, views | Soroban contract with the same functions in snake_case and the same rules. **Statuses:** Held, Released, Refunded, TimedOut. **Role:** an immutable owner who can change only the fee and the treasury. **Fee:** at most 500 bps (50 in the demo), snapshotted per hold, rounded down, and no treasury transfer when it is zero. **Window:** `settle` while `now ≤ heldAt + window`, `claim_timeout` only after it. The check order is unchanged. |
| Pulling the payment | TIP-20 EIP-2612 `permit`, then `transferFromWithMemo(agent → escrow, price, callId)`. A failed permit is tolerated when an allowance already covers the price. | `agent.require_auth()` and a SAC `transfer(agent → escrow, price)` inside `hold`. The agent signs one authorization tree that covers `hold(...)` and the inner `transfer` with its exact amount; the host enforces the nonce and the expiry. There is no permit and no allowance, so the permit edge cases disappear. |
| Linking money to a call | Every transfer is a `…WithMemo` variant with memo = callId; reconciliation filters `TransferWithMemo` logs by memo. | Escrow events carry `call_id` as their first topic after the name. The SAC's own `transfer` events land in the same transaction; they have no 32-byte memo field. Reconciliation reads the escrow events and the token events of those transactions. |
| Verdict signature | EIP-712 over `Verdict(...)`, domain (name "Fermata", version "1", chainId, verifyingContract); secp256k1, 65-byte r‖s‖v, low-s, `ecrecover` | Ed25519 over `"FERMATA_STELLAR_VERDICT_V1" ‖ sha256(network passphrase) ‖ contract id ‖ canonical(verdict)`, verified natively with `ed25519_verify` (strict). The network id plays the role of chainId, the contract id that of verifyingContract, and the versioned tag that of name, version and type hash. Section 3 has the byte layout. |
| Verifier identity | A 20-byte address per service | A 32-byte Ed25519 public key per service (`BytesN<32>`). The scripts generate it with `stellar keys generate`; it signs verdicts only, never transactions. |
| Service id | `bytes20(owner) ‖ bytes12(label)`; the prefix is checked against `msg.sender` | `sha256("FERMATA_STELLAR_SERVICE_V1" ‖ XDR(ScVal::Address(owner)) ‖ label[12])`, computed by the contract from the authenticated owner and returned by `register_service`. A Stellar address does not fit next to a label in 32 bytes. Hashing keeps the property that only the owner can register its ids (decision Q1). |
| Time | `block.timestamp` | `env.ledger().timestamp()`: ledger close time, in seconds |
| Amounts | `uint256`; pathUSD has 6 decimals | `i128` (SEP-41); classic USDC has 7 decimals. The price must be greater than 0 and at most `MAX_PRICE = i128::MAX / 10_000`, so the fee product cannot overflow. |
| Recipient checks | Not zero, not the escrow, not a TIP-20 address (transfers to those revert) | Not the escrow and not the service's token contract (funds sent there would be stuck). Stellar has no zero address. |
| Blocked recipient | TIP-403 receive policy: the escrow reverts with `RecipientBlocked`, so the hold stays open. | A SAC transfer to an account with no trustline, or with a deauthorized trustline or balance, fails and reverts the whole invocation. The hold stays Held and can still be refunded by a FAILED verdict or a timeout. Same outcome, no extra code; tested with a deauthorized payout and a deauthorized treasury. |
| Re-entrancy | State is updated before transfers; tested with `ReentrantTIP20` | State is still updated before transfers, and the host blocks re-entry. The hostile-token test is ported. |
| Storage | Three slots per hold. `serviceId` and `requestHash` are cleared at finalisation to mint Tempo storage credits (TIP-1060). | One persistent entry per call id, kept in full after finalisation: there are no storage credits, and events are not durable state on Stellar. TTL management is described in section 5. |
| Upgradeability | None | None: no entry point calls `update_current_contract_wasm`. |
| Test chain | Anvil `--chain-id 42431`, Tempo emulation with real TIP-20 precompile semantics | The soroban-sdk test environment (native code, the real SAC implementation, auth, events, TTL and archival); a local quickstart network (stellar-core 29.0.0, protocol 29), where both scripts ran 3/3; Stellar testnet (pending) |
| Fuzz and invariants | Foundry fuzz (512 runs); invariants (128 runs × depth 64, `fail_on_revert`) | proptest at the same counts: two properties at 512 cases, and one invariant property over 128 random sequences of up to 64 actions |
| Cross-language vectors | Rust k256 signature equals Foundry's `vm.sign`, byte for byte | `test-vectors/verdict-v1.json` holds message bytes and signatures. Three implementations agree on it: the contract, `fermata-verdict`, and Python with OpenSSL. Ed25519 signatures are deterministic, so they are reproducible. |
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

**Golden vectors.** `test-vectors/verdict-v1.json` contains four verdicts:

- DELIVERED and FAILED on testnet;
- the same DELIVERED verdict on mainnet;
- the same verdict for another escrow.

They use the values from Fermata's EIP-712 vector (callId 0x11…, requestHash 0x33…, …, issuedAt
1,700,000,000), a fixed contract id (`…0fe1`) and a fixed Ed25519 seed (`…01`). The service id is
derived from the account `0x22…` and the label `quote`, so the derivation has a vector too.

- **The contract tests** rebuild every message on-chain, derive the service id, and settle holds
  with the recorded signatures. The mainnet and other-escrow signatures must not settle.
- **`fermata-verdict`** re-encodes the messages and re-signs them, and its CLI reproduces them.
- **`test-vectors/check_vectors.py`** does the same in Python with OpenSSL's Ed25519.

## 4. Intentional differences from `FermataEscrow.sol`

1. **Payment pull.** `permit` + `transferFromWithMemo` becomes `agent.require_auth()` + a SAC `transfer`. Soroban authorization covers the token call, so there is no permit or allowance to manage; the permit-tolerance branch and its tests go away.
2. **No memo.** The call id travels in the escrow's event topics instead (section 2).
3. **Ed25519 verdicts** with the encoding in section 3.
   - `WrongVerifier` and `InvalidSignature` become one host failure: `ed25519_verify` traps instead of returning a value. Callers see `Error(Context, InvalidAction)`, and the diagnostics carry `Error(Crypto, InvalidInput)`.
   - A wrong-length signature cannot be passed at all (`BytesN<64>`).
4. **`outcome` is `u32`.** Soroban has no `u8`. The accepted values (1, 2) are unchanged.
5. **Service id derived on-chain** from the authenticated owner and a 12-byte label (decision Q1). The `Service` record also stores the label, since it can no longer be read from the id. Registration still needs no admin, and services stay immutable.
6. **Verifier key, not address.** The zero-address check on the verifier becomes "the key is not 32 zero bytes" (`InvalidVerifier`).
7. **No zero-address checks** for owner, treasury, payout or token: a Stellar `Address` cannot be zero. The recipient checks keep "not the escrow" and replace the TIP-20 prefix check with "not the service's token contract".
8. **`i128` amounts** with an explicit upper bound on the price (`MAX_PRICE`).
9. **Finalised holds keep their data.** On Tempo, `serviceId` and `requestHash` were cleared only to mint storage credits. Stellar has no such credits, and events expire from RPC. `amount` and `deadline` are still reported only while a hold is Held, as before.
10. **Views return `Option`.** `get_hold` and `get_service` return `None` for an unknown id, instead of a zeroed struct. `DOMAIN_SEPARATOR`, `hashVerdict` and `verdictDigest` are replaced by `verdict_message`, and `service_id(owner, label)` is added.
11. **Timeout event.** A distinct `timed_out` event instead of `Refunded` with a zero presentation hash (decision Q2). The status stays `TimedOut`, as on Tempo.
12. **Explicit TTL management** (section 5). Tempo has no state archival.
13. **Owner checks** use `owner.require_auth()`. A missing authorization is a host auth error rather than `NotOwner`.
14. **Event layout.** Snake_case names. An event has at most four topics including its name, so the topics are (name, `call_id`, `service_id`, counterparty), matching the three indexed parameters of the Solidity events.
15. **Constructor.** `__constructor(owner, treasury, fee_bps)` runs atomically with deployment, so there is no initialisation step to front-run. The host reports a failing constructor as a generic error, not the contract's own error code.
16. **Hostile tokens.** The host blocks re-entry; the re-entrancy test is kept. A SEP-41 token cannot "return false", so the `FalseTIP20` test becomes "a token whose transfer traps".
17. **Error codes start at 101.** A failing SAC transfer propagates the SAC's own codes (1–15) through the escrow. With Solidity-style numbering from 1, a client would read the SAC's "insufficient balance" (10) as the escrow's tenth error. The first test run showed exactly this.
18. **JSON hex without `0x`.** `fermata-verdict` prints 32-byte values as plain hex, the form the Stellar CLI takes for `BytesN`; it still accepts Fermata's `0x`-prefixed form.

## 5. Storage, TTL and state archival

- **Instance storage** (owner, treasury, fee): extended to 120 days whenever fewer than 60 remain, on every state-changing call.
- **Service entries** (persistent): the same, at registration and on every `hold`. The 60-day threshold exceeds the longest hold (30-day window plus grace), so a service always outlives its open holds.
- **Hold entries** (persistent, one per call id): extended at `hold` to the window in ledgers (5 s per ledger, rounded up) plus a 7-day grace period for `claim_timeout`. They are not extended after that.
- **The cap.** Every extension is capped at the network's maximum TTL.
- **Archived holds stay usable.** An entry whose TTL runs out is archived, not deleted. A later transaction that touches it restores it (automatically since protocol 23) and sees its real state, so:
  - a finalised hold still blocks its call id;
  - an open hold can still be settled or refunded.

  Both are tested against the host's archival emulation.
- **What archival can cost.** If the network's ledger time fell below 5 s, a hold could archive before its window ends; restoring it costs rent, never funds.
- **Not a security mechanism.** No property depends on TTL expiry, because anyone can extend any entry's TTL. Deadlines are stored in the hold and checked against the ledger timestamp.

## 6. Test mapping

Rust tests live in `contracts/escrow/src/tests/`. Each test's doc comment names the Solidity test
it ports.

### `FermataEscrow.t.sol` (43)

| # | Solidity test | Rust test | Note |
|---|---|---|---|
| 1 | `test_register_storesServiceAndEmits` | `register::register_stores_service_and_emits` | Also checks the stored label and that the id equals the off-chain derivation |
| 2 | `test_register_revertsOnDuplicate` | `register::register_reverts_on_duplicate` | |
| 3 | `test_register_revertsOnZeroId` | n/a | Ids are derived and cannot be zero. |
| 4 | `test_register_revertsWhenIdNotPrefixedBySender` | `register::register_needs_the_owners_authorization` | Registering for another owner without its authorization fails; the same label under two owners gives two different ids. |
| 5 | `test_register_revertsOnZeroAddresses` | `register::register_reverts_on_zero_verifier_key` | Only the all-zero verifier key remains to reject. |
| 6 | `test_register_revertsOnBadPriceOrWindow` | `register::register_reverts_on_bad_price_or_window` | Adds negative prices and the overflow bound, and accepts both bounds |
| 7 | `test_register_revertsOnUnpayablePayout` | `register::register_reverts_on_unpayable_payout` | Payout = escrow; payout = token |
| 8 | `test_hold_viaPermit` | `hold::hold_pulls_the_price_under_the_agents_authorization`, `hold::hold_succeeds_with_exactly_the_documented_authorizations` | Exact auth tree, balances, view, event, one token movement |
| 9 | `test_hold_revertsOnUsedCallId` | `hold::hold_reverts_on_used_call_id` | Also on another service: call ids are global |
| 10 | `test_hold_revertsOnUnknownService` | `hold::hold_reverts_on_unknown_service` | |
| 11 | `test_hold_revertsOnZeroCallIdOrRequest` | `hold::hold_reverts_on_zero_call_id_or_request` | |
| 12 | `test_hold_thirdPartyCannotUseAgentsPermit` | `hold::hold_third_party_cannot_spend_the_agents_balance` | |
| 13 | `test_hold_revertsWhenPermitValueDiffersFromPrice` | `hold::hold_reverts_when_the_authorized_amount_differs_from_the_price` | A wrong amount, and an authorization without the transfer |
| 14 | `test_hold_revertsOnExpiredPermitWithRealError` | n/a | No permits; the host enforces authorization expiry. |
| 15 | `test_hold_succeedsWhenPermitWasFrontRun` | n/a | No permit to front-run |
| 16 | `test_hold_approvePathWithJunkSignature` | n/a | No allowance path |
| 17 | `test_hold_revertsWithoutPermitOrAllowance` | `hold::hold_reverts_without_authorization_or_balance` | Missing authorization, or the SAC's insufficient-balance error (10); nothing recorded |
| 18 | `test_settle_delivered_paysVendorMinusFee` | `settle::settle_delivered_pays_vendor_minus_fee` | Settled with no authorization at all |
| 19 | `test_settle_delivered_feeRoundsToZero_singleTransfer` | `settle::settle_delivered_fee_rounds_to_zero_single_transfer` | |
| 20 | `test_settle_delivered_zeroFee` | `settle::settle_delivered_zero_fee` | |
| 21 | `test_settle_failed_refundsAgentInFull` | `settle::settle_failed_refunds_agent_in_full` | |
| 22 | `test_settle_revertsOnWrongVerifier` | `settle::settle_reverts_on_wrong_verifier`, `settle::a_wrong_verifier_fails_the_ed25519_check` | The second pins the cause as `Error(Crypto, InvalidInput)`. |
| 23 | `test_settle_revertsOnMalformedSignatures` | `settle::settle_reverts_on_malformed_signatures` | Zeroed, bit-flipped, zero-`R` and `S + L` signatures; 0, 63 and 65 bytes rejected by the argument type |
| 24 | `test_settle_revertsOnMismatchedFields` | `settle::settle_reverts_on_mismatched_fields`, `settle::settle_rejects_each_field_tampered_after_signing`, `settle::a_tampered_outcome_fails_the_ed25519_check` | Each mismatch error, then each of the eight fields changed after signing |
| 25 | `test_settle_revertsForVerdictSignedForAnotherEscrow` | `settle::settle_reverts_for_verdict_signed_for_another_escrow` | |
| 26 | `test_settle_revertsForVerdictSignedForAnotherChain` | `settle::settle_reverts_for_verdict_signed_for_another_network`, `settle::another_network_fails_the_ed25519_check` | Mainnet, futurenet and standalone passphrases |
| 27 | `test_digestMatchesIndependentImplementation` | `settle::verdict_message_matches_the_offchain_encoding` | |
| 28 | `test_settle_replayReverts` | `lifecycle::settle_replay_reverts` | |
| 29 | `test_settleAfterTimeout_andTimeoutAfterSettle_revert` | `lifecycle::settle_after_timeout_and_timeout_after_settle_revert` | |
| 30 | `test_unknownCall_reverts` | `lifecycle::unknown_call_reverts` | |
| 31 | `test_settle_atWindowEndSucceeds` | `lifecycle::settle_at_window_end_succeeds` | |
| 32 | `test_settle_afterWindowReverts` | `lifecycle::settle_after_window_reverts` | |
| 33 | `test_timeout_beforeOrAtWindowEndReverts` | `lifecycle::timeout_before_or_at_window_end_reverts` | |
| 34 | `test_timeout_refundsAgent_calledByStranger` | `lifecycle::timeout_refunds_agent_called_by_anyone` | With no authorization at all; the `timed_out` event |
| 35 | `test_constructor_validation` | `admin::constructor_validation` | Fee above 500; treasury = escrow; the constructor's events |
| 36 | `test_admin_onlyOwner` | `admin::admin_only_owner` | No authorization, a stranger's, and the owner's exact tree |
| 37 | `test_admin_setters` | `admin::admin_setters` | |
| 38 | `test_feeSnapshot_changeAfterHoldDoesNotApply` | `admin::fee_snapshot_change_after_hold_does_not_apply` | |
| 39 | `test_reentrantToken_cannotDoubleSpend` | `tokens::reentrant_token_cannot_double_spend` | Re-entry attempts inside the pull and the refund all fail; the flow completes. |
| 40 | `test_tokenReturningFalse_reverts` | `tokens::trapping_token_reverts_the_hold` | |
| 41 | `test_holdsAcrossServicesAreIsolated` | `tokens::holds_across_services_are_isolated` | Two SACs |
| 42 | `testFuzz_feeSplitIsExact` | `props::fee_split_is_exact` | 512 cases, up to `MAX_PRICE` |
| 43 | `testFuzz_foreignSignerNeverSettles` | `props::foreign_signer_never_settles` | 512 random seeds, both outcomes |

### Invariant suite, vectors and Tempo-only tests

| Solidity | Rust test | Note |
|---|---|---|
| `invariant_escrowBalanceEqualsHeld`, `invariant_statusesMatchGhost`, `invariant_conservation`, `afterInvariant` | `invariants::escrow_invariants_hold_under_random_sequences` | All three invariants after every step, with exact balance deltas inside every action. Finalised records keep their data (difference 9). |
| `Vectors.t.sol` `test_rustSignedVerdictSettles` | `vectors::vector_signatures_settle` | DELIVERED releases and FAILED refunds, with the file's signatures |
| `Vectors.t.sol` `test_foundrySignatureEqualsRust` | `fermata-verdict` `vectors::tests`, `tests/cli.rs`; `test-vectors/check_vectors.py` | Ed25519 is deterministic, so the signatures are reproduced exactly. |
| `Vectors.t.sol` `test_requestHashMatchesRust` | `fermata-verdict` `hashes::tests::request_hash_vector` | `0xe8b23a0b…` |
| `AttestVector.t.sol` `test_attestorVerdictCannotSettleAnotherCall` | `settle::verdict_cannot_settle_another_call` | Same structure, with a script-signed verdict |
| The other `AttestVector.t.sol` tests (3) | defer to M1 | Need real presentations |
| `test_tempo_holdViaPermit_thenDelivered`, `test_tempo_failedRefund_andTimeout` | replaced | The unit tests above run on the host's real SAC; `scripts/demo-cases.sh` runs the three cases on a network |
| `test_tempo_frontRunPermit_andApprovePath`, `test_tempo_badPermitBubblesPrecompileError` | n/a | No permits |
| `test_tempo_receivePolicyBlockedPayout_revertsThenTimesOut` | `tokens::blocked_payout_reverts_then_times_out_to_the_agent`, `tokens::blocked_treasury_blocks_release_but_not_refund` | Deauthorized SAC balances (code 11) |

### Stellar-specific tests

- **TTL and archival.** `ttl::a_hold_lives_through_its_window_and_a_grace_period`, `ttl::instance_and_service_entries_are_extended_when_low`, `ttl::ttl_is_capped_by_the_network_maximum`, `ttl::an_archived_finalised_hold_still_blocks_its_call_id` and `ttl::an_archived_open_hold_can_still_be_refunded`.
- **Golden vectors.** `vectors::contract_rebuilds_every_vector_message`, `vectors::contract_derives_the_vector_service_id` and `vectors::vectors_for_other_domains_do_not_settle_here`.
- **Authorization trees.** These are asserted inside tests 8 and 36.
- **Token movements.** Asserted for `hold`, DELIVERED (one or two transfers), FAILED and timeout, as the counterpart of Fermata's memo-movement checks.

### The brief's rejection matrix

| Rejection | Where it is tested |
|---|---|
| Unknown or rotated-out verifier key; a signature from another service's verifier | Tests 22 and 43. Services are immutable (decision Q1), so a vendor rotates by registering a new service, and the old key is "a key the service does not pin". |
| A tampered verdict (each field separately) | Test 24: `settle_rejects_each_field_tampered_after_signing` |
| Wrong call id, service id, request hash or pinned hashes | Test 24. Only `predicate_hash` is in the verdict; `origin_hash` and `notary_key_hash` are pinned in the service and checked off-chain by the attestor, as on Tempo. |
| Settling twice | Test 28 |
| Settling after the timeout | Tests 29 and 32 |
| Claiming the timeout before the window ends | Test 33 |
| A duplicate call id on hold | Test 9 |
| Missing buyer authorization | Tests 12, 13 and 17 |
| Bad amounts | Tests 6 and 17 |
| Non-admin service registration or updates | Tests 4 and 36. Services need the owner's authorization and cannot be updated, and only the escrow owner changes the fee or the treasury (decision Q1). |
| Replay across contracts or networks | Tests 25 and 26, and the golden vectors |

## 7. Decisions

These were the places where the brief and the Fermata repo disagreed. Each recommended option was
taken (2026-10-13).

- **Q1. Who registers services, and can a service change?** Keep Fermata's model.
  - Registration is permissionless, but the id is derived from the authenticated owner, so it is
    squat-proof.
  - Services are immutable. A vendor rotates a verifier by registering a new service.
  - The only role is the escrow owner, who sets the fee and the treasury.
- **Q2. Timeout event.** A distinct `timed_out` event (status `TimedOut`), instead of `refunded`
  with a zero presentation hash.
- **Q3. Branch.** Work is pushed to the session branch `claude/affectionate-shannon-mbtrvx` and
  merged into `main` by the repository owner.

## 8. Reuse and licensing

Fermata is MIT (© 2026 Bilgin Kocak). Its attestor is Apache-2.0 because it ports WebProof, which
is Apache-2.0. This repository is Apache-2.0. Each file copied or ported from either project names
its source repository, path and commit in a header comment, and `NOTICE` lists them with the MIT
notice.

- **The contract.** `contracts/escrow/src/lib.rs` ports `contracts/src/FermataEscrow.sol` @
  `d7cc642`. `contracts/escrow/src/tests/` ports `contracts/test/*.t.sol` case by case.
- **The verdict type.** `crates/fermata-verdict/src/verdict.rs` and `hex32.rs` keep the `Verdict`
  fields, the outcome constants and the hex serde helpers from `apps/attestor/src/eip712.rs` @
  `d7cc642`.
- **The hashes.** `crates/fermata-verdict/src/hashes.rs` is `apps/attestor/src/hashes.rs` @
  `d7cc642`, with its vectors.
- **The predicate.** `predicates/quote-v1.json` is `apps/attestor/predicates/quote-v1.json`, byte
  for byte.
- **The claim pattern.** The tag, canonical bytes, Ed25519 and a text vector file in the
  repository come from WebProof `crates/webproof-core/src/lib.rs` @ `609a654`.
- **Documentation text.** "What the proof does and does not establish", the trust model and the
  security policy are adapted from Fermata `README.md` and `SECURITY.md` @ `d7cc642`, and WebProof
  `docs/trust-model.md`.
