# Porting notes: Fermata from Tempo to Stellar

This file records how Fermata's Tempo implementation maps onto Stellar: what is kept, adapted,
replaced or deferred, and why. Section 4 lists every intentional difference from
`FermataEscrow.sol`.

It was written in Milestone 0, step 1, before any Stellar code. It was updated at the end of the
milestone with the decisions taken (section 7) and what the implementation showed. Section 9 is
Milestone 1 (the attestor and the TypeScript SDK): the plan written before its code, and what the
implementation showed. Section 10 is Milestone 2 (the gateway, its payment methods and reconciliation
from events): the plan, the decisions the owner took before its code, and what the implementation
showed.

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
| `contracts/test/AttestVector.t.sol`, `fixtures/attest-vector.json` | adapt | `contracts/escrow/src/tests/attest_vector.rs` and `test-vectors/attest-v1.json`, written by the ported attestor | M1, done | Real TLSNotary presentations, with verdicts signed for Stellar |
| `contracts/test-tempo/` (real TIP-20 precompile, TIP-403 registry) | replace | Unit tests run against the host's real SAC code, plus the local-network and testnet runs | M0, done (testnet run pending) | The soroban test environment runs the actual Stellar Asset Contract implementation. |
| `contracts/test/mocks/MockTIP20.sol`, `HostileTIP20.sol` | replace | SAC test assets, and a hostile SEP-41 token contract in `tests/tokens.rs` | M0, done | |
| `contracts/script/Deploy.s.sol`, `scripts/deploy-escrow.sh`, `scripts/export-deployment.ts` | replace | `scripts/deploy-testnet.sh`, `deployments/testnet.json` | M0, done | The Stellar CLI replaces Foundry and viem. |
| `scripts/escrow-roundtrip.ts` | adapt | `scripts/demo-cases.sh` | M0, done | Same three outcomes. As in Fermata's own Milestone 1, verdicts are signed by a script-held verifier key over placeholder presentation and response hashes, with no TLSNotary. |
| `scripts/demo/cases.ts` (`demo:cases` through the full stack) | defer | | M2 | Needs the gateway. The attestor's part is `scripts/attest-cases.sh` (M1). |
| `apps/attestor/src/eip712.rs` | replace | `crates/fermata-verdict` (canonical encoding, Ed25519 signing, CLI) | M0, done; the attestor uses it (M1, done) | Stellar verifies Ed25519 natively. |
| `apps/attestor` TLSNotary parts: `prove.rs`, `notary.rs`, `verify.rs` (binding checks 1–7), `predicate.rs`, `http_raw.rs`, `tunnel.rs`, `serve.rs`, `verify --offline` | keep | `apps/attestor`, in its own workspace pinned to Rust 1.95.0 | M1, done | Chain-agnostic. TLSNotary proving, the binding checks and the predicates stay as they are. |
| `apps/attestor/src/hashes.rs` | keep | `crates/fermata-verdict/src/hashes.rs`: request, predicate, origin and notary-key hashes with Fermata's vectors | M0, done | The escrow treats these hashes as opaque 32-byte values, so their definitions do not change. |
| `apps/attestor/src/chain.rs` (hand-rolled `eth_call`) | replace | Soroban RPC simulation of `get_hold` and `get_service`, and the latest ledger's close time | M1, done | |
| `apps/gateway` | defer | A `fermata` MPP method next to Stellar's MPP Charge, and an escrowed x402 scheme next to `exact` | M2 | Its `GatewayChain` interface is the seam. Routing, the call store, the SSRF guard, onboarding and the MCP plumbing are chain-agnostic. |
| `packages/sdk` | adapt | `packages/sdk`: the generated escrow client, the verdict, the hashes (M1, done); MPP and x402 client and server (M2) | M1 / M2 | `tip20.ts`, `escrow.ts`, `verdict.ts`, `serviceId.ts` and `chain.ts` are Tempo-specific. The hashes, the Wilson-score aggregator and `eventually` are reusable. |
| `apps/dashboard` | defer | Reads Soroban events through the gateway | M2 | It reads only the gateway API; the Tempo-specific strings will be replaced. |
| `apps/vendor` | keep | `apps/vendor`, unchanged | M1, done | Chain-agnostic demo vendor (TLSNotary's TLS 1.2 profile, CHAOS failure modes) |
| `apps/attestor/predicates/quote-v1.json` | keep | `predicates/quote-v1.json`, byte for byte (predicateHash `f9607cf2…`) | M0, done | Enforced by the attestor (M1) |
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
| `AttestVector.t.sol` `test_requestHashIsTheProvedRequest` | `attest_vector::request_hash_is_the_proved_request` | Recomputed with the host's SHA-256 |
| `AttestVector.t.sol` `test_attestorDeliveredVerdictReleases` | `attest_vector::attestor_delivered_verdict_releases` | The `released` event carries the presentation hash |
| `AttestVector.t.sol` `test_attestorFailedVerdictRefunds` | `attest_vector::attestor_failed_verdict_refunds` | |
| `AttestVector.t.sol` `test_attestorVerdictCannotSettleAnotherCall` | `attest_vector::attestor_verdict_cannot_settle_another_call`, and `settle::verdict_cannot_settle_another_call` with a script-signed verdict | |
| (new) | `attest_vector::the_contract_rebuilds_the_attestor_messages` | The 294 bytes the attestor signed |
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

## 9. Milestone 1 plan: the attestor and the TypeScript SDK

Written 2026-10-14, before any Milestone 1 code. The escrow and `fermata-verdict` from M0 do not
change.

### Facts checked for M1

| Fact | Value | Source |
|---|---|---|
| TLSNotary | `tlsn` v0.1.0-alpha.15, git only, pinned to rev `47aee45b`. MSRV 1.95, declared by the `mpz` crates. Fermata's lockfile has 325 packages. | Fermata `apps/attestor/Cargo.toml` and `Cargo.lock`; Fermata `docs/FACTS.md` §12 |
| It builds and proves here | Fermata's attestor @ `d7cc642`, built in a scratch copy outside this repository with rustc 1.95.0: the release build took 2 min 58 s on 4 vCPUs. Its MPC integration test passed: five proofs of the demo vendor at 1.4 to 2.1 s each, about 62 MB sent and 3.9 MB received between prover and notary per session, and a 2,132-byte presentation. These numbers come from Fermata's code and the local demo vendor in this container; they are not Stellar measurements. | Scratch run, 2026-10-14 |
| Ledger time | RPC `getLatestLedger` returns `closeTime` (unix seconds) | Local quickstart, RPC 29.0.1 |
| Read-only calls | `simulateTransaction` accepts a transaction whose source account has never existed (`GAAAA…WHF`, sequence 1) and returns the view's value. Reading `get_hold` and `get_service` needs no funded account and no key. | Local quickstart, `get_service` |
| Return values | A `#[contracttype]` struct comes back as an `ScMap` keyed by field-name symbols in sorted order, and `None` as `Void`. | Same |
| TypeScript bindings | `stellar contract bindings typescript` (CLI 28.1.0) generates a typed client: 330 lines, with the contract's doc comments and error codes, depending on `@stellar/stellar-sdk` ^16. The current release is 17.2.1 (Node 22.12 or newer). | CLI; npm registry |
| Local image | `stellar/quickstart@sha256:4f8dfd69…` (stellar-core 29.0.0, RPC 29.0.1), started with `--protocol-version 29` | `docker inspect` |

### Components

| Fermata (`apps/attestor` @ `d7cc642` unless named) | Decision | On Stellar |
|---|---|---|
| `prove.rs`, `notary.rs`, `tunnel.rs`, `http_raw.rs`, `predicate.rs`, `config.rs` | keep | `apps/attestor/src/`, copied with a source header. **Unchanged:** MPC-TLS through a separate notary; hiding the values of `Authorization`, `Cookie` and `Proxy-Authorization`; SECP256K1ETH attestations; retries and timeouts; the CONNECT tunnel; the content-addressed predicate store. |
| `verify.rs` | keep, re-wired | The same seven binding checks in the same order, the same session-time skew, the same predicate stage, and `reverify` for `--offline`. Signing goes through `fermata-verdict`. |
| `eip712.rs` | replace | `crates/fermata-verdict` as a path dependency: Ed25519 over the section 3 message, with the network passphrase and the escrow contract id as the domain |
| `hashes.rs` | replace by the M0 port | `fermata-verdict::hashes`: the same definitions and vectors |
| `chain.rs` | replace | `SorobanChain`, using the `stellar-xdr` crate for XDR. **Reads:** `simulateTransaction` of `get_hold` and `get_service` from the null source account, and `getLatestLedger.closeTime` for chain time. **Startup:** `getNetwork` checks the passphrase. The `ChainView` trait and `MockChain` stay. |
| `serve.rs` | keep, re-wired | **Same API:** `/healthz`, `/v1/prove`, `/v1/verify`, `/v1/attest`, `/v1/reverify` and `/v1/presentations/<callId>`, with the same error codes (422 for a failed binding check, 502 when there is no transcript) and proving in a child process. **Changed:** `/healthz` reports the network, the escrow and the verifier's `G…` key. |
| `main.rs` | adapt | **Same subcommands:** `notary`, `prove`, `verify [--offline]`, `serve`, `hashes`. **Chain flags:** `--network testnet\|local\|mainnet` (or `--network-passphrase`), `--rpc` (`STELLAR_RPC_URL`) and `--escrow C…` (`FERMATA_ESCROW`). **Key:** the verdict key comes from `FERMATA_VERIFIER_SECRET` (`S…` or hex), as in the `fermata-verdict` CLI. |
| `tests/attest.rs` | adapt | **Unchanged:** real MPC sessions against the demo vendor (ok, 500, truncated, hang) through a notary process, a `MockChain`, one negative case per binding check, tampering, and no transcript. **Changed:** signatures are checked with `fermata-verdict::verify` instead of `ecrecover`, and the test writes `test-vectors/attest-v1.json`. |
| `contracts/test/AttestVector.t.sol` (the 3 deferred tests) | adapt | `contracts/escrow/src/tests/attest_vector.rs`. The escrow is registered at the vector's contract id and settles the real DELIVERED and FAILED verdicts from `attest-v1.json`. |
| `apps/vendor` | keep | `apps/vendor`, unchanged: TLS 1.2 with ECDHE-ECDSA-AES128-GCM-SHA256 on P-256, and the CHAOS modes |
| `scripts/e2e-attest.sh`, `scripts/attest-e2e.ts` | adapt | `scripts/attest-cases.sh` (bash and the Stellar CLI, like M0's scripts), for `NETWORK=local` and `NETWORK=testnet` |
| `packages/sdk`: `hashes.ts`, `requestHash.ts` | keep | `packages/sdk/src/`, on `@noble/hashes` instead of viem, with Fermata's TypeScript vectors |
| `packages/sdk`: `serviceId.ts`, `verdict.ts` | replace | The Stellar versions: the service id from the owner's address XDR, the 294-byte verdict message, and Ed25519 signing and verification |
| `packages/sdk`: `abi.ts`, `escrow.ts`, `chain.ts`, `tip20.ts`, `deployments.ts` | replace | The generated client (`stellar contract bindings typescript`), committed. A CI check regenerates it from the built Wasm and fails if the file changes. |
| `packages/sdk`: `method.ts`, `client.ts`, `server.ts`, `scores.ts`, `logs.ts`, `eventually.ts` | defer | M2: the MPP and x402 methods, reconciliation and scores |

### Differences from Fermata's attestor

1. **Verdict output.** Verdicts are signed with Ed25519 through `fermata-verdict`. The JSON gives
   the 294-byte message, the 64-byte signature and the signer's `G…` key, instead of the EIP-712
   digest, the 65-byte signature and an address.
2. **Chain reads** go through Soroban RPC simulation. An unknown call is `None` from `get_hold`,
   read as Fermata's status 0. The re-read of an unknown hold (for up to 6 s, because a
   load-balanced RPC can lag behind the hold) is kept.
3. **Flag and variable names** follow Stellar, as listed under `main.rs` above.
4. **Hashes kept.** `presentation_hash` and `response_hash` stay keccak256 of the presentation and
   of the received bytes. The escrow treats them as opaque values.
5. **JSON hex without `0x`**, as in M0 (difference 18), in all of the attestor's JSON. Two places
   keep Fermata's `0x` form: the `X-Fermata-Call` header the vendor receives and the file names of
   stored presentations.
6. **The `User-Agent`** the prover sends names this repository.
7. **The vector** is written to `out/attest-v1.json`. `FERMATA_UPDATE_VECTORS=1` replaces the
   committed `test-vectors/attest-v1.json`, so routine runs do not modify a tracked file; Fermata's
   test overwrote its Foundry fixture each time.

### The three canonical cases with real proofs

`scripts/attest-cases.sh` runs after `scripts/deploy-testnet.sh` on the same network:

1. **Start the processes.**
   - Three demo vendors (ok, 500, hang) on local ports.
   - A notary with a key generated for this run. The key exists only in the script's memory, so
     nothing secret is written anywhere.
   - `fermata-attest serve`, with the verifier key from the keystore.
2. **Register three services** (labels with a run suffix). They pin the vendors' origins, that
   notary's key hash, `predicates/quote-v1.json` and the verifier key.
3. **DELIVERED.** Hold, then `POST /v1/attest`, then settle with the attestor's verdict. Checks:
   - the vendor is paid, and the `released` event carries the presentation hash;
   - the downloaded presentation's keccak256 equals that hash;
   - `verify --offline`, given the hashes read from `get_service` and `get_hold`, reports the same
     outcome and no mismatch;
   - the `Authorization` value is not in the presentation.
4. **Replay.** A new hold for the same request: the old presentation fails the Call check.
5. **FAILED.** The vendor's authenticated 500 gives a FAILED verdict, and settling refunds the
   agent.
6. **NO PROOF.** The vendor never answers: HTTP 502 `no-transcript` and no verdict. After the
   window, `claim_timeout` refunds the agent, for this hold and the replay hold.

The script prints stellar.expert links on testnet and exits non-zero if any check fails.

### CI

- **attestor**: Rust 1.95.0, fmt, clippy `-D warnings`, the unit tests, and the MPC integration
  test (it needs `node` and `openssl`; the runner has both).
- **sdk**: Node 22, pnpm through corepack, typecheck, tests, and the bindings drift check.
- **e2e**: the quickstart image pinned by digest, then `deploy-testnet.sh` and `attest-cases.sh`
  with `NETWORK=local`.

### Not in M1

- **Moved to M2:** the gateway and the payment methods (MPP, x402), the dashboard, the MCP server,
  vendor scores, session escrow and sampled proving.
- **Ported but not run in CI:** proving a third-party vendor (Fermata's npm registry test), kept as
  an ignored test.
- **Still blocked:** the testnet run needs the same network access as M0's.

### What the implementation showed

Written at the end of the milestone.

- **The plan held.** The six modules that do not touch the chain were copied unchanged, apart
  from one line `cargo fmt` wraps. `chain.rs` and the signer were replaced, and the rest was
  re-wired. The escrow and `fermata-verdict` did not change.
- **Workspaces.** `fermata-verdict` works as a path dependency of the attestor's own workspace,
  including its workspace-inherited fields. The attestor's lockfile is Fermata's, extended only by
  the new dependencies.
- **Real proofs.** The integration test passes with real MPC-TLS sessions: each proof took 1.1 to
  2.2 s, with about 62 MB sent and 3.9 MB received between prover and notary. Across two runs, 3
  of 10 sessions stalled in MPC setup and succeeded on the second attempt, which matches Fermata's
  report of stalls during setup.
- **The full path.** `scripts/attest-cases.sh` passed 3/3 on its first run against a local
  network, in about three minutes, most of it the timeout case's window. The run exercised the
  simulated `get_hold` and `get_service` reads, the offline re-verification against the chain,
  and the replay refusal.
- **The SDK and `@stellar/stellar-sdk` 17.** CLI 28.1.0 generates a client for
  `@stellar/stellar-sdk` 16. With version 17 the client returns `Uint8Array`s where its generated
  types promise `Buffer`s; the live test against a local deployment caught this, so the SDK
  depends on `^16.3.1`, the line still maintained alongside 17.
- **Compiler settings.** The generated client does not compile under `noImplicitOverride`. The
  file is kept as generated and that one option is off.
- **Tests ported from Fermata's `tests/attest.rs`.** `attestor_end_to_end`, `soak` and
  `real_vendor_npm`; the last two stay ignored. Fermata's two ABI unit tests (selector and word
  decoding) are replaced by five XDR tests.
- **The first proof's time bound.** Fermata's `attestor_end_to_end` requires the first proof to
  finish within 10 s. The test's own retry policy allows more: an attempt that stalls in MPC
  setup is cut off after 5 s and retried, up to three attempts. In CI run 20 two attempts stalled
  in a row, the third proved in under a second, and the whole took 10.9 s, so the test failed
  although the prover behaved as designed. The bound is now 10 s plus 5 s per retried attempt. A
  stall after setup still breaks it, because such an attempt runs to its full 15 s.

## 10. Milestone 2 plan: the gateway on Stellar

Written 2026-10-14, before any Milestone 2 code. The decisions at the end were taken by the
repository owner before the code was written.

### Facts checked for M2

| Fact | Value | Source |
|---|---|---|
| Fermata's gateway | `apps/gateway`: Hono 4.13.8, `@hono/node-server` 2.1.1, mppx 0.11.0, undici. The `fermata` method is `packages/sdk/src/method.ts`, `server.ts` and `client.ts`; scores, log scanning and `eventually` sit next to them. `apps/dashboard` is React 19 and Vite 7, about 1,700 lines, and reads only the gateway's API. | Fermata @ `d7cc642` |
| mppx | The current release is 0.13.4 (2026-10-08). The type definitions Fermata's code uses (`Method`, `Store`, `Challenge`, `Credential`, `Receipt`, `Errors`, `mppx/server`, `mppx/client`, `mppx/hono`, discovery) are identical in 0.10.1 and 0.11.0. | npm; package contents compared |
| Stellar's MPP payment method | `@stellar/mpp` 0.7.1 (npm, 2026-07-02) declares the peers `mppx ^0.6.29` and `@stellar/stellar-sdk ^15.1.0`; this repository's generated client needs stellar-sdk 16. Its `main` branch @ `90394ec` (2026-10-13, unreleased) declares `mppx ^0.10.1` and `@stellar/stellar-sdk ^16.3.0`. Pinned by commit, pnpm installs and builds it next to stellar-sdk 16.3.1 and mppx 0.10.1 with no peer warning. Charge has a pull mode (the client signs Soroban auth entries; the server submits and may pay the fee) and push modes (the client submits and sends the hash). | npm; `stellar/stellar-mpp-sdk` `CHANGELOG.md` and `package.json`; a scratch install |
| x402 on Stellar | `@x402/core`, `@x402/stellar` and `@x402/hono` 2.28.0 (2026-09-29); `@x402/stellar` depends on `@stellar/stellar-sdk ^16.3.0`. Stellar has only the `exact` scheme: the client signs the auth entries of a SEP-41 `transfer`, and the facilitator rebuilds the transaction, pays the fee and submits it. Schemes are pluggable through client, server and facilitator interfaces in `@x402/core`. | npm; `x402-foundation/x402` @ `e95b066` `specs/schemes/exact/scheme_exact_stellar.md`; `@x402/core` types |
| An escrow scheme in x402 | `auth-capture` (draft v1.1, 2026-08-18) has an `escrow` flow: `authorize` holds the funds before the resource runs, then `capture` or `void`, and the client can `reclaim` after a capture deadline. Only an EVM binding exists. The scheme also has partial capture and `refund` after capture, which Fermata's escrow does not have. | `specs/schemes/auth-capture/scheme_auth_capture.md` |
| OpenZeppelin's x402 facilitator | The hosted facilitator (`channels.openzeppelin.com/x402/testnet`, API key from a web form) is the Relayer plugin `@openzeppelin/relayer-plugin-x402-facilitator` 0.5.0. It accepts only `exact` (`schemes = ["exact"]`, and `verify` rejects any other scheme) and is AGPL-3.0, like the Relayer itself. | `OpenZeppelin/relayer-plugin-x402-facilitator` @ `7583ebc` `src/types.ts`, `src/stellar/verify.ts`; `OpenZeppelin/openzeppelin-relayer` @ `6646ed9` `LICENSE` |
| OpenZeppelin's Channels service | `@openzeppelin/relayer-plugin-channels` 0.21.0 submits any Soroban invocation given as `func` plus signed `auth` entries, through channel accounts, with a fee bump paid by its fund account. It is hosted at `channels.openzeppelin.com/testnet` (API key from a web form) or runs in a self-hosted Relayer. Its `package.json` declares MIT and its repository's `LICENSE` file is AGPL-3.0; this repository uses only its HTTP API. | `OpenZeppelin/relayer-plugin-channels` @ `c7cf073`, README "Submit with Function and Auth", `package.json`, `LICENSE` |
| Networks in those libraries | `@stellar/mpp` and `@x402/stellar` know only the testnet and mainnet passphrases; their RPC URLs can be changed. The quickstart image reads `NETWORK_PASSPHRASE` from the environment in `--local` mode, and a local network started with the testnet passphrase reported it from `getNetwork`. | `@stellar/mpp` `sdk/src/constants.ts`; `@x402/stellar` 2.28.0; quickstart `/start` line 252; a local run |
| Events | Stellar RPC keeps transactions and events for `history-retention-window` = 120,960 ledgers (about 7 days) by default. `getEvents` returns 100 events by default and at most 10,000 per call (`max-events-limit`). Providers choose their own values. Older history needs a Galexie data lake, Hubble (BigQuery) or a third-party indexer (Mercury, SubQuery, Goldsky). | `stellar/stellar-rpc` @ `40277d1` `cmd/stellar-rpc/internal/config/options.go`; SDF skill `data/SKILL.md` |
| Session escrow, sampled proving | Not built in Fermata. Its README lists them under "The production shape, none of it built yet", and notes that sampling changes the guarantee: an unproved call cannot be proved later. | Fermata `README.md`, "Economics" |

### Components

| Fermata | Decision | On Stellar |
|---|---|---|
| `packages/sdk` `method.ts`, `server.ts`, `client.ts` (the `fermata` method for mppx) | adapt | **Kept:** the server mints the call id inside an HMAC-bound challenge; the client checks the escrow, the verifier, the price and the window against its allow-lists before it holds; the server checks the hold and claims the call id once. **Changed:** `chainId` becomes the CAIP-2 `network`. As in Stellar's Charge, there are two credential types: `transaction` (the agent signs the auth entries of `hold`, and the gateway submits it and pays the fee) and `hash` (the agent submits `hold` itself and sends the transaction hash). The server checks the `held` event, the hold and the deadline. |
| (none) | new | **An escrowed x402 scheme**, `fermata` (decisions 2 and 3), with client, server and facilitator parts on `@x402/core`. The payload is a transaction with one `hold` invocation and its signed auth entries. The facilitator applies the checks of `exact` on Stellar to `hold`: one invocation of the trusted escrow with the requirement's service, call id and request hash; one sub-invocation, the token transfer of the price to the escrow; an expiry bound; the facilitator absent from every auth entry; a simulation that succeeds with only that balance change. Settling submits the hold. Capture and void are the verdict's `settle`, and reclaim is `claim_timeout`. |
| `apps/gateway` | adapt | **Kept:** the paid route `/s/:serviceId/*` (402, hold, fulfil through the attestor, verdict, `settle`, response with a receipt), the call store, the sweeper (`claim_timeout` after the window), admission control and the read API (`/services`, `/scores`, `/calls`, `/proofs`, `/ca.pem`, `/predicates/:hash`, `/info`, `/events`, `/reconcile/:callId`, `POST /proofs/:callId/verify`, discovery). **Changed:** one 402 offers four ways to pay, the MPP `fermata` method and Stellar's Charge, and the x402 escrowed scheme and `exact`. Charge and `exact` pay the vendor directly, without escrow or proof, like Fermata's `tempo` fallback; their receipts say `unprotected`. `GatewayChain` is reimplemented on Soroban RPC, with the relayer key from the keystore. |
| `scores.ts`, `logs.ts`, `eventually.ts`, `reconcile` in `escrow.ts` | adapt | The Wilson-score ranking over `service_registered`, `held`, `released`, `refunded` and `timed_out` (a timeout is its own event here). Reconciliation joins each call's escrow events with the token's `transfer` events in the same transactions, instead of filtering TIP-20 memos. |
| (none) | new | **An indexer** (see the note after the decisions): it polls `getEvents` for the escrow's events and for the token transfers to and from the escrow, stores them on disk with a cursor and resumes after a restart. The gateway and the reconciliation read from it. Its history starts when it first runs, or 7 days earlier at most. |
| `apps/dashboard` | adapt | The same views (live feed, the per-call proof drawer with offline re-verification, reconciliation, scores), with Stellar addresses, 7-decimal amounts, stellar.expert links and the `timed_out` outcome |
| `scripts/e2e-gateway.sh`, `apps/gateway/test/e2e.test.ts` | adapt | `scripts/gateway-cases.sh`: the three canonical outcomes paid through the gateway with MPP and with x402, each call then reconciled from the indexer's events, on a local network and in CI |
| `onboard.ts`, `public.ts`, `limits.ts`, `mcp.ts`, `apps/mcp`, `deploy/` | defer | Vendor onboarding is M3 in the roadmap. The public demo, the MCP server and hosting come after M2. |

### Testing and CI

- **Unit tests.** The method and the scheme against a mock chain, with the cases of Fermata's
  `gateway.test.ts`; the indexer and the reconciliation against recorded events; the scores.
- **End to end in CI.**
  - The stack: a quickstart network with the testnet passphrase (so Stellar's Charge and x402
    `exact` run unmodified), the escrow, three vendors, a notary, the attestor, the gateway and an
    agent. Every way to pay is exercised.
  - `exact` is facilitated in process with `@x402/stellar` and the relayer key, because hosted
    facilitators cannot reach a local network.
  - A local network with testnet's passphrase only uses keys made for the run, never testnet keys.
- **Testnet.** Commands for the owner, because this environment cannot reach testnet.
  OpenZeppelin's API keys and Circle's USDC faucet are web forms, so they cannot be scripted.

### Decisions

The repository owner took the recommended option on each question (2026-10-14).

1. **Stellar's Charge.** Its npm release needs stellar-sdk 15 and mppx 0.6, and this repository
   uses stellar-sdk 16. `@stellar/mpp` is pinned to `main` @ `90394ec` (unreleased), with mppx
   0.10.1, until the next npm release ships.
2. **Who submits the escrowed x402 scheme's holds.** The roadmap said "settled through the
   OpenZeppelin Relayer facilitator", but that facilitator accepts only `exact`. The scheme's
   facilitator runs in the gateway. It submits holds through OpenZeppelin's Channels service (the
   Relayer plugin that pays the fees) when an API key is set, and from the gateway's relayer
   account otherwise. `exact` goes through OpenZeppelin's x402 facilitator.
3. **The scheme's name** is `fermata`. It is documented as the escrow flow of `auth-capture`
   without partial capture or refund after capture.
4. **Session escrow and sampled proving.** Both need new contract functions, so a new deployment
   (the escrow cannot be upgraded), and sampling changes the guarantee. The gateway, both methods
   and reconciliation come first. A separate design then goes to the owner for approval before
   any code: [`session-escrow.md`](session-escrow.md), approved on 2026-10-14 with the
   recommended options.

The indexer is our own unless the owner prefers a third-party one: it runs on a local network
and in CI, and keeps history from the moment it starts.

### What the implementation showed

Written when the gateway half of Milestone 2 was done. Session escrow and sampled proving are not
started (decision 4).

- **The plan held.** Every component in the table above was built as planned, and neither the
  escrow nor the attestor changed. `scripts/gateway-cases.sh` passes its 8 calls and 42 checks on a
  local network and in CI.
- **One name changed.** The plan called the credential for a hold the agent submits itself `hash`,
  after Stellar's Charge. It is `hold`, the name of Fermata's credential, whose payload it keeps;
  `transaction` is the new one.
- **Stellar's libraries on a local network.**
  - **Passphrases.** `@stellar/mpp` and `@x402/stellar` know only testnet's and mainnet's
    passphrases. A quickstart network started with testnet's passphrase (`NETWORK_PASSPHRASE`)
    runs both unmodified; CI does this, with keys made for the run.
  - **HTTPS.** Stellar's Charge refuses a plain-HTTP RPC URL, since it sets no `allowHttp`. On a
    local network the gateway and the agent therefore reach the RPC through a small HTTPS proxy
    with a certificate made for the run (`scripts/lib/tls-proxy.mjs`).
  - **Ports.** The quickstart image uses ports 8001 to 8004 itself (8001 is its Horizon), so the
    proxy listens on 7443.
  - **Assets.** x402 clients refuse assets outside a default list. The agent in the cases allows
    any asset (`spendControls: { allowedAssets: true }`), because a local network's token is
    self-issued.
- **One pending transaction per account.** Stellar answers `TRY_AGAIN_LATER` to a second
  transaction from an account that has one pending, and `txBadSeq` to a stale sequence number. The
  relayer and the agent's own holds rebuild and resubmit in those cases, and the SDK's live test
  files run one after another.
- **The pinned dependency.** pnpm recorded `@stellar/mpp`'s commit as an SSH git URL, because its
  probe for a public repository fails behind this build environment's proxy. CI has no SSH key,
  so it could not clone it. The dependency is now an HTTPS git URL at the same commit.
- **CI caught a race.** In one CI run, the x402 release (B1) settled correctly but its record lost
  the hold transaction.
  - **Cause.** The sweeper had listed the call while its hold was being submitted. It then wrote
    over the record the request had moved on, because a record update is a read-modify-write.
  - **Fix.** Calls are now in flight from before their first record. The sweeper skips them and
    reads each record again before acting, and two tests reproduce the interleavings.
- **Process cleanup.** The cases script recorded the pid of the subshell that started the gateway,
  so the gateway outlived the script. The subshell now execs it.
- **The RPC's scan window.** stellar-rpc scans at most 10,000 ledgers per `getEvents` request
  (`LedgerScanLimit`, stellar-rpc @ `40277d1`). A page that ends at that window is short, with a
  cursor at the window's last ledger.
  - **The bug.** The indexer took any short page for the end of the history. Local networks and CI
    never had 10,000 ledgers, so nothing showed it; on testnet, an escrow deployed more than about
    14 hours earlier would have been read only in part.
  - **The fix.** The indexer now reads until its cursor reaches the RPC's latest ledger, and a test
    with a windowed fake RPC covers it.
- **The attestor on a custom passphrase.** `fermata-attest` needs `--rpc` for any network other
  than testnet and mainnet, and the scripts now always pass it. A CI run caught this when the
  scripts began naming a local network by its passphrase.
- **OpenZeppelin's Channels plugin.** Its `package.json` declares MIT, while its repository's
  `LICENSE` file is AGPL-3.0. This repository uses only its HTTP API, through a small client
  written against the documented request and answer, so no code is copied.
- **Measured here.** On a local network, each proof in the M2 cases took 1.1 to 1.3 s across two
  runs, with one attempt each. The CI step takes about three minutes, most of it waiting out the hang cases'
  120 s window. Neither has been measured on testnet.
- **Not tried yet:** testnet, OpenZeppelin's hosted Channels service and x402 facilitator, and
  Circle's USDC faucet. The build environment's network policy refuses all of them.

## 11. Session escrow, phase 1: what the implementation showed

Written when phase 1 was built (every call proved, k = 1). Sessions are new in this repository:
Fermata on Tempo has none, so nothing here is ported. The design is
[`session-escrow.md`](session-escrow.md), approved with decisions 2 to 4 on 2026-10-14.

- **What was reused.**
  - **Unchanged:** the escrow and the verdict.
  - **Reused in the new code:**
    - the attestor's proving, notary, binding checks and predicates, for each session call;
    - the helpers behind the sponsor's checks of a hold (the authorization entry's credentials
      and signature, the simulation's events), in `checkSponsoredOpen`;
    - the gateway's sweeper, which now also settles and closes sessions, and the SDK's indexer,
      which also follows the session contract.

    The gateway's session store is new, modelled on its store of calls.
  - **How the session contract reads the escrow:** through its own copy of the escrow's `Service`
    type, so the escrow needed no new function.
- **Cost.** Measured on the Wasm and on a local network; section 10 of `session-escrow.md` has the
  numbers. At B = 1,000 the transaction's size is the closest limit, not CPU.
- **MPC setup stalls, twice in CI.** The attestor cuts off an attempt whose MPC setup stalls
  (inside TLSNotary) and retries it.
  - **Run 20.** Two attempts in a row stalled before the first proof of `attestor_end_to_end`, so
    that proof took 10.9 s, over the test's 10 s bound, although the retry worked. The bound now
    allows for retried attempts (section 9).
  - **Run 21.** All three attempts of the third session call in `gateway-cases.sh` stalled. The
    attestor recorded the call UNANSWERED, the gateway settled it as a refund and the session
    reconciled, all as designed, but the case expected DELIVERED.
  - **A measurement.** A 40-proof soak (`soak` in `apps/attestor/tests/attest.rs`, 5 s setup
    timeout) on a 4-vCPU machine running a local network: 9 of 49 attempts stalled, and every
    retry after a stall succeeded. While an attempt is stalled the notary uses no CPU, so the
    stall is a wait on both sides, not a lack of CPU.
  - **The change.** At that rate, 3 attempts leave about 1 proof in 160 with no transcript. The
    scripts that start an attestor now give it 5 attempts (`ATTEST_ATTEMPTS` in
    `scripts/lib.sh`), where Fermata's scripts give 3. The attestor's own default stays 3. In a
    local run of `gateway-cases.sh` after the change, 3 of its 7 proofs needed a second attempt,
    and all its checks passed.
- **Reconciling a shared session contract.** One session contract serves every service of its
  escrow, but a gateway knows only its own services' tokens, and the contract's events name no
  token. A local run against a deployment that still had sessions of another service open failed
  the contract-wide check: their deposits were in the balance but in no token's open deposits.
  Reconciliation now takes a session's token from its deposit's transfer when the service is not
  the caller's, and lists a session in a token the index does not follow as untracked.
- **Not tried yet:** testnet. The build environment's network policy refuses it, as before.
