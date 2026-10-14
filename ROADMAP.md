# Roadmap

The milestones follow the Stellar Community Fund's tranche structure. Milestones 0 and 1, the
gateway of Milestone 2 and phase 1 of its session escrow are this repository today; their testnet
runs are pending. Everything else is planned and not built yet. Each milestone ends with something
a reviewer can run.

## M0 — The escrow on Stellar (done)

- **The escrow.** `FermataEscrow.sol` ported to Soroban with the same state machine, role, fee
  rules, checks and events (`contracts/escrow`).
- **The verdict.** An Ed25519 verdict over a domain-separated, fixed-width encoding, verified
  natively, with golden vectors that three implementations agree on (`crates/fermata-verdict`,
  `test-vectors/`).
- **Tests.**
  - Fermata's Solidity suite, ported case by case.
  - The rejection matrix, event and authorization checks, TTL and archival.
  - Randomized properties and invariants (85 tests in the workspace at the end of M0).
- **Scripts.** `scripts/deploy-testnet.sh` and `scripts/demo-cases.sh`. They run 3/3 on a local
  network. The testnet run is pending, because the build environment cannot reach testnet; the
  README has the exact commands.

In M0 the verifier key signs verdicts directly; no TLSNotary proof is involved yet.

## M1 — MVP: proofs on Stellar (done, except the testnet run)

- **`fermata-attest`, ported** (`apps/attestor`), in its own workspace pinned to Rust 1.95.0 with
  TLSNotary `v0.1.0-alpha.15`, as in Fermata.
  - **Unchanged:** TLSNotary proving, the notary, the seven binding checks (notary, origin,
    request, predicate, hold, call id, session time) and the predicates.
  - **Replaced:** the EIP-712 signer is `fermata-verdict`, and the `eth_call` chain reader is
    Soroban RPC simulation of `get_hold` and `get_service`, plus the latest ledger's close time.
  - **Tested** with real MPC-TLS sessions against the demo vendor and one negative case per
    binding check. The verdicts it signed settle on the escrow (`test-vectors/attest-v1.json`, the
    port of Fermata's `AttestVector` tests).
- **The full proof path for the three canonical cases** (`scripts/attest-cases.sh`):
  - hold → MPC-TLS proof → verdict → settle;
  - every settled verdict's presentation re-verifies offline (`verify --offline`) against the
    hashes on chain;
  - an old proof cannot settle a new hold.

  It passes 3/3 on a local network (protocol 29) and in CI. **The testnet run is pending:** the
  build environment cannot reach testnet, and the README has the commands.
- **TypeScript SDK** (`packages/sdk`), with golden-vector parity:
  - the typed escrow client the Stellar CLI generates;
  - the verdict message and Ed25519 signatures;
  - the service id and request hash, as in `test-vectors/verdict-v1.json`.

  A live test checks a deployment's views against it.

Done when the three cases pass on testnet with real presentations and their offline
re-verification matches the chain. Everything but the testnet run is in place.

## M2 — Testnet product on Stellar (the gateway and session phase 1 done, testnet run pending)

- **Done: a `fermata` MPP method** next to Stellar's MPP Charge, so an agent's paid request is held
  in escrow and settled on proof (`packages/sdk/src/mpp`, `apps/gateway`).
  - The agent signs only the authorization of `hold`, and the gateway submits it and pays the fee.
  - Or the agent submits the hold itself and sends its hash.
- **Done: an escrowed x402 scheme, `fermata`,** next to the `exact` scheme
  (`packages/sdk/src/x402`).
  - OpenZeppelin's x402 facilitator accepts only `exact`, so the escrowed scheme's facilitator runs
    in the gateway. It submits holds through OpenZeppelin's Channels service (the Relayer plugin
    that pays the fees) when an API key is set, and from the gateway's relayer otherwise.
  - `exact` goes through OpenZeppelin's facilitator when one is configured.
  - Neither hosted service has been tried yet: the build environment cannot reach them.
- **Done: dashboard and reconciliation from Soroban events.**
  - The escrow's `held`, `released`, `refunded` and `timed_out` events, joined with the Stellar
    Asset Contract's transfer events, through an indexer, because RPC keeps events for only about
    7 days.
  - Every call reconciles, and so does the escrow as a whole: per token, the balance against the
    open holds and the chain.
  - The dashboard is Fermata's, ported.
- **The cases.** `scripts/gateway-cases.sh` pays a vendor through the gateway with both methods
  (the three outcomes each, plus Stellar's MPP Charge and x402 `exact`) and reconciles every
  outcome. It passes on a local network and in CI. **The testnet run is pending:** the build
  environment cannot reach testnet, and the README has the commands.
- **Done: session escrow, phase 1** (every call proved, k = 1). The owner approved the design on
  2026-10-14 ([`docs/session-escrow.md`](docs/session-escrow.md)).
  - **The session contract** (`contracts/session`): one deposit for up to N calls of a service,
    settled in batches the verifier signs, next to the escrow, whose registry, fee and treasury it
    reads.
  - **The attestor** proves each session call against the agent's ticket and signs the batch
    statements.
  - **The gateway** sells sessions through the `session` intent of the `fermata` MPP method,
    settles them in batches and closes them after their deadline.
  - **Reconciliation** covers sessions, one by one and the contract as a whole.
  - **The cases.** `scripts/session-cases.sh` (script-signed statements) and a session through the
    gateway in `scripts/gateway-cases.sh` pass on a local network and in CI. **The testnet run is
    pending**, as above.
- **Next: sampled proving, phase 2** (prove a random subset the vendor cannot predict, k > 1). The
  contract already settles sampled batches. What remains is the attestor's unproved path with
  padding, then a measurement of whether a vendor can tell proved calls apart, then the gateway's
  sampling, switched on only if the measurement supports it. The guarantee for k > 1 (decision 1
  of the design) is open until then. x402 sessions are not planned yet.

Done when an agent pays a vendor through the gateway on testnet with both methods, and every
outcome reconciles from events. For that, everything but the testnet run is in place.

The plan and the decisions behind it are in
[`docs/PORTING_NOTES.md`](docs/PORTING_NOTES.md#10-milestone-2-plan-the-gateway-on-stellar),
section 10.

## M3 — Mainnet and UX

- **Mainnet deployment**, after the audit.
- **Vendor onboarding**: listing an API, checking it against TLSNotary's TLS profile, drafting
  its delivery predicate.
- **A security audit** of the escrow and the attestor.
- **The first design-partner APIs.**

## Trust minimization

Planned, in order:

- **An independent notary.** A partner or the vendor runs the notary with its own key, so the
  verifier can no longer produce a transcript the server never sent. Services pin the notary key
  hash already, so no contract change is needed.
- **Vendor-chosen verifiers.**
- **An N-of-M verifier quorum.**
- **Research into on-chain presentation verification.** The escrow would check the evidence
  itself instead of a signature over it.
