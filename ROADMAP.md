# Roadmap

The milestones follow the Stellar Community Fund's tranche structure. Milestone 0 is this
repository today. Everything after it is planned and not built yet. Each milestone ends with
something a reviewer can run.

## M0 — The escrow on Stellar (done)

- **The escrow.** `FermataEscrow.sol` ported to Soroban with the same state machine, role, fee
  rules, checks and events (`contracts/escrow`).
- **The verdict.** An Ed25519 verdict over a domain-separated, fixed-width encoding, verified
  natively, with golden vectors that three implementations agree on (`crates/fermata-verdict`,
  `test-vectors/`).
- **Tests.**
  - Fermata's Solidity suite, ported case by case.
  - The rejection matrix, event and authorization checks, TTL and archival.
  - Randomized properties and invariants (85 tests in the workspace).
- **Scripts.** `scripts/deploy-testnet.sh` and `scripts/demo-cases.sh`. They run 3/3 on a local
  network. The testnet run is pending, because the build environment cannot reach testnet; the
  README has the exact commands.

In M0 the verifier key signs verdicts directly; no TLSNotary proof is involved yet.

## M1 — MVP: proofs on Stellar

- **Port `fermata-attest`** (Rust, TLSNotary `v0.1.0-alpha.15`) into its own workspace pinned to
  Rust 1.95.0, as in Fermata.
  - **Unchanged:** TLSNotary proving, the notary, the seven binding checks (notary, origin,
    request, predicate, hold, call id, session time) and the predicates.
  - **Replaced:** the EIP-712 signer becomes `fermata-verdict`, and the `eth_call` chain reader
    becomes Soroban RPC reads of `get_hold`, `get_service` and the ledger time.
- **Run the full proof path on Stellar testnet** for the three canonical cases: hold → MPC-TLS
  proof → verdict → settle. Every verdict must re-verify offline against the on-chain values with
  `verify --offline`.
- **TypeScript SDK bindings** for the escrow, with golden-vector parity: the same verdict message,
  service id and request hash as `test-vectors/verdict-v1.json`.

Done when the three cases pass on testnet with real presentations and their offline
re-verification matches the chain.

## M2 — Testnet product: the gateway on Stellar

- **A `fermata` MPP method** next to Stellar's MPP Charge, so an agent's paid request is held in
  escrow and settled on proof.
- **An escrowed x402 scheme** next to the `exact` scheme, settled through the OpenZeppelin Relayer
  facilitator.
- **Dashboard and reconciliation from Soroban events.** The escrow's `held`, `released`,
  `refunded` and `timed_out` events, joined with the Stellar Asset Contract's transfer events,
  through an indexer, because RPC keeps events for only about 7 days.
- **Lower proving cost.** Session escrow (hold once for N calls, settle in batches) and sampled
  proving (prove a random subset the vendor cannot predict).

Done when an agent pays a vendor through the gateway on testnet with both methods, and every
outcome reconciles from events.

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
