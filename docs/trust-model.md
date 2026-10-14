# Trust model

Adapted from Fermata's v1 trust model (bilgin-kocak/fermata, `README.md` @ d7cc642) and
WebProof's `docs/trust-model.md` (bilgin-kocak/webproof-solana @ 609a654), for what exists on
Stellar today.

## In one paragraph

The escrow trusts one Ed25519 verifier key per service. Since Milestone 1 that key lives in the
attestor, which signs only after verifying a TLSNotary presentation of the vendor's HTTPS response
and checking it against the hold and the service it reads from the escrow. (In Milestone 0 the key
signed verdicts directly, with no proof; `scripts/demo-cases.sh` still does, as a baseline.) The
contract enforces several things:

- only the key the service pinned can settle a hold;
- the verdict must be for this call, this service, this request and this predicate, on this
  network and this contract;
- it must land inside the settlement window;
- without one, anyone can refund the agent after the window.

What the contract cannot check is whether a verdict is true. Every attestor verdict points at a
presentation that anyone can re-verify offline against the hashes the escrow stores, so a
dishonest verdict is detectable, though not prevented. In this milestone the attestor's operator
also runs the notary, so the evidence is only as independent as that operator (see "Who runs the
notary"). The trust-minimization items at the end are about prevention.

## Parties

| Party | Role | Holds a key? |
|---|---|---|
| Agent | Pays for one API call by authorizing `hold` (and the token transfer inside it) | Stellar account |
| Vendor | Registers a service (owner), receives `price − fee` on DELIVERED | Stellar account |
| Verifier | Signs DELIVERED or FAILED verdicts for the services that pin its public key | Ed25519 key, used for verdicts only |
| Relayer | Submits `settle` or `claim_timeout`; can be anyone, gains nothing | Any Stellar account |
| Escrow owner | Changes the fee (at most 5 %) and the treasury | Stellar account |
| Attestor (`fermata-attest`) | Proves the vendor's HTTPS response with TLSNotary, checks it against the escrow, signs the verdict | The verifier key; no Stellar account (it reads the escrow by simulation) |
| Notary | Takes part in MPC-TLS without seeing plaintext and signs an attestation of the commitments | A secp256k1 key, pinned per service by its hash |

## What the contract enforces

- **A hold needs the agent.** `hold` requires the agent's authorization. That authorization
  covers the inner token transfer with its exact amount, so nobody can hold from an agent's
  balance or for a different price (tested: `hold_third_party_cannot_spend_the_agents_balance`,
  `hold_reverts_when_the_authorized_amount_differs_from_the_price`).
- **Money moves only along `hold → release(proof) | refund(proof) | timeout refund`.**
  - The escrow never transfers to anyone but the agent, the service's payout and the treasury.
  - It does so only on a valid verdict or after the window. Each call settles at most once.
  - Tested by the invariant suite: balance equals open holds, conservation, no double settlement.
- **A verdict is bound to everything that matters.**
  - The signature covers a versioned tag, the network id, the contract id and all eight verdict
    fields.
  - The contract checks the call id, service id, request hash, predicate hash, outcome and a
    non-zero presentation hash before it verifies the signature.
  - A verdict signed for another call, service, network or escrow does not settle (tests 22–27
    and the golden vectors).
- **Refunds cannot be blocked by the vendor or the verifier.** After the window, anyone can call
  `claim_timeout`, and the money always goes to the agent. A vendor whose payout cannot receive
  (for example, a deauthorized trustline) blocks only its own release; the hold then times out to
  the agent.
- **The owner cannot touch held funds.**
  - The owner can change only the fee, capped at 5 %, and the treasury. A fee change does not
    apply to open holds, because the fee is snapshotted at `hold`.
  - Services are immutable.
  - There is no upgrade entry point, so the code cannot be replaced.

## What the contract trusts

- **The verifier key, for the decision.** A service's verifier decides between DELIVERED (the
  vendor is paid) and FAILED (the agent is refunded). The attestor backs each decision with a
  presentation that passed the seven binding checks and the predicate, but the contract sees only
  the signature. In the demo the verifier is operated by whoever runs the scripts.
- **The token contract.**
  - Each service names its token. The demo uses Circle's USDC Stellar Asset Contract on testnet,
    or a self-issued test asset.
  - A hostile token can only misbehave towards the holds of services that chose it: re-entry is
    blocked by the host and holds on other tokens are untouched (tests 39–41).
  - Stellar Asset Contract semantics apply: trustlines, issuer authorization flags, clawback.
- **Stellar itself**: consensus, the host's Ed25519 verification and authorization checks.

## What the parties trust

- **A vendor** trusts the verifier to sign DELIVERED when it delivered. The attestor signs
  DELIVERED when the presentation passes the predicate the vendor registered.
- **An agent** trusts the verifier not to sign DELIVERED for a failed call, and chooses which
  escrows and verifiers it pays into. The TypeScript SDK's `isTrustedService` checks a service's
  verifier key (and optionally its token) against the agent's allow-list before it holds money;
  the M2 gateway client will enforce it, as Fermata's Tempo SDK does.
- **Both** rely on the timeout. An agent whose call got no verdict is refunded after the window,
  without anyone's cooperation.

## What the proof does and does not establish

Ported from Fermata's README. The attestor here is Fermata's, so the same limits apply.

- **What a presentation proves.** A TLSNotary presentation establishes that a specific HTTPS
  server, identified by its TLS certificate, sent specific bytes in response to specific request
  bytes. That is all.
  - It does not establish that the data is correct: a quoted price can be wrong.
  - It cannot establish that a server never responded: no transcript, no proof.
- **What the predicate can check.** The delivery predicate contains only things that can be
  checked on the transcript: status code, content type, body size, JSON shape.
  - There are no latency or timing checks, because the transcript has no trusted clock.
  - Latency SLAs, if any, are gateway policy, not proof-backed.
- **No response, no verdict.** No response from the vendor means no transcript, which means no
  verdict. The agent is protected by the on-chain timeout refund, never by a verdict signed
  without evidence.
- **Privacy.** A presentation reveals the vendor's whole response.
  - Fermata's Tempo demo serves every presentation to anyone, so that anyone can re-verify a
    verdict. Call ids are public on-chain, so every paid answer is public too.
  - That suits test data, not a vendor selling proprietary or personal data.
  - A production version needs two things. First, proofs shared only with the agent, the vendor
    and, in a dispute, an auditor. Second, selective disclosure (TLSNotary can reveal chosen parts
    of a transcript and keep the rest hidden).

## Who runs the notary and the prover

The prover runs inside the attestor and the notary is a separate process, both run by the
operator. That is how Fermata's Tempo demo works, and how `scripts/attest-cases.sh` works here; the
script makes a new notary key for each run and registers services that pin it. A prover and a
notary run by the same party could collude to produce a presentation for bytes the server never
sent. Offline re-verification shows the evidence is consistent with the chain; it becomes evidence
independent of the operator only when someone else runs the notary. Each service pins a notary key
hash, so another notary is used by registering a service with its key.

## Trust minimization (planned)

None of these is built. In order:

1. **An independent notary.** A partner or the vendor runs the notary with its own key, so the
   verifier can no longer produce a transcript the server never sent.
2. **Vendor-chosen verifiers.**
3. **An N-of-M verifier quorum.** Adjudication moves off a single operator.
4. **Research into on-chain presentation verification.** The escrow would check the evidence
   itself instead of a signature over it.

See [`ROADMAP.md`](../ROADMAP.md).
