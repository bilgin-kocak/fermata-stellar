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
dishonest verdict is detectable, though not prevented. In these milestones the attestor's operator
also runs the notary, so the evidence is only as independent as that operator (see "Who runs the
notary"). The trust-minimization items at the end are about prevention.

Since Milestone 2, agents pay through a gateway. It submits holds and settlements, but it cannot
move held money or change what an agent authorized (see "The gateway").

## Parties

| Party | Role | Holds a key? |
|---|---|---|
| Agent | Pays for one API call by authorizing `hold` (and the token transfer inside it) | Stellar account |
| Vendor | Registers a service (owner), receives `price − fee` on DELIVERED | Stellar account |
| Verifier | Signs DELIVERED or FAILED verdicts for the services that pin its public key | Ed25519 key, used for verdicts only |
| Relayer | Submits `settle` or `claim_timeout`; can be anyone, gains nothing. The gateway's relayer also submits sponsored holds and pays their fees | Any Stellar account |
| Escrow owner | Changes the fee (at most 5 %) and the treasury | Stellar account |
| Attestor (`fermata-attest`) | Proves the vendor's HTTPS response with TLSNotary, checks it against the escrow, signs the verdict | The verifier key; no Stellar account (it reads the escrow by simulation) |
| Notary | Takes part in MPC-TLS without seeing plaintext and signs an attestation of the commitments | A secp256k1 key, pinned per service by its hash |
| Gateway | Sells calls to agents over MPP and x402, submits holds and settlements, sweeps timed-out holds, indexes events | The relayer account and an HMAC key for its challenges |
| OpenZeppelin Channels (optional) | Submits sponsored holds from its own accounts and pays their fees | Its own accounts and API keys |
| x402 facilitator for `exact` (optional) | Settles the unprotected x402 option, a direct payment to the vendor | Its own account |

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
  escrows and verifiers it pays into. The SDK's MPP and x402 clients check, before anything is
  signed:
  - the escrow and the service's verifier key, against the agent's allow-lists;
  - the price and the settlement window, against its limits.

  They refuse otherwise; the live tests cover an untrusted verifier, an untrusted escrow and
  another network.
- **Both** rely on the timeout. An agent whose call got no verdict is refunded after the window,
  without anyone's cooperation.

## The gateway

The gateway is the agent's counterparty for the HTTP call. In these milestones its operator also
runs the attestor and the notary.

- **What the agent's authorization fixes.** For a sponsored hold, the agent signs a Soroban
  authorization entry for one `hold`. That entry names:
  - the escrow, the call id, the service and the request hash;
  - one inner token transfer of exactly the price into the escrow;
  - an expiry a few minutes ahead at most. The gateway accepts up to 5 minutes for MPP and
    60 seconds for x402, plus 10 ledgers of clock skew.

  The gateway, or OpenZeppelin Channels, can submit that entry or not submit it. It cannot change
  the entry, spend it twice (the escrow refuses a used call id), or reuse it after it expires.
- **What the gateway can do.**
  - **Refuse or stall.** It can refuse to serve, or never ask for a proof. The hold then times out
    and anyone, the gateway's sweeper included, refunds the agent.
  - **Return the wrong bytes.** It can answer the agent with something other than the proved
    response. Every receipt names the call, so the agent can fetch the presentation and re-verify
    it offline.
  - **Forge evidence.** Because it runs the notary, a dishonest operator could forge a transcript;
    offline re-verification cannot tell (see "Who runs the notary").
- **What it cannot do.** Move held money anywhere but along the escrow's paths, or settle a call
  without a verdict signed by the service's verifier.
- **Replays.** A credential or an x402 payment is accepted once:
  - MPP challenges are HMAC-bound to the gateway, the request and a call id it minted;
  - x402 requirements carry a call id that is an HMAC over the request and an expiry;
  - the escrow refuses a second hold for the same call id.
- **OpenZeppelin Channels**, when configured, sees the signed hold before it lands. It can delay
  it or drop it (the agent then pays nothing), but it cannot change it.
- **The unprotected options** (Stellar's MPP Charge and x402 `exact`) are direct payments to the
  vendor's account. They carry none of these guarantees: no escrow, no proof, no refund. With x402
  `exact`, the agent also trusts the facilitator that settles it, as in any x402 payment.

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
operator. That is how Fermata's Tempo demo works, and how `scripts/attest-cases.sh` and
`scripts/gateway-cases.sh` work here; each script makes a new notary key for its run and registers
services that pin it. A prover and a
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
