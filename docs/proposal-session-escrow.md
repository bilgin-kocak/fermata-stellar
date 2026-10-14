# Proposal: session escrow and sampled proving

**Status: a proposal for the repository owner's decision. Nothing in this file is built.** It is
decision 4 of [`PORTING_NOTES.md`](PORTING_NOTES.md#decisions): the gateway, both payment methods
and reconciliation came first, and this design goes to the owner before any code. Written
2026-10-14.

Neither part exists in Fermata on Tempo either. Fermata's README lists both under "The production
shape, none of it built yet", and notes that sampling changes the guarantee.

## Why

Today every call costs the following:

- **A hold.** One transaction, whose fee the gateway pays when the hold is sponsored.
- **A settlement.** A second transaction.
- **An MPC-TLS proof.** Each proof took 1.1 to 1.3 s in the M2 cases. M1 measured about 62 MB
  sent and 3.9 MB received between prover and notary per proof.

The two parts of this proposal attack these costs separately:

- **Session escrow** replaces the per-call transactions. The agent deposits once for up to N
  calls, and calls are settled in batches.
- **Sampled proving** replaces most of the proofs. One call in k is proved, and the vendor cannot
  tell which.

## What does not change

- **The escrow.** The per-call escrow (`contracts/escrow`) and its deployments stay as they are.
  Open holds are unaffected.
- **The verdict.** The verdict, its encoding and its vectors stay as they are.
- **Proved calls.** The attestor's binding checks and the delivery predicate apply to every proved
  call, as now.
- **Trust.** The service's verifier stays trusted for its decisions, as now.

## 1. A session contract next to the escrow

**What it is.** A new contract, `contracts/session`, deployed next to an existing escrow. It
reads that escrow's registry by cross-contract calls: `get_service`, `fee_bps` and `treasury`.
Services are not registered twice, and the escrow's owner keeps the one fee and treasury setting.

**Functions:**

| Function | Authorization | Effect |
|---|---|---|
| `open_session(agent, session_id, service_id, max_calls, ticket_key, sample_k, batch_size, seed, expires_at)` | the agent, covering the transfer of `max_calls × price` | Records the session: the service's terms, the fee at opening, the agent's ticket key (Ed25519), k, the batch size B, the verifier's seed commitment, and a deadline of `expires_at + settlement_window` |
| `settle_batch(session_id, batch)` | none (anyone) | Checks the batch (below), pays the vendor and the treasury for its paid calls, and refunds the rest of the batch to the agent |
| `close_session(session_id)` | none (anyone), after the deadline | Refunds whatever is still deposited to the agent |
| `get_session`, `ticket_message`, `statement_message` | none | Views, so off-chain code can check parity, as `verdict_message` does today |

**Events:**

- `session_opened(session_id, service_id, agent)`;
- `batch_settled(session_id, from, to, paid, refunded, fee, statement_hash)`;
- `session_closed(session_id, refunded)`.

Calls made but not settled before the deadline are refunded at close, as a timeout is today.

## 2. Tickets: the agent's commitment to each call

**The ticket key.** The agent makes an Ed25519 key for the session, apart from its account key,
and registers its public key at `open_session`. Stellar's MPP channel intent works the same way:
cumulative commitments, signed off-chain with a separate key, settled later on chain.

**The ticket.** Calls are numbered 1, 2, and so on, up to `max_calls`. Before call n, the agent
signs a fixed-width message:

```
ticket(n) = "FERMATA_STELLAR_TICKET_V1" ‖ network id ‖ session contract id ‖ session_id ‖ n (u32) ‖ chain(n)
chain(0)  = session_id
chain(n)  = sha256(chain(n−1) ‖ request_hash of call n)
```

**What a ticket authorizes.** The latest ticket authorizes every call so far, each bound to its
exact request. So a batch needs one agent signature, however many calls it settles. The gateway
refuses a call without the next valid ticket, and sends exactly the request the ticket names.

**What it prevents.** No one can charge the session for a call the agent did not make, even with
a dishonest verifier. The agent cannot disown a call it made.

## 3. Sampling: who decides which calls are proved

**The sample.** Batch j holds calls `(j − 1) × B + 1` through `j × B`, for j = 1, 2, and so on.
Call n in batch j is proved when the first 4 bytes of `sha256(seed_j ‖ n)`, read big-endian, are a
multiple of k. With k = 1, every call is proved.

**The seeds.** They come from a hash chain the verifier commits to at opening:

- **Commitment.** `seed_0 = sha256^m(s)` for a secret s, with m at least the number of batches.
  It is carried in `open_session`, and so covered by the agent's authorization. It is never used
  for sampling itself.
- **Reveals.** Batch j reveals `seed_j`, and the contract checks `sha256(seed_j) = seed_(j−1)`.

**Who can predict the sample:**

- **The vendor and the agent cannot.** They see `seed_0`, and later only the seeds of batches
  already settled. Each later seed is a preimage of the last one revealed, so it cannot be
  computed from it.
- **The verifier knows the sample in advance.** It is already trusted with every verdict. It
  cannot change the sample after the fact: the commitment fixes it, and anyone can recompute it
  once the seeds are revealed.

**Why not other sources of randomness:**

- **An agent-chosen seed.** An agent that knew which calls would be proved could send requests
  designed to fail the predicate in those calls, and collect the penalty refunds (section 4).
- **A vendor-chosen seed.** The vendor would know which calls to serve honestly.
- **A ledger hash.** Proving has to start at the TLS handshake. A future ledger is not known then,
  and a past one is public.

## 4. Settling a batch, and what each call pays

A batch covers calls `from + 1` through `to`, where `from` is where the last batch ended. It
carries the following:

- the request hashes of those calls;
- the agent's ticket for `to`;
- the revealed seed;
- one entry per call: a verdict outcome, presentation hash and response hash for a proved call,
  or `ANSWERED` / `UNANSWERED` for an unproved one;
- the verifier's Ed25519 signature over a statement of all of it, tagged
  `"FERMATA_STELLAR_BATCH_V1"`.

The contract checks, in order:

1. **The window.** The batch lands before the deadline and covers the next B calls. A shorter
   batch is the session's last: revealing its seed exposes the sample of any later call in that
   batch, so no call may follow it.
2. **The agent's ticket.** The request hashes extend the stored chain to `chain(to)`, and the
   ticket's signature verifies under the agent's ticket key.
3. **The seed and the sample.** `sha256(seed)` is the stored seed. Every sampled call carries a
   proved outcome, and every other call does not.
4. **The verifier's statement.** Its signature verifies under the service's verifier key.

**Payment.** Let A be the unproved answered calls in the batch, D the proved DELIVERED calls and F
the proved FAILED calls:

```
paid calls = max(0, A + D − (k − 1) × F)
vendor     = paid × (price − fee)      treasury = paid × fee
agent      = (to − from − paid) × price, refunded in the same transaction
```

**What this means for each kind of call:**

- An unanswered call is refunded, on the verifier's report, as a missing transcript is refunded
  by timeout today.
- A proved failure refunds itself and k − 1 more calls.
- With k = 1 this is exactly today's rule: a call is paid if and only if its proof says
  DELIVERED.

## 5. The guarantee with sampling (k > 1)

The guarantee changes from per call to per session, in expectation. The owner has to accept this
explicitly.

- **Per call: nothing for unproved calls.** An unproved call can be paid although it failed. It
  can never be proved later, because no transcript was recorded.
- **In expectation: exact.** Say a vendor answers a fraction f of its calls with a response that
  fails the predicate, and cannot tell which calls are proved. A call it does not answer at all is
  refunded either way. Each answered call then pays, in expectation,
  `(1 − 1/k) × 1 + (1/k) × ((1 − f) × 1 − f × (k − 1)) = 1 − f`. So the vendor is paid exactly
  for what it delivered, and failing unproved calls earns it nothing on average.
- **Noise.**
  - **Size.** The variance per call is `f × (k − f)`. Over N calls the payment varies by about
    `√(N f (k − f))` calls (one standard deviation). For example, with k = 10, f = 5 % and
    N = 1000, the vendor is paid for about 950 ± 22 calls.
  - **An honest vendor (f = 0) has no noise.** It is paid for every call, exactly.
  - **Clamping.** The clamp at zero per batch favours the vendor when failures are heavy.
- **Trust added on top of today's.**
  - The verifier fixes the sample, but it commits to it in advance.
  - The verifier reports which unproved calls went unanswered. Today it can already cause a
    refund by withholding a proof.

## 6. The open risk: can the vendor tell proved calls apart?

Everything in section 5 assumes the vendor cannot tell proved calls from unproved ones. With
TLSNotary v0.1.0-alpha.15, a proved call runs MPC-TLS during the session, and its handshake is
slower than a plain TLS handshake.

**Mitigations.** Unproved calls would go out from the same host, with the same TLS client
configuration (so the same ClientHello), and with their handshake timing padded to match.

**A measurement before sampling is switched on.** From the vendor's side, measure how well a
classifier separates proved from unproved calls, and publish the result. If a vendor can tell
them apart, sampling deters only vendors that do not look.

**An alternative to investigate.** Notarization by a proxy that records every session and proves
only the sampled ones afterwards would remove the signal. This proposal does not assume
TLSNotary offers it.

## 7. Payment methods

- **MPP.** Sessions would be a session flow of the `fermata` method:
  - **Opening.** The agent signs the authorization of `open_session`, and the gateway submits it,
    as with a sponsored hold.
  - **Calls.** Each call's credential is the next ticket.
- **x402.** Not covered by this proposal.

## 8. Cost, roughly

| | Per-call escrow (today) | Session (proposal) |
|---|---|---|
| Transactions for N calls | 2N | 2 + ⌈N / B⌉ |
| Proofs for N calls | N | about N / k |
| Signature checks on chain | N | 2 per batch |

**On-chain CPU.** In the host's default cost model (soroban-env-host 29.0.1):

- an Ed25519 verification costs about 0.38 M CPU instructions;
- a SHA-256 of 64 bytes costs about 7 k;
- the default per-transaction budget is 100 M.

The per-call work in a batch is a few hashes and its share of the signed statement. The batch size
would be set from measured CPU, memory and transaction size against testnet's limits.

## 9. Plan, if approved

1. **Phase 1, k = 1.** The session contract, tickets and batch settlement, with every call
   proved: today's per-call guarantee, with fewer transactions.
   - **Tests.** The ported invariants (the contract's balance equals the open deposits,
     conservation, no double settlement). A rejection matrix for tickets, statements, seeds and
     batches. Golden vectors for the ticket and statement encodings, agreed on by the contract,
     `fermata-verdict`, the SDK and the Python check.
   - **Runs.** A script for the cases on a local network and in CI, then the testnet commands.
2. **Phase 2, k > 1.** The attestor's unproved path with padding, then the measurement in section
   6, then the gateway's sampling. Statistical tests compare payments against delivered calls
   across failure rates and values of k. Sampling is switched on only if the measurement supports
   it.

## Decisions for the owner

1. **The guarantee.** Accept the changed guarantee for k > 1 (section 5), and the
   indistinguishability assumption it rests on (section 6)?
2. **The contract's shape.** Recommended: a session contract that reads the existing escrow's
   registry, fee and treasury. The alternative is a second escrow version holding both the
   per-call and the session functions, with services registered again.
3. **The randomness.** Recommended: the verifier's committed hash chain (section 3).
4. **The order.** Recommended: phase 1 (k = 1) first, and sampling only after the measurement.
