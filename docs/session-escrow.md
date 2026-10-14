# Session escrow and sampled proving: the design

**Status: approved by the repository owner on 2026-10-14, with the recommended options (decisions
2 to 4 at the end); decision 1 stays open until phase 2. Phase 1 (every call proved, k = 1) is in
progress; sampling (k > 1) is not built and will not be switched on before the measurement in
section 6.** This was decision 4 of [`PORTING_NOTES.md`](PORTING_NOTES.md#decisions): the gateway,
both payment methods and reconciliation came first, and this design went to the owner before any
code. Written 2026-10-14; section 10 specifies phase 1.

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
  `ANSWERED` for an unproved call, or `UNANSWERED` for any call that got no answer (a sampled
  call with no answer has no transcript, so it cannot carry a proof);
- the verifier's Ed25519 signature over a statement of all of it, tagged
  `"FERMATA_STELLAR_BATCH_V1"`.

The contract checks, in order:

1. **The window.** The batch lands before the deadline and covers the next B calls. A shorter
   batch is the session's last: revealing its seed exposes the sample of any later call in that
   batch, so no call may follow it.
2. **The agent's ticket.** The request hashes extend the stored chain to `chain(to)`, and the
   ticket's signature verifies under the agent's ticket key.
3. **The seed and the sample.** `sha256(seed)` is the stored seed. A proved outcome appears only
   on a sampled call, `ANSWERED` only on an unsampled one, and `UNANSWERED` on either.
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

## 10. Phase 1 specification

What phase 1 builds, made exact. The contract implements sections 1 to 4 for any k ≥ 1, so phase
2 needs no new contract; phase 1's gateway and attestor open and settle sessions with k = 1 only.

**Encodings.** Fixed-width, integers big-endian; `contract` is the 32-byte id of the session
contract, `network` sha256 of the network passphrase:

```
chain(0)     = session_id
chain(n)     = sha256(chain(n−1) ‖ request_hash of call n)
ticket(n)    = "FERMATA_STELLAR_TICKET_V1" ‖ network ‖ contract ‖ session_id ‖ n (u32) ‖ chain(n)          157 bytes
entry        = result (u32) ‖ presentation_hash ‖ response_hash                                             68 bytes
entries_hash = sha256(entry of call from+1 ‖ … ‖ entry of call to)
statement    = "FERMATA_STELLAR_BATCH_V1" ‖ network ‖ contract ‖ session_id ‖ service_id ‖ predicate_hash
               ‖ from (u32) ‖ to (u32) ‖ chain(to) ‖ seed ‖ entries_hash                                    288 bytes
sampled(n)   = k = 1, or the first 4 bytes of sha256(seed_j ‖ n (u32)), read as a u32, are a multiple of k
call_id(n)   = sha256("FERMATA_STELLAR_SESSION_CALL_V1" ‖ contract ‖ session_id ‖ n (u32))
```

`call_id(n)` is what the attestor proves the call against (its `X-Fermata-Call` header), as a
hold's call id today. Golden vectors pin every encoding (`test-vectors/session-v1.json`), and the
contract, `fermata-verdict`, the SDK and the Python check must agree on them.

**Results.** `DELIVERED` = 1 and `FAILED` = 2 (proved: a non-zero presentation hash), `ANSWERED` = 3
and `UNANSWERED` = 4 (unproved: both hashes zero).

**Batches.** A batch settles calls `from + 1` through `to`, where `from` is what the session has
settled, and `to − from` is at most B.

- **k = 1.** Nothing is sampled: batches may be any size up to B, the seeds are 32 zero bytes, and
  the session stays open until `to = max_calls` or until it is closed after its deadline.
- **k > 1.** Batch j covers exactly calls `(j − 1) × B + 1` through `j × B` and reveals `seed_j`. A
  shorter batch ends the session, and its remaining deposit is refunded with it.

**Terms.** At opening, the service's price, token, payout, verifier, predicate hash and settlement
window are copied from the escrow's registry, and its fee is read; services are immutable there,
so the copy cannot go stale. The treasury is read at each batch, as the escrow reads it at each
release.

**Limits.** `max_calls` in 1 to 1,000,000, with `max_calls × price` fitting the deposit; k in 1 to
1,000; B in 1 to 1,000; `expires_at` later than now and at most 30 days ahead. A zero session id,
ticket key or (with k > 1) seed is refused, and so is a service whose payout is this contract.

**Errors** start at 201, apart from the escrow's (101 to 117) and the Stellar Asset Contract's (1
to 15). A signature that does not verify is a host crypto error, as in the escrow.

## Decisions taken

The repository owner took the recommended options on 2026-10-14.

1. **The guarantee for k > 1** (section 5) and the indistinguishability assumption (section 6):
   **open until phase 2.** Phase 1 keeps today's per-call guarantee (k = 1), so it does not depend
   on this decision.
2. **The contract's shape: a session contract** that reads the existing escrow's registry, fee and
   treasury.
3. **The randomness: the verifier's committed hash chain** (section 3).
4. **The order: phase 1 (k = 1) first**, and sampling only after the measurement.
