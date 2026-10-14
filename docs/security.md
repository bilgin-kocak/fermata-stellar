# Security

Adapted from Fermata's `SECURITY.md` (bilgin-kocak/fermata @ d7cc642) for the Stellar port.

**Unaudited code.** Nobody outside this project has reviewed it. Do not use it with real funds.

## Scope

- **Testnet only.** The escrow and the session contract are built for, and demonstrated on,
  Stellar testnet and local quickstart networks. There is no mainnet deployment; a security audit comes before one
  ([`ROADMAP.md`](../ROADMAP.md), M3).
- **Trust model.** The escrow and the session contract trust one Ed25519 verifier key per
  service. The attestor holds it and signs only after a TLSNotary presentation passes its checks;
  in these milestones the same operator runs the notary. See [`trust-model.md`](trust-model.md).
- **Dependencies.** Pinned:
  - **Contract and verdict crate.** `soroban-sdk` 29.0.1 (exact versions in `Cargo.lock`) and
    Rust 1.97.0 (`rust-toolchain.toml`).
  - **Attestor.** TLSNotary at git rev `47aee45b` and Rust 1.95.0 (`apps/attestor/Cargo.lock`
    and `rust-toolchain.toml`).
  - **SDK.** `@stellar/stellar-sdk` 16.3.1 and the rest in `pnpm-lock.yaml`.
  - **Gateway.** mppx 0.10.1, `@x402/*` 2.28.0, Hono 4, and Stellar's MPP SDK (`@stellar/mpp`)
    pinned to commit `90394ec` of its unreleased main branch, because its npm release needs
    stellar-sdk 15. All in `pnpm-lock.yaml`.
  - **Tools.** Stellar CLI 28.1.0, whose checksum CI checks, and the quickstart image, which CI
    pins by digest.

## Keys

- **No secrets in this repository.** Keys live in the Stellar CLI keystore (`stellar keys`), as
  identities named `fermata-<role>`. The scripts never print or write them.
- **The verifier secret** is read from the keystore, or from the `FERMATA_VERIFIER_SECRET`
  environment variable if set. It reaches `fermata-verdict` and `fermata-attest` only through
  their environment, never as a command-line flag. The attestor holds no Stellar account: it reads
  the escrow by simulation.
- **The agent's ticket key** (sessions) is an Ed25519 key apart from its account, used only to
  sign tickets. `scripts/session-cases.sh` keeps it in the keystore as `fermata-ticket`; the SDK's
  client makes a new one for each session and keeps it in memory.
- **The notary key** (secp256k1) is read from `NOTARY_PRIVATE_KEY`. `scripts/attest-cases.sh` and
  `scripts/gateway-cases.sh` generate one for each run and keep it in memory; services pin only its
  hash.
- **The gateway's keys** come only from its environment, never from its config file:
  - `FERMATA_RELAYER_SECRET`: the account that submits holds, settlements and timeouts and pays
    their fees.
  - `GATEWAY_SECRET_KEY`: the HMAC key for MPP challenges and x402 call ids, at least 32 bytes.
  - Optional: `FEE_PAYER_SECRET`, and OpenZeppelin's API keys `OZ_CHANNELS_API_KEY` and
    `X402_FACILITATOR_API_KEY`.

  `scripts/gateway-cases.sh` passes the relayer's and the agent's keys from the keystore into
  those two processes' environments for the run, and generates the HMAC key for each run. It also
  checks that the vendor's `Authorization` value never appears in a presentation.
- **Keep the verifier key for verdicts and statements only.** Never use it as an account signer.
  Verdict messages are 294 bytes and batch statements 288, each starting with its own fixed tag,
  while Stellar transaction and authorization signatures cover 32-byte hashes, so none can be
  confused with another. A dedicated key keeps it that way.
- **Files.** `.env`, `.stellar/`, `*.secret`, certificates and keys (`certs/`, `*.pem`, `*.key`)
  and stored presentations are git-ignored. The demo vendor's dev CA is generated on each machine.
  If you find a real secret committed here, treat it as compromised and report it.

## Properties the tests check

- **Authorization.** Only the agent can hold from its balance, for exactly the service's price.
  Only a service's owner can register under its ids. Only the escrow owner can change the fee
  and the treasury.
- **Verdicts.** Only the pinned key can settle, and only for the call it signed. A signature for
  another network or escrow is rejected, and so is any verdict changed after signing.
- **Money.**
  - The escrow balance equals the sum of open holds.
  - Each call settles at most once.
  - The fee is snapshotted and capped, and the fee arithmetic cannot overflow (prices are bounded
    by `MAX_PRICE`).
  - Money is conserved.
- **Liveness.** After the window anyone can refund the agent, and an archived hold can still be
  refunded or still blocks its call id.
- **The attestor.**
  - With real MPC-TLS sessions, each of the seven binding checks rejects its failure case, and no
    verdict is signed without a transcript.
  - A tampered or foreign presentation is rejected.
  - The `Authorization` value never appears in a presentation, and hiding anything other than
    the three auth header values is rejected.
  - Its verdicts settle on the escrow only for the call they name.
- **Holds and payments.** A sponsor accepts a signed hold only if:
  - it authorizes exactly that hold (call, service, request, escrow, token, amount, agent), with
    nothing deeper;
  - it expires soon, its signature is the agent's for this network, and its source is the all-zero
    account;
  - its simulation emits only the hold's event and transfer.
- **Replays.** The gateway refuses a replayed credential or payment, one reused on another
  request, a stranger naming another agent's public call id, and x402 requirements it did not
  issue for that request.
- **The sweeper.** It refunds every hold that gets no verdict after the window, including after a
  restart. It retries a failed settlement, and leaves alone a call that a request is still
  handling.
- **Reconciliation.** It flags a wrong amount, a second settlement, a hold missing from the index
  and a balance that does not match the open holds. On a local network, every call in the M2
  cases, and the escrow as a whole, reconcile from the indexed events.
- **Sessions.**
  - Only the agent can open a session from its balance, for exactly calls × price.
  - A batch settles only with the agent's ticket over its requests and the verifier's statement
    over its results, for this network and contract. A replayed batch, another key's ticket or
    statement, a request the agent did not sign, and entries changed after signing are refused.
  - The contract's balance equals what is left of the open sessions' deposits, each call settles
    at most once, and money is conserved (random sequences across services, tokens and agents).
  - After the deadline anyone can close a session, and what was not settled goes to the agent; an
    archived session can still be closed and still blocks its id.
  - The attestor checks the agent's ticket before the vendor is contacted, takes the calls of a
    session in order and once each, records a call with no proof as UNANSWERED (also across a
    restart), and signs statements only over calls it recorded.
  - The gateway refuses a call out of order, a ticket over another request and a replayed
    credential, and its sweeper settles and closes sessions.

The suite was mutation-checked by hand during development: five injected bugs were each caught.
They were fee rounding up, the window off by one, the fee read at settlement instead of at hold,
`hold` without the agent's authorization, and a verdict message without the contract id.

## Known limitations

- **The verifier decides.** A compromised or dishonest verifier key can sign DELIVERED for a call
  that failed (the vendor is paid) or FAILED for one that succeeded (the agent is refunded). The
  contract cannot tell. A dishonest verdict is detectable by re-verifying its presentation
  offline; it is not impossible.
- **The notary is run by the attestor's operator** in these milestones, so that operator could
  produce a presentation for bytes the vendor never sent. An independent notary is the planned fix.
- **The attestor's HTTP API has no authentication.** It is meant for a gateway on the same host,
  and listens on 127.0.0.1 by default. Anyone who can reach it can ask it to prove calls, and can
  download stored presentations. A session call, proved or recorded UNANSWERED, also needs the
  agent's ticket for it.
- **Recipients that cannot receive.**
  - A DELIVERED settlement fails as a whole if the vendor's payout or the treasury cannot receive
    the token (no trustline, deauthorized by the issuer, frozen). The hold stays open and the
    agent is refunded after the window.
  - A treasury that cannot receive therefore blocks releases until the owner sets another.
- **Tokens are per service, chosen by the vendor.** A non-standard token (fee-on-transfer, or one
  that lies about balances) can only affect holds on services that chose it; holds on other tokens
  are isolated. Agents should pay only into services whose token they accept; the TypeScript
  SDK's `isTrustedService` checks the verifier and, optionally, the token.
- **Error codes.** Contract errors use codes 101–117 (the escrow) and 201–211 (the session
  contract), so they cannot be confused with the Stellar Asset Contract's own codes (1–15). The
  SAC propagates those unchanged when a transfer inside a contract call fails.
- **A failed signature check is a host error, not a contract error.** `ed25519_verify` traps, and
  callers see a generic host error. The cause, `Error(Crypto, InvalidInput)`, appears in the
  transaction's diagnostic events.
- **Events expire from RPC.**
  - RPC providers typically keep events for about 7 days, and events are not ledger state.
  - The gateway's indexer keeps its own copy from the moment it starts (or from the escrow's
    deployment, if the RPC still has it). A gateway that is down for longer than the RPC's
    retention loses those events. The indexer records the gap, and the escrow-wide balance check
    is then skipped.
- **The gateway's read API has no authentication.** It listens on 127.0.0.1 by default. Anyone who
  can reach it can list every call and session, download every presentation, and so read every
  vendor response.
- **MPP replay protection is in memory** (mppx's store) and is forgotten when the gateway
  restarts. A credential replayed after a restart can still never make an agent pay twice:
  - the gateway checks that the hold is still open;
  - the escrow refuses a second hold for the same call id;
  - for sessions, the gateway's record takes each call number once, and the contract refuses a
    second opening of a session id.
- **Sponsored holds and session openings cost the gateway fees.** Each one is a transaction it pays
  for (or OpenZeppelin Channels does). A payer must lock real money in each, which bounds the
  cost. Still, the only limit is admission control: no rate limit per agent.
- **Sessions.**
  - **The deposit is locked** until the session's last call is settled or its deadline has
    passed, even if the gateway disappears; then anyone can close the session and the rest
    returns to the agent.
  - **No batch, no payment.** Calls not settled by the deadline are refunded at the close,
    delivered or not, as a hold with no verdict times out. The vendor relies on the gateway, or on
    the attestor's statements, to settle in time.
  - **One call at a time.** The gateway takes the calls of a session one after another; parallel
    calls need parallel sessions.
  - **The SDK's client keeps its sessions in memory.** An agent that restarts cannot continue a
    session; its rest returns after the deadline.
  - **Not covered.** x402 has no session flow, the gateway does not accept openings the agent
    submits itself, and sampling (k > 1) is not built.
- **Unprotected options.** Stellar's MPP Charge and x402 `exact` pay the vendor directly. Nothing
  is held or proved, and nothing is refunded. With `exact` through a hosted facilitator, that
  facilitator settles the payment. Neither hosted OpenZeppelin service has been tried from this
  repository yet.
- **An unreleased dependency.** Stellar's MPP SDK is pinned to a commit of its main branch until a
  release supports stellar-sdk 16.
- **Development-only pieces.**
  - `scripts/lib/tls-proxy.mjs` (HTTPS in front of a local network's RPC, with a certificate made
    for the run) is for local networks only.
  - A local network started with testnet's passphrase accepts signatures made for testnet. Use
    keys made for it (`KEY_PREFIX`), never testnet keys that hold anything.
- **State archival.** Holds, sessions, services and the contract instances are extended as
  described in [`architecture.md`](architecture.md). An archived entry is restored when touched (protocol 23
  and later), which costs rent but never loses funds.
- **Proofs and privacy.** A TLSNotary presentation reveals the vendor's whole response, and the
  attestor serves stored presentations to anyone who can reach it; see the trust model.
- **MPC sessions sometimes stall** during setup, before the vendor is contacted. Fermata
  measured about 1 in 20 sessions; here 3 of 10 sessions in two test runs needed a second attempt.
  The attestor retries, each retry costs a few seconds, and the hold's window bounds the delay. In
  CI run 20 two attempts in a row stalled before the third proved the call.
- **Testnet resets.** Stellar testnet is reset about once a quarter. A deployment and its links
  disappear and must be redeployed with `scripts/deploy-testnet.sh`.

## Reporting

Please report vulnerabilities privately through GitHub's "Report a vulnerability" (Security,
Advisories) on [bilgin-kocak/fermata-stellar](https://github.com/bilgin-kocak/fermata-stellar), or
to the maintainer, Bilgin Kocak. Expect an acknowledgement within a few days. There is no bug
bounty.
