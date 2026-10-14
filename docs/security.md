# Security

Adapted from Fermata's `SECURITY.md` (bilgin-kocak/fermata @ d7cc642) for the Stellar port.

**Unaudited code.** Nobody outside this project has reviewed it. Do not use it with real funds.

## Scope

- **Testnet only.** The escrow is built for, and demonstrated on, Stellar testnet and local
  quickstart networks. There is no mainnet deployment; a security audit comes before one
  ([`ROADMAP.md`](../ROADMAP.md), M3).
- **Trust model.** The escrow trusts one Ed25519 verifier key per service. The attestor holds it
  and signs only after a TLSNotary presentation passes its checks; in this milestone the same
  operator runs the notary. See [`trust-model.md`](trust-model.md).
- **Dependencies.** Pinned:
  - **Contract and verdict crate.** `soroban-sdk` 29.0.1 (exact versions in `Cargo.lock`) and
    Rust 1.97.0 (`rust-toolchain.toml`).
  - **Attestor.** TLSNotary at git rev `47aee45b` and Rust 1.95.0 (`apps/attestor/Cargo.lock`
    and `rust-toolchain.toml`).
  - **SDK.** `@stellar/stellar-sdk` 16.3.1 and the rest in `pnpm-lock.yaml`.
  - **Tools.** Stellar CLI 28.1.0, whose checksum CI checks, and the quickstart image, which CI
    pins by digest.

## Keys

- **No secrets in this repository.** Keys live in the Stellar CLI keystore (`stellar keys`), as
  identities named `fermata-<role>`. The scripts never print or write them.
- **The verifier secret** is read from the keystore, or from the `FERMATA_VERIFIER_SECRET`
  environment variable if set. It reaches `fermata-verdict` and `fermata-attest` only through
  their environment, never as a command-line flag. The attestor holds no Stellar account: it reads
  the escrow by simulation.
- **The notary key** (secp256k1) is read from `NOTARY_PRIVATE_KEY`. `scripts/attest-cases.sh`
  generates one for each run and keeps it in memory; services pin only its hash.
- **Keep the verifier key for verdicts only.** Never use it as an account signer. Verdict messages
  are 294 bytes and start with a fixed tag, while Stellar transaction and authorization
  signatures cover 32-byte hashes, so the two cannot be confused. A dedicated key keeps it that
  way.
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

The suite was mutation-checked by hand during development: five injected bugs were each caught.
They were fee rounding up, the window off by one, the fee read at settlement instead of at hold,
`hold` without the agent's authorization, and a verdict message without the contract id.

## Known limitations

- **The verifier decides.** A compromised or dishonest verifier key can sign DELIVERED for a call
  that failed (the vendor is paid) or FAILED for one that succeeded (the agent is refunded). The
  contract cannot tell. A dishonest verdict is detectable by re-verifying its presentation
  offline; it is not impossible.
- **The notary is run by the attestor's operator** in this milestone, so that operator could
  produce a presentation for bytes the vendor never sent. An independent notary is the planned fix.
- **The attestor's HTTP API has no authentication.** It is meant for a gateway on the same host,
  and listens on 127.0.0.1 by default. Anyone who can reach it can ask it to prove calls, and can
  download stored presentations.
- **Recipients that cannot receive.**
  - A DELIVERED settlement fails as a whole if the vendor's payout or the treasury cannot receive
    the token (no trustline, deauthorized by the issuer, frozen). The hold stays open and the
    agent is refunded after the window.
  - A treasury that cannot receive therefore blocks releases until the owner sets another.
- **Tokens are per service, chosen by the vendor.** A non-standard token (fee-on-transfer, or one
  that lies about balances) can only affect holds on services that chose it; holds on other tokens
  are isolated. Agents should pay only into services whose token they accept; the TypeScript
  SDK's `isTrustedService` checks the verifier and, optionally, the token.
- **Error codes.** Contract errors use codes 101–117, so they cannot be confused with the Stellar
  Asset Contract's own codes (1–15). The SAC propagates those unchanged when a transfer inside
  `hold`, `settle` or `claim_timeout` fails.
- **A failed signature check is a host error, not a contract error.** `ed25519_verify` traps, and
  callers see a generic host error. The cause, `Error(Crypto, InvalidInput)`, appears in the
  transaction's diagnostic events.
- **Events expire from RPC.**
  - RPC providers typically keep events for about 7 days, and events are not ledger state.
  - Hold records stay in contract storage (archived, not deleted, when their TTL runs out). The
    full history of releases and refunds needs an indexer or archived transaction metadata;
    reconciliation from events is planned for Milestone 2.
- **State archival.** Holds, services and the contract instance are extended as described in
  [`architecture.md`](architecture.md). An archived entry is restored when touched (protocol 23
  and later), which costs rent but never loses funds.
- **Proofs and privacy.** A TLSNotary presentation reveals the vendor's whole response, and the
  attestor serves stored presentations to anyone who can reach it; see the trust model.
- **MPC sessions sometimes stall** during setup, before the vendor is contacted. Fermata
  measured about 1 in 20 sessions; here 3 of 10 sessions in two test runs needed a second attempt.
  The attestor retries, each retry costs a few seconds, and the hold's window bounds the delay.
- **Testnet resets.** Stellar testnet is reset about once a quarter. A deployment and its links
  disappear and must be redeployed with `scripts/deploy-testnet.sh`.

## Reporting

Please report vulnerabilities privately through GitHub's "Report a vulnerability" (Security,
Advisories) on [bilgin-kocak/fermata-stellar](https://github.com/bilgin-kocak/fermata-stellar), or
to the maintainer, Bilgin Kocak. Expect an acknowledgement within a few days. There is no bug
bounty.
