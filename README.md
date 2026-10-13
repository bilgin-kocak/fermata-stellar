# Fermata on Stellar: pay on proof

[![CI](https://github.com/bilgin-kocak/fermata-stellar/actions/workflows/ci.yml/badge.svg)](https://github.com/bilgin-kocak/fermata-stellar/actions/workflows/ci.yml)

**Chargebacks for machine payments, decided on cryptographic evidence instead of a support ticket.**

A card payment has a chargeback: when the goods never arrive, the buyer disputes and a person reads
the ticket. An agent paying an API per call has nothing. It pays, the API answers with a 500 or
with malformed JSON, and the money is gone.

Fermata is the chargeback for that payment, except no one reads a ticket:

- the payment is **held** in escrow;
- the vendor's HTTPS response is recorded with [TLSNotary](https://github.com/tlsnotary/tlsn);
- the hold is **released** to the vendor only when that record passes a pre-agreed, mechanically
  checkable delivery predicate;
- a verified failure, or a proof window that runs out, **refunds** the agent.

This repository makes Stellar Fermata's primary home. It ports the escrow from
[Fermata on Tempo](https://github.com/bilgin-kocak/fermata), a working system there, to a Soroban
contract, with a verdict format Stellar verifies natively. That is Milestone 0, and it works as
follows:

- The escrow holds an agent's USDC for one call.
- The service's registered verifier signs an Ed25519 verdict.
- DELIVERED pays the vendor the price minus a 0.5 % fee; FAILED refunds the agent.
- With no verdict before the settlement window closes, anyone can trigger the refund.

**In Milestone 0 the verdicts are signed directly with the verifier key: the TLSNotary attestor
is not wired in yet.** It is the next milestone ([`ROADMAP.md`](ROADMAP.md)).

Vocabulary throughout: `hold → release(proof) → refund`.

## How it works on Stellar

```mermaid
sequenceDiagram
  autonumber
  participant Ag as Agent
  participant Es as Fermata escrow (Soroban)
  participant Tk as USDC (Stellar Asset Contract)
  participant Vf as Verifier
  participant Rl as Relayer (anyone)
  participant Ve as Vendor API
  Ag->>Es: hold(agent, callId, serviceId, requestHash), authorized by the agent
  Es->>Tk: transfer(agent to escrow, price)
  Note over Es: event held(callId, serviceId, agent)
  Ag->>Ve: the paid API call (through the gateway from M2)
  Note over Vf,Ve: From M1 the attestor proves the response with TLSNotary and checks it against the hold and the predicate. In M0 no proof is made and the verifier key signs directly.
  Vf->>Rl: Ed25519 verdict, DELIVERED or FAILED, bound to this network and this escrow
  Rl->>Es: settle(callId, verdict, signature)
  alt DELIVERED
    Es->>Tk: transfer(escrow to vendor payout, price minus fee)
    Es->>Tk: transfer(escrow to treasury, fee)
  else FAILED
    Es->>Tk: transfer(escrow to agent, price)
  end
  Note over Ag,Es: No verdict before the window closes, then anyone calls claim_timeout and the agent is refunded
```

How the parts map from Tempo:

- **Payment pull.** The agent authorizes `hold`, and that authorization covers the token transfer
  with its exact amount. This replaces Tempo's TIP-20 permit.
- **Linking money to a call.** The escrow's events carry the call id as a topic, next to the
  token's transfer events in the same transaction. This replaces Tempo's transfer memos.
- **The verdict.** It is signed over
  `"FERMATA_STELLAR_VERDICT_V1" ‖ sha256(network passphrase) ‖ escrow id ‖ the verdict's eight
  fields` and checked with the host's `ed25519_verify`. A verdict for another call, network or
  escrow does not settle.
- **Every difference** from the Solidity contract, with its reason, is in
  [`docs/PORTING_NOTES.md`](docs/PORTING_NOTES.md).

## Status

| Capability | Status |
|---|---|
| Escrow: `register_service`, `hold`, `settle`, `claim_timeout`, fee and treasury administration, events | **Implemented and tested on Stellar** ([`contracts/escrow`](contracts/escrow), 57 tests) |
| Stellar verdict: encoding, Ed25519 signer, strict verification, CLI, golden vectors | **Implemented and tested on Stellar** ([`crates/fermata-verdict`](crates/fermata-verdict), 28 tests; [`test-vectors/`](test-vectors)) |
| Deployment and the three canonical cases (`scripts/`) | **Implemented and tested on Stellar**: 3/3 on a local network (protocol 29). The testnet run is pending; see [Live on testnet](#live-on-testnet). |
| TLSNotary attestor: proving, blind notary, 7 binding checks, predicates, offline re-verification | **Only in the Tempo version**. Planned for Stellar in M1. |
| TypeScript SDK (`fermata-sdk`) | **Only in the Tempo version**. Stellar bindings planned in M1. |
| Gateway with the `fermata` MPP payment method, MCP server (`fermata-mcp`) | **Only in the Tempo version**. On Stellar: MPP and x402 planned in M2. |
| Dashboard, reconciliation, vendor scores, self-serve onboarding | **Only in the Tempo version**. Planned in M2 (onboarding in M3). |
| Session escrow, sampled proving | **Planned** (M2), in neither version yet |
| Mainnet, security audit, design partners | **Planned** (M3) |
| Independent notary, vendor-chosen verifiers, N-of-M quorum, on-chain presentation verification | **Planned** (trust minimization) |

## Live on testnet

**Not deployed yet.** The build environment that produced this milestone cannot reach Stellar
testnet: its network policy refuses the RPC, Horizon and Friendbot hosts. So nothing here claims a
testnet deployment, and [`deployments/testnet.json`](deployments/testnet.json) is a placeholder.
Both scripts ran 3/3 against a local Stellar network (stellar-core 29.0.0, RPC 29.0.1, protocol 29,
testnet resource limits) instead.

To deploy and run the three cases on testnet, from a machine that reaches it:

```sh
git clone https://github.com/bilgin-kocak/fermata-stellar && cd fermata-stellar
scripts/deploy-testnet.sh   # builds, creates fermata-* identities, deploys, registers the demo service,
                            # writes deployments/testnet.json and prints the agent's address
# Circle's testnet USDC: request it for that address at https://faucet.circle.com (Stellar testnet).
# The faucet is a web form with a captcha. Or skip it with a self-issued test asset:
#   TOKEN=test scripts/deploy-testnet.sh
scripts/demo-cases.sh       # release, verified-failure refund, timeout refund, with stellar.expert links
```

This section then lists the contract id and the six transaction links: a hold and a settlement
or claim for each case. Testnet is reset about once a quarter; the scripts redeploy from scratch.

## Quick start

Requirements:

- Rust via rustup: `rust-toolchain.toml` pins 1.97.0 with the `wasm32v1-none` target.
- The Stellar CLI, 25.2 or newer (tested with 28.1.0); `soroban-sdk` 29 builds contracts only
  through `stellar contract build`.
- `jq` and `openssl` for the scripts.
- Python 3 with `cryptography` for the independent vector check.

```sh
rustup toolchain install                          # the pinned toolchain
cargo test --workspace                            # 85 tests, about 15 s once built
cargo clippy --all-targets -- -D warnings && cargo fmt --all -- --check
stellar contract build --package fermata-escrow   # target/wasm32v1-none/release/fermata_escrow.wasm
python3 test-vectors/check_vectors.py             # golden vectors, independently (pip install cryptography)
```

Against a local Stellar network (Docker):

```sh
docker run -d --name stellar --network host stellar/quickstart:latest \
  --local --enable core,rpc,horizon --protocol-version 29   # the image defaults to protocol 28
NETWORK=local scripts/deploy-testnet.sh           # uses a self-issued FERMATATEST asset
NETWORK=local scripts/demo-cases.sh
```

That `docker run` command is the one these scripts were tested with (on Linux). Where host
networking is unavailable, map the port instead (`-p 8000:8000`).
`stellar container start local --protocol-version 29` should start the same network; it was not
tested here.

Keys live only in the Stellar CLI keystore (`stellar keys`). [`.env.example`](.env.example) lists
the settings the scripts read.

Sign and check a verdict by hand:

```sh
cargo run -q -p fermata-verdict -- --help
FERMATA_VERIFIER_SECRET="$(stellar keys secret fermata-verifier)" \
  cargo run -q -p fermata-verdict -- sign --network-passphrase "Test SDF Network ; September 2015" \
  --contract C... --call-id ... --service-id ... --request-hash ... --predicate-hash ... \
  --outcome delivered --presentation-hash ... --response-hash ...
```

## Trust model

- **What the contract enforces.** The escrow trusts one Ed25519 verifier key per service, and
  enforces everything around that key:
  - only the agent can fund a hold, for exactly the service's price;
  - only the pinned key can settle, for the call, service, request, predicate, network and
    contract it signed, inside the window;
  - after the window, anyone can refund the agent;
  - the owner can change the fee (at most 5 %, never for open holds) and the treasury, never
    held funds;
  - services are immutable and there is no upgrade path.
- **What it cannot check** is whether a verdict is true. In Milestone 0, a verdict is the
  verifier's word. From Milestone 1, the attestor signs only after verifying a TLSNotary
  presentation that anyone can re-verify offline. A dishonest verdict then becomes detectable,
  though not prevented.
- **Closing that gap.** Vendor-chosen verifiers, an N-of-M quorum and on-chain verification are on
  the roadmap. Details: [`docs/trust-model.md`](docs/trust-model.md) and
  [`docs/security.md`](docs/security.md).

## What the proof does and does not establish

Ported from Fermata. These limits apply once the attestor is ported (Milestone 1); in
Milestone 0 there is no proof, only the verifier's signature.

- **What a presentation proves.** A TLSNotary presentation establishes that a specific HTTPS
  server, identified by its TLS certificate, sent specific bytes in response to specific request
  bytes. That is all.
  - It does not establish that the data is correct: a quoted price can be wrong.
  - It cannot establish that a server never responded: no transcript, no proof.
- **What the predicate can check.** The delivery predicate contains only what can be checked on
  the transcript: status code, content type, body size, JSON shape.
  - There are no latency or timing checks, because the transcript has no trusted clock.
  - Latency SLAs, if any, are gateway policy, not proof-backed.
- **No response, no verdict.** No response from the vendor means no transcript, which means no
  verdict. The agent is protected by the on-chain timeout refund, never by a verdict signed
  without evidence.
- **Privacy.** A presentation reveals the vendor's whole response.
  - Fermata's Tempo demo serves every presentation publicly so that anyone can re-verify. That is
    fine for test data, not for proprietary or personal data.
  - Production needs proofs shared only with the agent, the vendor and, in a dispute, an auditor,
    plus selective disclosure.

## The verdict and its vectors

A verdict has the same eight fields as Fermata's EIP-712 `Verdict`: call id, service id, request
hash, predicate hash, outcome, presentation hash, response hash and issue time. It is signed over
a 294-byte message in which every field is fixed-width and integers are big-endian (layout in
[`docs/architecture.md`](docs/architecture.md#the-verdict)).

The network id (sha256 of the network passphrase) and the escrow's contract id take the place of
EIP-712's `chainId` and `verifyingContract`.

[`test-vectors/verdict-v1.json`](test-vectors/verdict-v1.json) pins the encoding, and three
implementations agree on it byte for byte:

- **The contract.** It rebuilds each message and settles holds with the recorded signatures.
- **`fermata-verdict`.** It re-encodes the messages and reproduces the signatures, since Ed25519 is
  deterministic.
- **[`check_vectors.py`](test-vectors/check_vectors.py).** It is written in Python and signs with
  OpenSSL.

## Repository layout

```
contracts/escrow/          Soroban port of FermataEscrow (src/tests: the ported suite and more)
crates/fermata-verdict/    Stellar verdict encoding + Ed25519 signer: library and CLI
test-vectors/              golden vectors, asserted by the contract tests and the crate,
                           plus an independent Python/OpenSSL check
scripts/                   deploy-testnet.sh, demo-cases.sh (and lib.sh)
predicates/                the demo service's delivery predicate (from Fermata)
deployments/testnet.json   the testnet deployment (a placeholder until the script runs there)
docs/                      PORTING_NOTES.md, architecture.md, trust-model.md, security.md
```

## Prior work

- **[Fermata on Tempo](https://github.com/bilgin-kocak/fermata).** The system this repository
  ports: a Solidity escrow, the `fermata-attest` attestor (TLSNotary `v0.1.0-alpha.15`), an MPP
  gateway, a TypeScript SDK, a dashboard, an MCP server and a demo vendor with failure modes.
  Fermata's own documentation reports these numbers, **measured on Tempo, not on Stellar**:
  - **Tempo's Moderato testnet**, 2026-10-01: the three canonical cases passed 3/3, and a 100-call
    run against a vendor failing at random gave 96 releases and 4 refunds, with MPC-TLS proving
    at 1.03 s per call (median).
  - **Anvil's Tempo emulation**: about 66 MB of prover-to-notary traffic per proof.

  None of these have been measured on Stellar yet.
- **[WebProof](https://github.com/bilgin-kocak/webproof-solana).** The earlier bridge from
  TLSNotary to signed claims, on Solana. Fermata's attestor ports its TLSNotary code, and this
  repository reuses its claim pattern: a versioned tag, canonical bytes, Ed25519, and a vector
  file in the repository.
- **[SorobanGenie](https://github.com/bilgin-kocak/soroban-genie).** Earlier Stellar work: a chat
  assistant that turns plain-language requests into Soroban contracts.

## License and security

Apache-2.0 ([`LICENSE`](LICENSE)). [`NOTICE`](NOTICE) lists the code and text ported from Fermata
(MIT) and WebProof (Apache-2.0). The code is unaudited and for testnet only; see
[`docs/security.md`](docs/security.md) for the scope, the known limitations and how to report a
vulnerability.
