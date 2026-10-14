# fermata-stellar-sdk

The TypeScript side of Fermata on Stellar, used by the gateway, the agent script and the tests.
It is not published to npm yet; use it from this workspace (`pnpm install` at the repository
root).

## What is in it

- **Contract clients.** `EscrowClient` and `SessionClient` are the typed clients that
  `stellar contract bindings typescript` generates from the contracts' Wasm. They are committed as
  generated (`src/escrow/bindings.ts`, `src/session/bindings.ts`); `scripts/bindings.sh`
  regenerates them, and CI checks that they match the contracts. `EscrowReader` and
  `SessionReader` read services, holds and sessions by simulation, with no account.
- **Encodings,** with the same definitions as the contracts, the attestor and
  `crates/fermata-verdict`:
  - verdicts: `verdictMessage` (the 294 bytes the escrow verifies), `signVerdict`,
    `verifyVerdict`, and `toContractVerdict` for `settle`;
  - sessions: `chainNext`, `ticketMessage`, `signTicket`, `verifyTicket`, `entriesHash`,
    `statementMessage`, `signStatement`, `verifyStatement`, `sessionCallId`, `isSampled` and
    `paidCalls`;
  - hashes: `serviceId`, `requestHash`, `originHash`, `notaryKeyHash` and `predicateHash`. These
    and their vectors are ported from Fermata's `packages/sdk` @ `d7cc642`.
- **Holds and sessions on chain.**
  - A sponsored hold: the agent signs only the authorization of `hold` (`signSponsoredHold`); the
    sponsor checks it (`checkSponsoredHold`, `simulateSponsoredHold`) and submits it
    (`submitSponsoredHold`). Or the agent submits it itself (`submitOwnHold`).
  - A session opening works the same way (`signSponsoredOpen`, `checkSponsoredOpen`,
    `simulateSponsoredOpen`, `submitSponsoredOpen`, `submitOwnOpen`), and
    `settleBatchOperation` and `closeSessionOperation` build the rest.
  - `Relayer` submits and pays for transactions from one account; `submitThroughChannels` hands a
    sponsored transaction to OpenZeppelin's Channels service.
- **MPP: the `fermata` method,** for mppx 0.10.1, with two intents:
  - `charge`, a hold per call: `fermata(…)` for the agent, `fermataServer(…)` for the gateway;
  - `session`, one deposit and a ticket per call: `fermataSession(…)` and
    `fermataSessionServer(…)`.

  The agent's clients check the escrow, the session contract, the network, the service's
  verifier and price, and the agent's limits before they sign anything.
- **x402: the `fermata` scheme.** `FermataX402Client` for the agent, `fermataRequirements` for the
  server, and `FermataX402Facilitator`, which checks and submits the agent's hold. Settling the
  verdict afterwards is the gateway's job.
- **Events.** `EscrowIndexer` copies the escrow's (or the session contract's) events and the
  token transfers next to them to disk. `reconcileCall`, `reconcileEscrow`, `reconcileSession`
  and `reconcileSessions` check them; `aggregateScores` ranks services by proven outcomes.

## Examples

Check a service before holding money, and a verdict before relaying it:

```ts
import { EscrowClient, isTrustedService, verifyVerdict } from 'fermata-stellar-sdk'

const networkPassphrase = 'Test SDF Network ; September 2015'
const escrow = new EscrowClient({ contractId: 'C…', networkPassphrase, rpcUrl: 'https://soroban-testnet.stellar.org' })
const service = (await escrow.get_service({ service_id: Buffer.from(serviceIdHex, 'hex') })).result
// before holding money: is this service settled by a verifier you trust?
isTrustedService({ verifier: service!.verifier.toString('hex') }, { trustedVerifiers: ['G…'] })
// before relaying a verdict from the attestor: does it verify for this escrow?
await verifyVerdict(service!.verifier, { networkPassphrase, contract: 'C…' }, verdict, signature)
```

Pay a gateway's calls with a session (one deposit for 20 calls, then a ticket per call):

```ts
import { Keypair } from '@stellar/stellar-sdk'
import { Mppx } from 'mppx/client'
import { FermataSessions, fermataSession } from 'fermata-stellar-sdk'

const sessions = new FermataSessions()
const mppx = Mppx.create({
  methods: [
    fermataSession({
      keypair: Keypair.fromSecret(agentSecret),
      rpcUrl: 'https://soroban-testnet.stellar.org',
      network: 'stellar:testnet',
      trustedVerifiers: ['G…'],
      escrows: ['C…'],
      sessionContracts: ['C…'],
      callsPerSession: 20,
      sessions,
    }),
  ],
  polyfill: false,
})
// Naming the session lets the gateway's challenge say which call it takes next.
const named = sessions.sessionId(serviceId)
const res = await mppx.fetch(url, { headers: named ? { 'x-fermata-session': named } : {} })
```

The client keeps its sessions, and their ticket keys, in memory. An agent that restarts starts a
new session; what is left of the old one returns to it after that session's deadline.

## Tests

```sh
pnpm sdk:typecheck
pnpm sdk:test      # 81 tests: parity with test-vectors/, holds, sessions, x402, Channels,
                   # the indexer, reconciliation and scores
# the 19 live tests, against a deployment (scripts/deploy-testnet.sh writes the file); they have
# run against a local network in CI, not against testnet yet:
FERMATA_DEPLOYMENT=deployments/testnet.json \
  FERMATA_AGENT_SECRET="$(stellar keys secret fermata-agent)" \
  FERMATA_RELAYER_SECRET="$(stellar keys secret fermata-relayer)" \
  FERMATA_VERIFIER_SECRET="$(stellar keys secret fermata-verifier)" pnpm sdk:test
```

The generated clients target `@stellar/stellar-sdk` 16 (what CLI 28.1.0 generates for), so the SDK
depends on `^16.3.1`. With version 17 the client returns `Uint8Array`s where its generated types
promise `Buffer`s; the live test caught this.
