# fermata-stellar-sdk

The TypeScript side of Fermata on Stellar (Milestone 1). Not published to npm yet; use it from this
workspace (`pnpm install` at the repository root).

- **The escrow client.** `EscrowClient` is the typed client that `stellar contract bindings
  typescript` generates from the contract Wasm. `src/escrow/bindings.ts` is committed as generated;
  `scripts/bindings.sh` regenerates it and CI checks that it matches the contract.
- **The verdict.** `verdictMessage` builds the 294 bytes the escrow verifies, `signVerdict` and
  `verifyVerdict` sign and check them with Ed25519, and `toContractVerdict` converts a verdict (for
  example the one `fermata-attest serve` returns) into the client's form for `settle`.
- **The hashes.** `serviceId`, `requestHash`, `originHash`, `notaryKeyHash` and `predicateHash`,
  with the same definitions as the contract, the attestor and `crates/fermata-verdict`. The hash
  functions and their vectors are ported from Fermata's `packages/sdk` @ `d7cc642`.

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

## Tests

```sh
pnpm sdk:typecheck
pnpm sdk:test      # golden-vector parity with test-vectors/verdict-v1.json and attest-v1.json
FERMATA_DEPLOYMENT=deployments/testnet.json pnpm sdk:test   # also checks a deployed escrow's views
```

The generated client targets `@stellar/stellar-sdk` 16 (what CLI 28.1.0 generates for), so the SDK
depends on `^16.3.1`. With version 17 the client returns `Uint8Array`s where its generated types
promise `Buffer`s; the live test caught this.
