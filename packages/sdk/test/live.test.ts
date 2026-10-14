// Parity against a deployed escrow, through the generated client: the contract's own views agree
// with the SDK's service id and verdict message. Opt in with a deployment file written by
// scripts/deploy-testnet.sh:
//
//   FERMATA_DEPLOYMENT=deployments/testnet.json pnpm sdk:test
//   FERMATA_DEPLOYMENT=deployments/local.json FERMATA_RPC_URL=http://localhost:8000/rpc pnpm sdk:test
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { EscrowClient, label, serviceId, toContractVerdict, toHex, verdictMessage, type Domain } from '../src/index.ts'

const file = process.env.FERMATA_DEPLOYMENT
const root = new URL('../../../', import.meta.url)

describe.skipIf(!file)('a deployed escrow (FERMATA_DEPLOYMENT)', () => {
  const d = file ? JSON.parse(readFileSync(new URL(file, root), 'utf8')) : undefined
  const rpcUrl =
    process.env.FERMATA_RPC_URL ?? (d?.network === 'local' ? 'http://localhost:8000/rpc' : 'https://soroban-testnet.stellar.org')
  const client = () =>
    new EscrowClient({
      contractId: d.escrow.contract_id,
      networkPassphrase: d.network_passphrase,
      rpcUrl,
      allowHttp: rpcUrl.startsWith('http://'),
    })

  it('derives the demo service id like the SDK, and stores the registered service', async () => {
    const id = serviceId(d.service.owner, d.service.label)
    expect(id).toBe(d.service.id)
    const view = await client().service_id({ owner: d.service.owner, label: Buffer.from(label(d.service.label)) })
    expect(view.result.toString('hex')).toBe(id)
    const service = (await client().get_service({ service_id: Buffer.from(id, 'hex') })).result
    expect(service).toBeDefined()
    expect(service!.verifier.toString('hex')).toBe(d.service.verifier)
    expect(service!.predicate_hash.toString('hex')).toBe(d.service.predicate_hash)
    expect(service!.origin_hash.toString('hex')).toBe(d.service.origin_hash)
    expect(service!.price_per_call).toBe(BigInt(d.service.price_per_call))
  })

  it('rebuilds the verdict message exactly as the contract does', async () => {
    const vectors = JSON.parse(readFileSync(new URL('test-vectors/verdict-v1.json', root), 'utf8'))
    const v = vectors.verdicts[0].verdict
    const domain: Domain = { networkPassphrase: d.network_passphrase, contract: d.escrow.contract_id }
    const onchain = (await client().verdict_message({ verdict: toContractVerdict(v) })).result
    expect(onchain.toString('hex')).toBe(toHex(verdictMessage(domain, v)))
  })
})
