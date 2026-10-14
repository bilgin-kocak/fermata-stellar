// Parity against a deployed escrow, through the generated client: the contract's own views agree
// with the SDK's service id and verdict message. Opt in with a deployment file written by
// scripts/deploy-testnet.sh:
//
//   FERMATA_DEPLOYMENT=deployments/testnet.json pnpm sdk:test
//   FERMATA_DEPLOYMENT=deployments/local.json FERMATA_RPC_URL=http://localhost:8000/rpc pnpm sdk:test
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { Keypair } from '@stellar/stellar-sdk'
import {
  EXPIRY_SKEW_LEDGERS,
  EscrowClient,
  EscrowReader,
  HoldStatus,
  LEDGER_SECONDS,
  Relayer,
  checkHoldTransaction,
  checkSponsoredHold,
  label,
  rpcServer,
  serviceId,
  signSponsoredHold,
  simulateSponsoredHold,
  submitOwnHold,
  submitSponsoredHold,
  toContractVerdict,
  toHex,
  verdictMessage,
  waitForTransaction,
  type Domain,
  type HoldTerms,
} from '../src/index.ts'

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

// Holding through a sponsor and directly, on the deployment. Needs the agent's and the relayer's
// secrets for this one command (scripts and CI pass them from the keystore):
//
//   FERMATA_AGENT_SECRET="$(stellar keys secret fermata-agent)" \
//   FERMATA_RELAYER_SECRET="$(stellar keys secret fermata-relayer)" FERMATA_DEPLOYMENT=… pnpm sdk:test
const agentSecret = process.env.FERMATA_AGENT_SECRET
const relayerSecret = process.env.FERMATA_RELAYER_SECRET

describe.skipIf(!file || !agentSecret || !relayerSecret)('holds on a deployed escrow (agent and relayer secrets)', () => {
  const d = file ? JSON.parse(readFileSync(new URL(file, root), 'utf8')) : undefined
  const rpcUrl =
    process.env.FERMATA_RPC_URL ?? (d?.network === 'local' ? 'http://localhost:8000/rpc' : 'https://soroban-testnet.stellar.org')
  const server = rpcServer(rpcUrl)
  const passphrase: string = d?.network_passphrase
  const reader = new EscrowReader(d?.escrow.contract_id, rpcUrl, passphrase)
  const agent = agentSecret ? Keypair.fromSecret(agentSecret) : undefined
  const relayer = relayerSecret ? new Relayer(Keypair.fromSecret(relayerSecret), server, passphrase) : undefined
  const fresh = () => toHex(crypto.getRandomValues(new Uint8Array(32)))

  async function termsFor(): Promise<HoldTerms> {
    const s = await reader.service(d.service.id)
    if (!s) throw new Error('the demo service is not registered')
    return { escrow: d.escrow.contract_id, token: s.token, amount: s.pricePerCall, serviceId: s.serviceId, callId: fresh(), requestHash: fresh() }
  }

  it('a sponsored hold: the agent signs, the relayer checks, simulates and submits it', async () => {
    const terms = await termsFor()
    const { transaction } = await signSponsoredHold({ server, networkPassphrase: passphrase, keypair: agent!, terms, validForSeconds: 60 })
    const latest = (await server.getLatestLedger()).sequence
    const hold = checkSponsoredHold({
      transaction,
      networkPassphrase: passphrase,
      terms,
      latestLedger: latest,
      maxLedger: latest + Math.ceil(60 / LEDGER_SECONDS) + EXPIRY_SKEW_LEDGERS,
      sponsors: [relayer!.address],
    })
    expect(hold.agent).toBe(agent!.publicKey())
    const landed = await submitSponsoredHold({ server, networkPassphrase: passphrase, hold, terms, relayer })
    expect(landed.via).toBe('relayer')
    expect(landed.held.agent).toBe(agent!.publicKey())
    const onchain = await reader.hold(terms.callId)
    expect(onchain?.status).toBe(HoldStatus.Held)
    expect(onchain?.amount).toBe(terms.amount)

    // The same signed hold cannot be submitted twice.
    await expect(simulateSponsoredHold({ server, networkPassphrase: passphrase, hold, terms })).rejects.toThrow()
  })

  it('a hold the agent submits itself, checked from its transaction', async () => {
    const terms = await termsFor()
    const { hash } = await submitOwnHold({ server, networkPassphrase: passphrase, keypair: agent!, terms })
    const tx = await waitForTransaction(server, hash)
    const held = checkHoldTransaction(tx, terms)
    expect(held.agent).toBe(agent!.publicKey())
    expect(() => checkHoldTransaction(tx, { ...terms, callId: fresh() })).toThrow(/no money for this call/)
  })
})
