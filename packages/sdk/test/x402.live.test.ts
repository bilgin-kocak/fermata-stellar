// The `fermata` x402 scheme end to end on a deployed escrow, without the gateway: a stub resource
// server answering with x402 v2 headers, the scheme's facilitator in process, and `@x402/fetch` (a
// standard x402 client) paying with `FermataX402Client`. Needs the deployment and the agent's and
// relayer's secrets (see live.test.ts).
import { readFileSync } from 'node:fs'
import { Keypair } from '@stellar/stellar-sdk'
import { decodePaymentResponseHeader, decodePaymentSignatureHeader, encodePaymentRequiredHeader, encodePaymentResponseHeader } from '@x402/core/http'
import type { Network } from '@x402/core/types'
import { wrapFetchWithPaymentFromConfig } from '@x402/fetch'
import { describe, expect, it } from 'vitest'
import {
  EscrowReader,
  FermataX402Client,
  FermataX402Facilitator,
  HoldStatus,
  Relayer,
  caip2,
  fermataRequirements,
  fermataRequirementsProblem,
  holdTermsOf,
  requestHash,
  rpcServer,
  type FermataOffer,
} from '../src/index.ts'

const file = process.env.FERMATA_DEPLOYMENT
const agentSecret = process.env.FERMATA_AGENT_SECRET
const relayerSecret = process.env.FERMATA_RELAYER_SECRET
const root = new URL('../../../', import.meta.url)

describe.skipIf(!file || !agentSecret || !relayerSecret)('the fermata x402 scheme on a deployed escrow', () => {
  const d = file ? JSON.parse(readFileSync(new URL(file, root), 'utf8')) : undefined
  const rpcUrl =
    process.env.FERMATA_RPC_URL ?? (d?.network === 'local' ? 'http://localhost:8000/rpc' : 'https://soroban-testnet.stellar.org')
  const passphrase: string = d?.network_passphrase
  const network = (caip2(passphrase ?? '') ?? 'stellar:testnet') as Network
  const escrow: string = d?.escrow.contract_id
  const reader = new EscrowReader(escrow, rpcUrl, passphrase)
  const agent = agentSecret ? Keypair.fromSecret(agentSecret) : undefined
  const relayer = relayerSecret ? new Relayer(Keypair.fromSecret(relayerSecret), rpcServer(rpcUrl), passphrase) : undefined
  const secret = 'the resource server secret, thirty-two bytes or more'
  const target = '/v1/quote?symbol=BTC-USD'

  async function server() {
    const svc = (await reader.service(d.service.id))!
    const offer: FermataOffer = { network, escrow, token: svc.token, amount: svc.pricePerCall, serviceId: svc.serviceId, requestHash: requestHash(svc.serviceId, 'GET', target) }
    const facilitator = new FermataX402Facilitator({ rpcUrl, network, networkPassphrase: passphrase, escrows: [escrow], relayer })
    const signatures: string[] = []
    const fetch = async (url: string | URL | Request, init?: RequestInit) => {
      const req = new Request(url, init)
      const header = req.headers.get('payment-signature')
      const required = (error?: string) =>
        new Response(null, {
          status: 402,
          headers: {
            'PAYMENT-REQUIRED': encodePaymentRequiredHeader({ x402Version: 2, error, resource: { url: req.url }, accepts: [fermataRequirements(offer, secret)] }),
          },
        })
      if (!header) return required()
      signatures.push(header)
      const payload = decodePaymentSignatureHeader(header)
      const problem = fermataRequirementsProblem(payload.accepted, offer, secret)
      if (problem) return required(problem)
      const verified = await facilitator.verify(payload, payload.accepted)
      if (!verified.isValid) return required(verified.invalidMessage)
      const settled = await facilitator.settle(payload, payload.accepted)
      if (!settled.success) return required(settled.errorMessage)
      return Response.json({ quote: 'ok' }, { headers: { 'PAYMENT-RESPONSE': encodePaymentResponseHeader(settled) } })
    }
    return { fetch, signatures, offer }
  }

  const payWith = (fetch: (url: string | URL | Request, init?: RequestInit) => Promise<Response>, trustedVerifiers = [d.service.verifier]) =>
    wrapFetchWithPaymentFromConfig(fetch as typeof globalThis.fetch, {
      schemes: [{ network, client: new FermataX402Client({ keypair: agent!, rpcUrl, networkPassphrase: passphrase, trustedVerifiers, escrows: [escrow] }) }],
      spendControls: { allowedAssets: true },
    })

  it('a standard x402 client pays with the fermata scheme; the facilitator holds the price in the escrow', async () => {
    const s = await server()
    const res = await payWith(s.fetch)(`http://resource.test${target}`)
    expect(res.status).toBe(200)
    const settled = decodePaymentResponseHeader(res.headers.get('payment-response')!)
    expect(settled.success).toBe(true)
    expect(settled.payer).toBe(agent!.publicKey())
    expect(settled.transaction).toMatch(/^[0-9a-f]{64}$/)
    const terms = holdTermsOf(decodePaymentSignatureHeader(s.signatures[0]!).accepted)
    const hold = await reader.hold(terms.callId)
    expect(hold?.status).toBe(HoldStatus.Held)
    expect(hold?.requestHash).toBe(s.offer.requestHash)

    // Replaying the same payment does not hold twice.
    const replay = await s.fetch(`http://resource.test${target}`, { headers: { 'payment-signature': s.signatures[0]! } })
    expect(replay.status).toBe(402)
  })

  it('refuses a payment for requirements the server did not issue for this request', async () => {
    const s = await server()
    const other = { ...s.offer, requestHash: requestHash(s.offer.serviceId, 'GET', '/v1/quote?symbol=ETH-USD') }
    const forged = fermataRequirements(other, 'another server secret, thirty-two bytes')
    const payload = { x402Version: 2, accepted: forged, payload: { transaction: 'AAAA' } }
    const res = await s.fetch(`http://resource.test${target}`, { headers: { 'payment-signature': Buffer.from(JSON.stringify(payload)).toString('base64') } })
    expect(res.status).toBe(402)
  })

  it('the client refuses an untrusted verifier before anything is signed', async () => {
    const s = await server()
    await expect(payWith(s.fetch, [Keypair.random().publicKey()])(`http://resource.test${target}`)).rejects.toThrow(/not a trusted verifier/)
    expect(s.signatures).toHaveLength(0)
  })
})
