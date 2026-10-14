// The `fermata` MPP method end to end on a deployed escrow, without the gateway: an mppx server with
// `fermataServer` in front of a stub resource, and an mppx client paying with `fermata`. Needs the
// deployment and the agent's and relayer's secrets (see live.test.ts).
import { readFileSync } from 'node:fs'
import { Keypair } from '@stellar/stellar-sdk'
import { Receipt } from 'mppx'
import { Mppx as ClientMppx } from 'mppx/client'
import { Mppx } from 'mppx/server'
import { describe, expect, it } from 'vitest'
import {
  EscrowReader,
  HoldStatus,
  Relayer,
  caip2,
  fermata,
  fermataServer,
  requestHash,
  rpcServer,
  toHex,
  type FermataClientOptions,
} from '../src/index.ts'

const file = process.env.FERMATA_DEPLOYMENT
const agentSecret = process.env.FERMATA_AGENT_SECRET
const relayerSecret = process.env.FERMATA_RELAYER_SECRET
const root = new URL('../../../', import.meta.url)

describe.skipIf(!file || !agentSecret || !relayerSecret)('the fermata MPP method on a deployed escrow', () => {
  const d = file ? JSON.parse(readFileSync(new URL(file, root), 'utf8')) : undefined
  const rpcUrl =
    process.env.FERMATA_RPC_URL ?? (d?.network === 'local' ? 'http://localhost:8000/rpc' : 'https://soroban-testnet.stellar.org')
  const passphrase: string = d?.network_passphrase
  const network = caip2(passphrase ?? '') ?? 'stellar:testnet'
  const escrow: string = d?.escrow.contract_id
  const reader = new EscrowReader(escrow, rpcUrl, passphrase)
  const agent = agentSecret ? Keypair.fromSecret(agentSecret) : undefined
  const relayer = relayerSecret ? new Relayer(Keypair.fromSecret(relayerSecret), rpcServer(rpcUrl), passphrase) : undefined
  const secretKey = toHex(crypto.getRandomValues(new Uint8Array(32)))
  const target = '/v1/quote?symbol=BTC-USD'

  /** An mppx server charging `fermata` for one route; `sponsor` makes it submit signed holds. */
  async function route(sponsor: boolean, key = secretKey, path = target) {
    const svc = (await reader.service(d.service.id))!
    const handler = fermataServer({ rpcUrl, network, networkPassphrase: passphrase, escrow, secretKey: key, relayer: sponsor ? relayer : undefined })
    const mppx = Mppx.create({ secretKey: key, realm: 'gateway.test', methods: [handler] })
    const offer = { amount: svc.pricePerCall.toString(), currency: svc.token, escrow, network, serviceId: svc.serviceId, requestHash: requestHash(svc.serviceId, 'GET', path) }
    const seen: string[] = []
    const fetch = async (url: string | URL | Request, init?: RequestInit) => {
      const req = new Request(url, init)
      const auth = req.headers.get('authorization')
      if (auth) seen.push(auth)
      const r = await mppx.compose([handler, offer] as never)(req)
      if (r.status === 402) return r.challenge
      return r.withReceipt(Response.json({ quote: 'ok' }))
    }
    return { fetch, seen }
  }

  const client = (fetch: (url: string, init?: RequestInit) => Promise<Response>, over: Partial<FermataClientOptions> = {}) =>
    ClientMppx.create({
      methods: [fermata({ keypair: agent!, rpcUrl, network, networkPassphrase: passphrase, trustedVerifiers: [d.service.verifier], escrows: [escrow], ...over })],
      polyfill: false,
      fetch: fetch as never,
    })

  it('sponsored: the agent signs the hold, the server submits it and pays the fee', async () => {
    const { fetch, seen } = await route(true)
    const xlm = async () => (await rpcServer(rpcUrl).getAccount(agent!.publicKey())).sequenceNumber()
    const before = await xlm()
    const res = await client(fetch).fetch(`http://gateway.test${target}`)
    expect(res.status).toBe(200)
    const receipt = Receipt.fromResponse(res)
    expect(receipt.reference).toMatch(/^[0-9a-f]{64}$/)
    const callId = JSON.parse(Buffer.from(seen[0]!.replace(/^Payment /, ''), 'base64url').toString()).payload.callId as string
    const hold = await reader.hold(callId)
    expect(hold?.status).toBe(HoldStatus.Held)
    expect(hold?.agent).toBe(agent!.publicKey())
    // The agent sent no transaction of its own: its sequence number did not move.
    expect(await xlm()).toBe(before)

    // The same credential cannot be redeemed twice.
    const replay = await fetch(`http://gateway.test${target}`, { headers: { authorization: seen[0]! } })
    expect(replay.status).toBe(402)
  })

  it('direct: the agent submits the hold itself when the server does not sponsor', async () => {
    const { fetch } = await route(false)
    const res = await client(fetch).fetch(`http://gateway.test${target}`)
    expect(res.status).toBe(200)
  })

  it('refuses a challenge before any money moves: untrusted verifier, untrusted escrow, another network', async () => {
    const { fetch } = await route(true)
    const other = Keypair.random().publicKey()
    await expect(client(fetch, { trustedVerifiers: [other] }).fetch(`http://gateway.test${target}`)).rejects.toThrow(/not a trusted verifier/)
    await expect(client(fetch, { escrows: [] }).fetch(`http://gateway.test${target}`)).rejects.toThrow(/untrusted escrow/)
    await expect(client(fetch, { network: 'stellar:pubnet' }).fetch(`http://gateway.test${target}`)).rejects.toThrow(/challenge is for/)
  })

  it('refuses a credential for a challenge another server signed', async () => {
    const a = await route(true)
    await client(a.fetch).fetch(`http://gateway.test${target}`)
    const b = await route(true, toHex(crypto.getRandomValues(new Uint8Array(32))))
    const res = await b.fetch(`http://gateway.test${target}`, { headers: { authorization: a.seen[0]! } })
    expect(res.status).toBe(402)
  })

  it('refuses a credential paid for another request', async () => {
    const a = await route(true)
    const b = await route(true, secretKey, '/v1/quote?symbol=ETH-USD')
    // Pay for BTC-USD, then present the same credential for ETH-USD (fresh call id, same server key).
    const paid = await client(a.fetch).fetch(`http://gateway.test${target}`)
    expect(paid.status).toBe(200)
    const res = await b.fetch(`http://gateway.test/v1/quote?symbol=ETH-USD`, { headers: { authorization: a.seen[0]! } })
    expect(res.status).toBe(402)
  })
})
