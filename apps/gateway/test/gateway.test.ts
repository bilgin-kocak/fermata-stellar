// The gateway against a fake chain, attestor and facilitators: no network.
//
// Ported from Fermata `apps/gateway/test/gateway.test.ts` @ d7cc642 (github.com/bilgin-kocak/fermata,
// MIT): the 402, the three outcomes, the sweeper (overlapping sweeps, restarts, calls finalised by
// someone else), admission control, a failed settle, a stranger naming a public call id, replay and
// request binding, the startup checks, reconciliation and the read API. The MCP, scores-over-MCP and
// onboarding cases are not ported (those parts are not). Added for Stellar: the x402 offers and the
// `fermata` scheme paid end to end, and sponsored holds recorded before submission.
//
// The `fermata` method here keeps the real server's `request` and `stableBinding` hooks (call ids
// minted per challenge, echoed only from this server's challenges, bound to the request) and fakes
// only the hold check against the fake chain; the real check is tested on a network in the SDK.
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { Challenge, Credential, Errors, Method, Receipt, Store } from 'mppx'
import { Mppx } from 'mppx/client'
import { Keypair } from '@stellar/stellar-sdk'
import { decodePaymentRequiredHeader, decodePaymentResponseHeader, encodePaymentSignatureHeader } from '@x402/core/http'
import type { PaymentPayload, PaymentRequirements } from '@x402/core/types'
import { beforeEach, describe, expect, it } from 'vitest'
import {
  HoldStatus,
  SessionStatus,
  accountAddress,
  chainNext,
  contractAddress,
  fermataMethod,
  fermataServer,
  fermataSessionMethod,
  fermataSessionServer,
  holdTermsOf,
  originHash,
  requestHash,
  signTicket,
  toHex,
  verifyTicket,
  type Hex,
  type HoldInfo,
  type IndexedEvent,
  type ServiceInfo,
  type SessionBatch,
  type SessionInfo,
  type Verdict,
} from 'fermata-stellar-sdk'
import { createGateway, toDecimal, type EventSource, type X402Facilitator } from '../src/app.ts'
import type { AttestInput, AttestResult, Attestor, SessionCallInput, SessionCallResult, SessionEntry } from '../src/attestor.ts'
import type { GatewayChain, TxResult } from '../src/chain.ts'
import type { GatewayConfig } from '../src/config.ts'
import { SessionStore, openingRecord, viewOf } from '../src/sessions.ts'
import { CallStore, type CallRecord } from '../src/store.ts'

const h = (s: string) => toHex(new TextEncoder().encode(s.padEnd(32, '.').slice(0, 32)))
const escrow = contractAddress(new Uint8Array(32).fill(0xe5))
const token = contractAddress(new Uint8Array(32).fill(0x70))
const signerKey = '51'.repeat(32)
const vendor = accountAddress(new Uint8Array(32).fill(0x0e))
const treasury = accountAddress(new Uint8Array(32).fill(0x7e))
const agent = accountAddress(new Uint8Array(32).fill(0xa9))
const sid = h('service quote')
const upstream = 'https://vendor.fermata.test:8443'
const BASE = 'http://gw.test'
const SECRET = 'unit-test-secret-key-at-least-32-bytes!!'
const PASSPHRASE = 'Test SDF Network ; September 2015'
const QUOTE = `/s/${sid}/v1/quote?symbol=BTC-USD`

type Hold = { status: HoldStatus; deadline: bigint; agent: string; serviceId: Hex; requestHash: Hex }
const sessionContract = contractAddress(new Uint8Array(32).fill(0x5e))
type OnchainSession = { status: SessionStatus; settled: number; deadline: bigint; maxCalls: number; ticketKey: Hex; batchSize: number }

class FakeChain implements GatewayChain {
  network = 'stellar:testnet'
  networkPassphrase = PASSPHRASE
  escrow = escrow
  holds = new Map<string, Hold>()
  settled: { callId: Hex; outcome: number }[] = []
  timeouts: Hex[] = []
  settleFails = 0
  time = 1_000n
  verifier = signerKey
  origin = originHash(upstream)
  /** Indexed events, as the indexer would read them after each settlement. */
  events: IndexedEvent[] = []
  private n = 0
  private pos(tx: string) {
    this.n++
    return { ledger: this.n, txHash: h(tx), id: `${String(this.n).padStart(10, '0')}-0000000000` }
  }

  async service(id: Hex): Promise<ServiceInfo | undefined> {
    if (id !== sid) return undefined
    return {
      serviceId: sid, owner: vendor, label: '00'.repeat(12), payout: vendor, token, verifier: this.verifier, pricePerCall: 10_000n,
      settlementWindow: 120, predicateHash: '44'.repeat(32), originHash: this.origin, notaryKeyHash: '55'.repeat(32),
    }
  }
  async hold(callId: Hex): Promise<HoldInfo | undefined> {
    const x = this.holds.get(callId)
    if (!x) return undefined
    return { callId, agent: x.agent, serviceId: x.serviceId, requestHash: x.requestHash, amount: 10_000n, heldAt: 900n, deadline: x.deadline, feeBps: 50, status: x.status }
  }
  async now() {
    return this.time
  }
  /** A hold landing: the escrow's state and the events the indexer would read. */
  addHold(callId: Hex, rh: Hex) {
    this.holds.set(callId, { status: HoldStatus.Held, deadline: 1_120n, agent, serviceId: sid, requestHash: rh })
    const p = this.pos(`hold ${callId}`)
    this.events.push(
      { name: 'held', callId, serviceId: sid, agent, amount: 10_000n, requestHash: rh, ...p },
      { name: 'transfer', token, from: agent, to: escrow, amount: 10_000n, ...p, id: `${p.id}a` },
    )
    return p.txHash
  }
  async settle(callId: Hex, verdict: Verdict): Promise<TxResult> {
    if (this.settleFails > 0) {
      this.settleFails--
      return { ok: false, error: 'WindowClosed (#107)' }
    }
    this.settled.push({ callId, outcome: verdict.outcome })
    this.holds.get(callId)!.status = verdict.outcome === 1 ? HoldStatus.Released : HoldStatus.Refunded
    const p = this.pos(`settle ${callId}`)
    if (verdict.outcome === 1) {
      this.events.push(
        { name: 'released', callId, serviceId: sid, payout: vendor, amount: 10_000n, fee: 50n, presentationHash: verdict.presentation_hash, ...p },
        { name: 'transfer', token, from: escrow, to: vendor, amount: 9_950n, ...p, id: `${p.id}a` },
        { name: 'transfer', token, from: escrow, to: treasury, amount: 50n, ...p, id: `${p.id}b` },
      )
    } else {
      this.events.push(
        { name: 'refunded', callId, serviceId: sid, agent, amount: 10_000n, presentationHash: verdict.presentation_hash, ...p },
        { name: 'transfer', token, from: escrow, to: agent, amount: 10_000n, ...p, id: `${p.id}a` },
      )
    }
    return { ok: true, txHash: p.txHash }
  }
  async claimTimeout(callId: Hex): Promise<TxResult> {
    this.timeouts.push(callId)
    this.holds.get(callId)!.status = HoldStatus.TimedOut
    return { ok: true, txHash: h(`timeout ${callId}`) }
  }
  async balance() {
    return 0n
  }

  // Sessions: the session contract's state, and its events as its indexer would read them.
  /** Set by `build`: the gateway sees a session contract only when sessions are enabled. */
  sessionContract?: string
  sessions = new Map<string, OnchainSession>()
  batches: { sessionId: Hex; from: number; to: number; results: number[] }[] = []
  closes: Hex[] = []
  sessionEvents: IndexedEvent[] = []
  openFails = false
  /** An opening landing, with its deposit. */
  openSession(sessionId: Hex, maxCalls: number, expiresAt: bigint, ticketKey: Hex, batchSize: number) {
    this.sessions.set(sessionId, { status: SessionStatus.Open, settled: 0, deadline: expiresAt + 120n, maxCalls, ticketKey, batchSize })
    const p = this.pos(`open ${sessionId}`)
    const deposit = 10_000n * BigInt(maxCalls)
    this.sessionEvents.push(
      { name: 'session_opened', sessionId, serviceId: sid, agent, deposit, maxCalls, price: 10_000n, sampleK: 1, batchSize, deadline: expiresAt + 120n, ...p },
      { name: 'transfer', token, from: agent, to: sessionContract, amount: deposit, ...p, id: `${p.id}a` },
    )
    return p.txHash
  }
  async session(sessionId: Hex): Promise<SessionInfo | undefined> {
    const s = this.sessions.get(sessionId)
    if (!s) return undefined
    return {
      sessionId, agent, serviceId: sid, token, payout: vendor, price: 10_000n, feeBps: 50, verifier: signerKey, predicateHash: '44'.repeat(32),
      ticketKey: s.ticketKey, maxCalls: s.maxCalls, sampleK: 1, batchSize: s.batchSize, openedAt: 1_000n, deadline: s.deadline,
      settled: s.settled, chain: sessionId, seed: '00'.repeat(32), status: s.status,
    }
  }
  async settleBatch(b: SessionBatch): Promise<TxResult> {
    const s = this.sessions.get(b.sessionId)!
    if (s.status !== SessionStatus.Open) return { ok: false, error: 'NotOpen (#204)' }
    if (this.time > s.deadline) return { ok: false, error: 'WindowClosed (#205)' }
    const from = s.settled
    if (b.to - from !== b.entries.length || b.to - from > s.batchSize) return { ok: false, error: 'InvalidBatch (#207)' }
    const results = b.entries.map((e) => e.result)
    this.batches.push({ sessionId: b.sessionId, from, to: b.to, results })
    s.settled = b.to
    const paid = results.filter((r) => r === 1).length
    const refund = BigInt(results.length - paid) * 10_000n
    // h() keeps 32 characters: the batch number goes first so each batch has its own transaction.
    const p = this.pos(`batch ${b.to} ${b.sessionId}`)
    const rest = b.to === s.maxCalls ? 0n : undefined
    this.sessionEvents.push({
      name: 'batch_settled', sessionId: b.sessionId, serviceId: sid, from, to: b.to, delivered: paid, failed: results.filter((r) => r === 2).length,
      answered: 0, unanswered: results.filter((r) => r === 4).length, paid, payoutAmount: BigInt(paid) * 9_950n, fee: BigInt(paid) * 50n, refund,
      chain: h(`chain ${b.to}`), entriesHash: h(`entries ${b.to}`), ...p,
    })
    if (paid) {
      this.sessionEvents.push(
        { name: 'transfer', token, from: sessionContract, to: vendor, amount: BigInt(paid) * 9_950n, ...p, id: `${p.id}a` },
        { name: 'transfer', token, from: sessionContract, to: treasury, amount: BigInt(paid) * 50n, ...p, id: `${p.id}b` },
      )
    }
    if (refund) this.sessionEvents.push({ name: 'transfer', token, from: sessionContract, to: agent, amount: refund, ...p, id: `${p.id}c` })
    if (rest !== undefined) {
      s.status = SessionStatus.Closed
      this.sessionEvents.push({ name: 'session_closed', sessionId: b.sessionId, serviceId: sid, agent, refund: rest, ...p, id: `${p.id}z` })
    }
    return { ok: true, txHash: p.txHash }
  }
  async closeSession(sessionId: Hex): Promise<TxResult> {
    const s = this.sessions.get(sessionId)!
    if (s.status !== SessionStatus.Open) return { ok: false, error: 'NotOpen (#204)' }
    if (this.time <= s.deadline) return { ok: false, error: 'WindowOpen (#206)' }
    s.status = SessionStatus.Closed
    this.closes.push(sessionId)
    const refund = BigInt(s.maxCalls - s.settled) * 10_000n
    const p = this.pos(`close ${sessionId}`)
    this.sessionEvents.push({ name: 'session_closed', sessionId, serviceId: sid, agent, refund, ...p })
    if (refund) this.sessionEvents.push({ name: 'transfer', token, from: sessionContract, to: agent, amount: refund, ...p, id: `${p.id}a` })
    return { ok: true, txHash: p.txHash }
  }
  async treasury() {
    return treasury
  }
}

class FakeAttestor implements Attestor {
  calls: AttestInput[] = []
  next: (input: AttestInput) => AttestResult = () => ({ kind: 'no-transcript', detail: 'unset' })
  async attest(input: AttestInput) {
    this.calls.push(input)
    return this.next(input)
  }
  async health() {
    return { network: PASSPHRASE, escrow, signer: accountAddress(new Uint8Array(32).fill(0x51)), signerKey, sessionContract: this.sessionContract }
  }
  async reverify(input: { callId: Hex }) {
    return {
      presentationHash: h(`presentation ${input.callId}`), responseHash: '66'.repeat(32), requestHash: null, originHash: originHash(upstream),
      notaryKeyHash: '55'.repeat(32), predicateHash: '44'.repeat(32), outcome: 'DELIVERED', callHeader: null, callHeaderMatches: true,
    } as never
  }
  async presentation(callId: Hex) {
    return /^[0-9a-f]{64}$/.test(callId) ? new Uint8Array([1, 2, 3]) : undefined
  }

  // Sessions: a book of the calls it recorded, as the real attestor keeps one.
  sessionContract: string | null = null
  sessionCalls: SessionCallInput[] = []
  unansweredCalls: SessionCallInput[] = []
  unreachable = false
  sessionNext: (i: SessionCallInput) => SessionCallResult = (i) => sessionEntry(i, 1)
  book = new Map<string, { n: number; entry: SessionEntry; ticket: Hex }[]>()
  chain?: FakeChain
  private record(i: SessionCallInput, entry: SessionEntry) {
    const calls = this.book.get(i.sessionId) ?? []
    this.book.set(i.sessionId, [...calls.filter((c) => c.n !== i.n), { n: i.n, entry, ticket: i.ticket }])
  }
  async sessionAttest(i: SessionCallInput): Promise<SessionCallResult> {
    this.sessionCalls.push(i)
    if (this.unreachable) return { kind: 'unreachable', detail: 'attestor unreachable: connection refused' }
    const r = this.sessionNext(i)
    if (r.kind === 'entry') this.record(i, r.entry)
    if (r.kind === 'unanswered') this.record(i, { result: 4, presentation_hash: '00'.repeat(32), response_hash: '00'.repeat(32) })
    return r
  }
  async sessionUnanswered(i: SessionCallInput): Promise<SessionCallResult> {
    this.unansweredCalls.push(i)
    if (this.unreachable) return { kind: 'unreachable', detail: 'attestor unreachable: connection refused' }
    this.record(i, { result: 4, presentation_hash: '00'.repeat(32), response_hash: '00'.repeat(32) })
    return { kind: 'unanswered', n: i.n, chain: '', detail: 'recorded unanswered' }
  }
  async sessionStatement({ sessionId, to }: { sessionId: Hex; to: number }) {
    const from = this.chain!.sessions.get(sessionId)!.settled
    const calls = (this.book.get(sessionId) ?? []).filter((c) => c.n > from && c.n <= to).sort((a, b) => a.n - b.n)
    if (calls.length !== to - from) return { ok: false as const, status: 409, detail: `calls ${from + 1}-${to} are not all in the book` }
    return {
      ok: true as const,
      signed: {
        statement: {}, message: 'ab'.repeat(288), signature: 'cd'.repeat(64), from, to,
        requestHashes: calls.map((c) => h(`request ${c.n}`)), entries: calls.map((c) => c.entry), ticket: calls.at(-1)!.ticket, signer: 'G',
      },
    }
  }
}

/** The attestor proved call n of a session: `result` 1 (DELIVERED) or 2 (FAILED). */
const sessionEntry = (i: SessionCallInput, result: 1 | 2): SessionCallResult => ({
  kind: 'entry',
  n: i.n,
  chain: '',
  entry: { result, presentation_hash: h(`presentation ${i.sessionId} ${i.n}`), response_hash: '66'.repeat(32) },
  outcome: result === 1 ? 'DELIVERED' : 'FAILED',
  failures: result === 1 ? [] : ['status 500 not in [200]'],
  presentationHash: h(`presentation ${i.sessionId} ${i.n}`),
  response: { status: result === 1 ? 200 : 500, headers: [['content-type', 'application/json']], bodyBase64: Buffer.from(result === 1 ? '{"price":1}' : '{"error":"boom"}').toString('base64') },
  proveMs: 1000,
})

const verdict = (callId: Hex, outcome: 1 | 2, response: { status: number; body: string }): AttestResult => ({
  kind: 'verdict',
  presentationHash: h(`presentation ${callId}`),
  proveMs: 1234,
  signed: {
    verdict: {
      call_id: callId, service_id: sid, request_hash: '33'.repeat(32), predicate_hash: '44'.repeat(32), outcome,
      presentation_hash: h(`presentation ${callId}`), response_hash: '66'.repeat(32), issued_at: 1000,
    },
    outcome: outcome === 1 ? 'DELIVERED' : 'FAILED',
    failures: outcome === 1 ? [] : ['status 500 not in [200]'],
    message: 'ab'.repeat(294),
    signature: 'cd'.repeat(64),
    signer: accountAddress(new Uint8Array(32).fill(0x51)),
    signerKey,
  },
  response: {
    status: response.status,
    headers: [['content-type', 'application/json'], ['content-length', String(response.body.length)], ['connection', 'close']],
    bodyBase64: Buffer.from(response.body).toString('base64'),
  },
})

/** The `fermata` method with the real request/binding hooks and a hold check against the fake chain. */
function fakeFermataServer(chain: FakeChain) {
  const real = fermataServer({ rpcUrl: 'http://127.0.0.1:1/unused', network: 'stellar:testnet', escrow, secretKey: SECRET })
  const store = Store.memory()
  const fail = (reason: string): never => {
    throw new Errors.VerificationFailedError({ reason })
  }
  return Method.toServer(fermataMethod, {
    request: real.request!,
    stableBinding: real.stableBinding!,
    async validate({ credential, request }) {
      const callId = credential.challenge.request.callId ?? fail('no callId')
      if (credential.payload.callId !== callId) fail('credential callId does not match the challenge')
      const hold = chain.holds.get(callId)
      if (!hold || hold.status !== HoldStatus.Held) fail('no open hold for this call')
      if (hold!.requestHash !== credential.challenge.request.requestHash) fail('hold is for another request')
      return { challenge: credential.challenge, credential, details: {}, intent: 'charge', method: 'fermata', request: request as never, source: credential.source }
    },
    async broadcast({ credential }) {
      const callId = credential.challenge.request.callId!
      if (!(await Store.tryClaim(store as never, `call:${callId}`, Date.now() + 3_600_000))) fail('callId already used')
      await onBroadcast?.(callId, credential.challenge.request.requestHash)
      return { method: 'fermata', reference: h(`hold ${callId}`), status: 'success', timestamp: new Date().toISOString() }
    },
  })
}

/** The `fermata` x402 facilitator, faked: a payload `{ transaction: 'signed-hold' }` holds the call. */
class FakeFermataFacilitator implements X402Facilitator {
  constructor(private readonly chain: FakeChain) {}
  async verify(payload: PaymentPayload) {
    return payload.payload.transaction === 'signed-hold' ? { isValid: true, payer: agent } : { isValid: false, invalidReason: 'bad', invalidMessage: 'not a signed hold' }
  }
  async settle(payload: PaymentPayload, req: PaymentRequirements) {
    const terms = holdTermsOf(req)
    if (this.chain.holds.has(terms.callId)) return { success: false, errorReason: 'CallIdUsed', transaction: '', network: req.network }
    const txHash = this.chain.addHold(terms.callId, terms.requestHash)
    return { success: true, transaction: txHash, network: req.network, payer: agent }
  }
}

let chain: FakeChain
let attestor: FakeAttestor
let store: CallStore
let sessionStore: SessionStore
let gw: Awaited<ReturnType<typeof createGateway>>
let lastCredential: string | undefined
/** Runs where the real method submits a sponsored hold (the gateway records the call just before). */
let onBroadcast: ((callId: Hex, requestHash: Hex) => Promise<void>) | undefined

const config = (over: Partial<GatewayConfig> = {}): GatewayConfig => ({
  port: 0, host: '127.0.0.1', realm: 'gw.test', network: 'stellar:testnet', networkPassphrase: PASSPHRASE, rpcUrl: 'http://unused', escrow,
  attestorUrl: 'http://unused', storageDir: '', indexDir: '', sweepIntervalMs: 1000, indexIntervalMs: 1000,
  sessions: { batchSize: 10, maxCalls: 100, maxDurationSeconds: 3_600, storageDir: '', indexDir: '' },
  services: [{ serviceId: sid, upstream, examplePath: '/v1/quote?symbol=BTC-USD', upstreamAuth: { header: 'Authorization', env: 'VENDOR_TOKEN' } }],
  ...over,
})

const indexer = (): EventSource => ({
  get events() {
    return chain.events
  },
  gaps: [],
  latestLedger: 100,
  poll: async () => 0,
})

async function build(over: Partial<GatewayConfig> = {}, env: Record<string, string> = {}, withSessions?: { batchSize: number }) {
  store = new CallStore(mkdtempSync(path.join(tmpdir(), 'fermata-gw-')))
  sessionStore = new SessionStore(mkdtempSync(path.join(tmpdir(), 'fermata-gw-sessions-')))
  chain.sessionContract = withSessions ? sessionContract : undefined
  if (withSessions) {
    attestor.sessionContract = sessionContract
    attestor.chain = chain
  }
  return createGateway({
    config: { ...config(over), storageDir: store.dir },
    chain,
    attestor,
    store,
    secretKey: SECRET,
    fermataHandler: fakeFermataServer(chain),
    x402: { fermata: new FakeFermataFacilitator(chain) },
    indexer: indexer(),
    env: { VENDOR_TOKEN: 'Bearer vendor-secret', ...env },
    log: () => {},
    ...(withSessions
      ? {
          sessions: {
            handler: fakeSessionServer(chain, sessionStore),
            store: sessionStore,
            batchSize: withSessions.batchSize,
            maxCalls: 50,
            maxDurationSeconds: 3_600,
            indexer: { get events() { return chain.sessionEvents }, gaps: [], latestLedger: 100, poll: async () => 0 },
          },
        }
      : {}),
  })
}

/**
 * The `session` intent with the real request and binding hooks, and the checks against the fake
 * chain and the gateway's records; tickets are real Ed25519 signatures, checked as the real server
 * does. An opening's "transaction" here is `signed-open:` and its terms as JSON.
 */
function fakeSessionServer(chain: FakeChain, sessions: SessionStore) {
  const real = fermataSessionServer({
    rpcUrl: 'http://127.0.0.1:1/unused', network: 'stellar:testnet', escrow, sessionContract, secretKey: SECRET, lookup: async () => undefined,
  })
  const claims = Store.memory()
  const domain = { networkPassphrase: PASSPHRASE, contract: sessionContract }
  const fail = (reason: string): never => {
    throw new Errors.VerificationFailedError({ reason })
  }
  const termsOf = (transaction: string) => JSON.parse(transaction.replace(/^signed-open:/, '')) as { maxCalls: number; expiresAt: string; ticketKey: Hex }
  return Method.toServer(fermataSessionMethod, {
    request: (p) => ({ ...p.request, sponsored: true }),
    stableBinding: real.stableBinding!,
    async validate({ credential, request }) {
      const c = credential.challenge.request
      const p = credential.payload
      if (p.action === 'open') {
        const t = termsOf(p.transaction)
        if (t.maxCalls > c.maxCalls) fail('too many calls')
        if (!(await verifyTicket(t.ticketKey, domain, p.sessionId, 1, chainNext(p.sessionId, c.requestHash), p.ticket))) fail('the ticket for call 1 does not cover this request')
      } else {
        const r = await sessions.get(p.sessionId)
        const view = r ? viewOf(r) : undefined
        if (!view || !view.open) return fail('no open session with this id at this gateway')
        if (view.serviceId !== c.serviceId) fail('the session is for another service')
        if (p.n !== view.next) fail(`call ${p.n} is not the next call of the session (${view.next})`)
        if (chain.time >= view.expiresAt) fail('the session has expired')
        if (!(await verifyTicket(view.ticketKey, domain, p.sessionId, p.n, chainNext(view.chain, c.requestHash), p.ticket))) fail('the ticket does not cover this request')
      }
      return { challenge: credential.challenge, credential, details: {}, intent: 'session', method: 'fermata', request: request as never, source: credential.source }
    },
    async broadcast({ credential }) {
      const p = credential.payload
      const key = p.action === 'open' ? `open:${p.sessionId}` : `call:${p.sessionId}:${p.n}`
      if (!(await Store.tryClaim(claims as never, key, Date.now() + 3_600_000))) fail('this credential was already used')
      if (p.action === 'call') return { method: 'fermata', reference: `${p.sessionId}:${p.n}`, status: 'success', timestamp: new Date().toISOString() }
      const t = termsOf(p.transaction)
      const c = credential.challenge.request
      await sessions.put(
        openingRecord({ sessionId: p.sessionId, serviceId: c.serviceId, agent, ticketKey: t.ticketKey, maxCalls: t.maxCalls, batchSize: c.batchSize, expiresAt: BigInt(t.expiresAt), deposit: 10_000n * BigInt(t.maxCalls) }),
      )
      if (chain.openFails) fail('open_session was not submitted: txBadSeq')
      const txHash = chain.openSession(p.sessionId, t.maxCalls, BigInt(t.expiresAt), t.ticketKey, c.batchSize)
      return { method: 'fermata', reference: txHash, status: 'success', timestamp: new Date().toISOString() }
    },
  })
}

/** An agent paying with the `session` intent: it opens a session, then signs one ticket per call. */
function sessionAgent(opts: { maxCalls?: number; seconds?: number } = {}) {
  const seed = new Uint8Array(32).fill(0x7c)
  const ticketKey = toHex(Keypair.fromRawEd25519Seed(Buffer.from(seed)).rawPublicKey())
  const agentState: { sessionId?: Hex; chains: Hex[]; next: number; challenges: Record<string, unknown>[] } = { chains: [], next: 1, challenges: [] }
  const method = Method.toClient(fermataSessionMethod, {
    async createCredential({ challenge }) {
      const r = challenge.request
      agentState.challenges.push(r)
      const domain = { networkPassphrase: PASSPHRASE, contract: r.sessionContract }
      if (!agentState.sessionId) {
        const sessionId = toHex(crypto.getRandomValues(new Uint8Array(32)))
        const chain1 = chainNext(sessionId, r.requestHash)
        Object.assign(agentState, { sessionId, chains: [sessionId, chain1], next: 2 })
        const terms = { maxCalls: opts.maxCalls ?? 5, expiresAt: String(chain.time + BigInt(opts.seconds ?? 600)), ticketKey }
        const ticket = await signTicket(seed, domain, sessionId, 1, chain1)
        return Credential.serialize({ challenge, payload: { action: 'open', transaction: `signed-open:${JSON.stringify(terms)}`, sessionId, ticket } })
      }
      const n = agentState.next
      const c = chainNext(agentState.chains[n - 1]!, r.requestHash)
      agentState.chains[n] = c
      agentState.next = n + 1
      const ticket = await signTicket(seed, domain, agentState.sessionId, n, c)
      return Credential.serialize({ challenge, payload: { action: 'call', sessionId: agentState.sessionId, n, ticket } })
    },
  })
  const m = Mppx.create({ methods: [method], polyfill: false, fetch: ((url: string, init: RequestInit) => gw.app.request(url, init)) as never })
  return {
    fetch: (p: string, init?: RequestInit) =>
      m.fetch(`${BASE}${p}`, { ...init, headers: { ...(init?.headers as Record<string, string>), ...(agentState.sessionId ? { 'x-fermata-session': agentState.sessionId } : {}) } }),
    state: agentState,
  }
}

/** The agent's `fermata` method: the hold lands on the fake chain. */
function holdMethod() {
  return Method.toClient(fermataMethod, {
    async createCredential({ challenge }) {
      const r = challenge.request
      const txHash = chain.addHold(r.callId!, r.requestHash)
      lastCredential = Credential.serialize({ challenge, payload: { type: 'hold', txHash, callId: r.callId! } })
      return lastCredential
    },
  })
}

/** An agent paying with `fermata` over MPP. */
function agentFetch() {
  const m = Mppx.create({ methods: [holdMethod()], polyfill: false, fetch: ((url: string, init: RequestInit) => gw.app.request(url, init)) as never })
  return (p: string, init?: RequestInit) => m.fetch(`${BASE}${p}`, init)
}

const receiptOf = (res: Response) => Receipt.fromResponse(res) as Receipt.Receipt & Record<string, unknown>

/** The `fermata` x402 requirement of a fresh 402, and a paid retry with a (faked) signed hold. */
async function payX402(p = QUOTE, transaction = 'signed-hold') {
  const res402 = await gw.app.request(`${BASE}${p}`)
  const required = decodePaymentRequiredHeader(res402.headers.get('payment-required')!)
  const accepted = required.accepts.find((a) => a.scheme === 'fermata')!
  const header = encodePaymentSignatureHeader({ x402Version: 2, accepted, payload: { transaction } })
  return { res: await gw.app.request(`${BASE}${p}`, { headers: { 'payment-signature': header } }), accepted, header }
}

beforeEach(async () => {
  chain = new FakeChain()
  attestor = new FakeAttestor()
  onBroadcast = undefined
  gw = await build()
})

describe('gateway', () => {
  it('answers 402 with a fermata MPP offer bound to this exact request, and the fermata x402 requirement', async () => {
    const res = await gw.app.request(`${BASE}${QUOTE}`)
    expect(res.status).toBe(402)
    const challenges = Challenge.fromResponseList(res)
    expect(challenges.map((c) => c.method)).toEqual(['fermata'])
    const f = challenges[0]!.request as Record<string, unknown>
    expect(f.requestHash).toBe(requestHash(sid, 'GET', '/v1/quote?symbol=BTC-USD'))
    expect(f).toMatchObject({ amount: '10000', currency: token, escrow, network: 'stellar:testnet', serviceId: sid })
    expect(f.callId).toMatch(/^[0-9a-f]{64}$/)
    const x402 = decodePaymentRequiredHeader(res.headers.get('payment-required')!)
    expect(x402.accepts).toHaveLength(1)
    expect(x402.accepts[0]).toMatchObject({ scheme: 'fermata', network: 'stellar:testnet', asset: token, amount: '10000', payTo: escrow })
    expect(holdTermsOf(x402.accepts[0]!).requestHash).toBe(f.requestHash)
  })

  it('DELIVERED: proves, settles, returns the proved response and a receipt with the settle tx', async () => {
    attestor.next = (i) => verdict(i.callId, 1, { status: 200, body: '{"price":1}' })
    const res = await agentFetch()(QUOTE, { headers: { accept: 'application/json', authorization: 'agent-secret' } })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ price: 1 })
    const r = receiptOf(res)
    expect(r).toMatchObject({ method: 'fermata', status: 'success', outcome: 'DELIVERED' })
    expect(r.txHash).toBe(chain.events.find((e) => e.name === 'released')!.txHash)
    expect(r.holdTx).toBe(h(`hold ${r.callId}`))
    expect(chain.settled).toEqual([{ callId: r.callId, outcome: 1 }])
    const call = attestor.calls[0]!
    expect(call.url).toBe(`${upstream}/v1/quote?symbol=BTC-USD`)
    expect(call.headers).toEqual({ accept: 'application/json', authorization: 'Bearer vendor-secret' })
    expect(await store.get(r.callId as string)).toMatchObject({ status: 'released', paidWith: 'mpp', sponsored: false })
    expect(await (await gw.app.request(`${BASE}/calls/${r.callId}`)).json()).toMatchObject({ status: 'released', outcome: 'DELIVERED' })
  })

  it('FAILED: returns the proved 500 and refunds', async () => {
    attestor.next = (i) => verdict(i.callId, 2, { status: 500, body: '{"error":"boom"}' })
    const res = await agentFetch()(QUOTE)
    expect(res.status).toBe(500)
    const r = receiptOf(res)
    expect(r.outcome).toBe('FAILED')
    expect(chain.settled[0]?.outcome).toBe(2)
    expect((await store.get(r.callId as string))?.status).toBe('refunded')
  })

  it('no transcript: never settles, 504, then the sweeper refunds after the window', async () => {
    attestor.next = () => ({ kind: 'no-transcript', detail: 'vendor never answered' })
    const res = await agentFetch()(QUOTE)
    expect(res.status).toBe(504)
    const r = receiptOf(res)
    expect(r.outcome).toBe('AWAITING_TIMEOUT')
    expect(chain.settled).toEqual([])
    expect(await gw.sweep()).toEqual([]) // window still open
    chain.time = 1_121n
    expect(await gw.sweep()).toEqual([r.callId])
    expect((await store.get(r.callId as string))?.status).toBe('timed-out')
  })

  it('overlapping sweeps: a slow claim_timeout is not re-marked by the next tick', async () => {
    attestor.next = () => ({ kind: 'no-transcript', detail: 'vendor never answered' })
    const callId = receiptOf(await agentFetch()(QUOTE)).callId as Hex
    chain.time = 1_121n
    const claim = chain.claimTimeout.bind(chain)
    chain.claimTimeout = async (id) => {
      const r = await claim(id) // landed: timed out on-chain
      await new Promise((ok) => setTimeout(ok, 50)) // still waiting for the result
      return r
    }
    const first = gw.sweep()
    await new Promise((ok) => setTimeout(ok, 10))
    const [a, b] = await Promise.all([first, gw.sweep()])
    expect(a).toEqual([callId])
    expect(b).toEqual([callId])
    expect(chain.timeouts).toEqual([callId])
    expect((await store.get(callId))?.status).toBe('timed-out')
  })

  it('a call cut off by a restart (held, not in flight) still gets its timeout refund', async () => {
    const callId = h('orphan')
    const now = new Date().toISOString()
    await store.put({ callId, serviceId: sid, method: 'GET', target: '/v1/quote', requestHash: '33'.repeat(32), paidWith: 'mpp', sponsored: false, holdTx: h('h'), agent, deadline: '1120', status: 'held', createdAt: now, updatedAt: now })
    chain.holds.set(callId, { status: HoldStatus.Held, deadline: 1_120n, agent, serviceId: sid, requestHash: '33'.repeat(32) })
    expect(await gw.sweep()).toEqual([]) // still inside the window
    chain.time = 1_121n
    expect(await gw.sweep()).toEqual([callId])
    expect((await store.get(callId))?.status).toBe('timed-out')
  })

  it('a call finalised by someone else records the on-chain outcome', async () => {
    const callId = h('elsewhere')
    const now = new Date().toISOString()
    await store.put({ callId, serviceId: sid, method: 'GET', target: '/v1/quote', requestHash: '33'.repeat(32), paidWith: 'mpp', sponsored: false, holdTx: h('h2'), agent, deadline: '1120', status: 'awaiting-timeout', createdAt: now, updatedAt: now })
    chain.holds.set(callId, { status: HoldStatus.TimedOut, deadline: 1_120n, agent, serviceId: sid, requestHash: '33'.repeat(32) }) // the agent reclaimed it itself
    await gw.sweep()
    expect(await store.get(callId)).toMatchObject({ status: 'timed-out', error: expect.stringContaining('another transaction') })
  })

  it('a sponsored hold recorded before submission: landed, it is refunded after the window; never landed, it is closed', async () => {
    const now = new Date().toISOString()
    const old = new Date(Date.now() - 16 * 60_000).toISOString()
    const landed = h('landed')
    const lost = h('lost')
    await store.put({ callId: landed, serviceId: sid, method: '', target: '', requestHash: '33'.repeat(32), paidWith: 'mpp', sponsored: true, agent, deadline: '0', status: 'holding', createdAt: now, updatedAt: now })
    await store.put({ callId: lost, serviceId: sid, method: '', target: '', requestHash: '34'.repeat(32), paidWith: 'x402', sponsored: true, agent, deadline: '0', status: 'holding', createdAt: old, updatedAt: old })
    chain.holds.set(landed, { status: HoldStatus.Held, deadline: 1_120n, agent, serviceId: sid, requestHash: '33'.repeat(32) })
    await gw.sweep()
    expect(await store.get(landed)).toMatchObject({ status: 'awaiting-timeout', deadline: '1120' })
    expect(await store.get(lost)).toMatchObject({ status: 'closed' })
    chain.time = 1_121n
    expect(await gw.sweep()).toEqual([landed])
  })

  it('a sweep leaves a call alone while it is being paid and proved, even from a stale snapshot', async () => {
    // The race CI caught: the sweeper listed the call while its hold was being submitted
    // ('holding'), saw the hold land, and wrote over the record the request had moved on to.
    let release!: () => void
    const proving = new Promise<void>((ok) => (release = ok))
    let started!: () => void
    const attesting = new Promise<void>((ok) => (started = ok))
    attestor.attest = async (input) => {
      attestor.calls.push(input)
      started()
      await proving
      return verdict(input.callId, 1, { status: 200, body: '{"price":"1"}' })
    }
    const put = store.put.bind(store)
    let holding: CallRecord | undefined
    store.put = async (r) => {
      const written = await put(r)
      if (r.status === 'holding') holding = written
      return written
    }
    store.list = async () => (holding ? [holding] : []) // the sweeper's snapshot, taken while 'holding'

    const paying = payX402()
    await attesting // mid-proof: the hold has landed and the record says 'held'
    const callId = holding!.callId
    expect((await store.get(callId))?.status).toBe('held')
    expect(await gw.sweep()).toEqual([])
    expect((await store.get(callId))?.status).toBe('held')
    release()
    const { res } = await paying
    expect(res.status).toBe(200)
    const holdTx = decodePaymentResponseHeader(res.headers.get('payment-response')!).transaction
    expect(res.headers.get('x-fermata-hold-tx')).toBe(holdTx)
    expect(await store.get(callId)).toMatchObject({ status: 'released', holdTx })
    expect((await store.get(callId))?.error).toBeUndefined()
  })

  it('an MPP payment is in flight from before its hold is submitted: a sweep then leaves it alone', async () => {
    attestor.next = (i) => verdict(i.callId, 1, { status: 200, body: '{"price":"1"}' })
    let during: string | undefined
    onBroadcast = async (callId, rh) => {
      // What main.ts's onSponsoredHold does, then a sweep while the hold is being submitted (it has landed).
      const now = new Date().toISOString()
      await store.put({ callId, serviceId: sid, method: '', target: '', requestHash: rh, paidWith: 'mpp', sponsored: true, agent, deadline: '0', status: 'holding', createdAt: now, updatedAt: now })
      expect(await gw.sweep()).toEqual([])
      during = (await store.get(callId))?.status
    }
    const res = await agentFetch()(QUOTE)
    expect(res.status).toBe(200)
    expect(during).toBe('holding')
    const r = receiptOf(res)
    expect(await store.get(r.callId as string)).toMatchObject({ status: 'released', holdTx: h(`hold ${r.callId}`) })
  })

  it('turns new payers away (503, nothing charged) while proving is saturated', async () => {
    const busy = await build({}, { GATEWAY_MAX_IN_FLIGHT: '0' })
    const res = await busy.app.request(`${BASE}${QUOTE}`)
    expect(res.status).toBe(503)
    expect(res.headers.get('retry-after')).toBe('5')
  })

  it('binding check failed: 502, awaiting timeout, no verdict', async () => {
    attestor.next = () => ({ kind: 'rejected', check: 'origin', detail: 'wrong server' })
    const res = await agentFetch()(QUOTE)
    expect(res.status).toBe(502)
    expect(chain.settled).toEqual([])
    expect((await store.get(receiptOf(res).callId as string))?.status).toBe('awaiting-timeout')
  })

  it('a failed settle stays pending and the sweeper retries it inside the window', async () => {
    chain.settleFails = 1
    attestor.next = (i) => verdict(i.callId, 1, { status: 200, body: '{}' })
    const callId = receiptOf(await agentFetch()(QUOTE)).callId as Hex
    expect(await store.get(callId)).toMatchObject({ status: 'settle-pending', error: 'settle: WindowClosed (#107)' })
    await gw.sweep()
    expect((await store.get(callId))?.status).toBe('released')
  })

  it("a stranger cannot redeem another agent's hold by naming its public call id", async () => {
    const quote = `${BASE}${QUOTE}`
    // The victim gets a challenge and holds call X on-chain: X, its hold tx and request hash are public.
    const victim = Challenge.fromResponseList(await gw.app.request(quote)).find((c) => c.method === 'fermata')!
    const X = victim.request.callId as Hex
    const holdTx = chain.addHold(X, victim.request.requestHash as Hex)
    // The stranger forges a challenge naming X: the 402 it gets back must not be a signed challenge for X.
    const forged = Credential.serialize({ challenge: { ...victim, id: 'A'.repeat(43) } as never, payload: { type: 'hold', txHash: holdTx, callId: X } })
    const reply = await gw.app.request(quote, { headers: { authorization: forged } })
    expect(reply.status).toBe(402)
    const reissued = Challenge.fromResponseList(reply).find((c) => c.method === 'fermata')!
    expect(reissued.request.callId).not.toBe(X)
    const stolen = Credential.serialize({ challenge: reissued, payload: { type: 'hold', txHash: holdTx, callId: X } })
    expect((await gw.app.request(quote, { headers: { authorization: stolen } })).status).toBe(402)
    expect(attestor.calls).toEqual([]) // nothing was proved for the stranger
    // The victim still gets what it paid for.
    attestor.next = (i) => verdict(i.callId, 1, { status: 200, body: '{"price":1}' })
    const own = Credential.serialize({ challenge: victim, payload: { type: 'hold', txHash: holdTx, callId: X } })
    expect((await gw.app.request(quote, { headers: { authorization: own } })).status).toBe(200)
  })

  it('refuses a replayed credential and a credential reused on another request', async () => {
    attestor.next = (i) => verdict(i.callId, 1, { status: 200, body: '{}' })
    await agentFetch()(QUOTE)
    const replay = await gw.app.request(`${BASE}${QUOTE}`, { headers: { authorization: lastCredential! } })
    expect(replay.status).toBe(402)
    const elsewhere = await gw.app.request(`${BASE}/s/${sid}/v1/quote?symbol=ETH-USD`, { headers: { authorization: lastCredential! } })
    expect(elsewhere.status).toBe(402)
    expect(attestor.calls).toHaveLength(1)
  })

  it('refuses to start when the on-chain verifier or origin does not match', async () => {
    chain.verifier = 'ee'.repeat(32)
    await expect(build()).rejects.toThrow(/not this attestor/)
    chain.verifier = signerKey
    chain.origin = originHash('https://evil.example')
    await expect(build()).rejects.toThrow(/not the registered origin/)
  })

  it('reconciles a released call from the indexed events and lists them', async () => {
    attestor.next = (i) => verdict(i.callId, 1, { status: 200, body: '{}' })
    const callId = receiptOf(await agentFetch()(QUOTE)).callId as Hex
    chain.events.unshift({ name: 'treasury_updated', treasury, ledger: 0, txHash: h('deploy'), id: '0000000000-0000000000' })
    const rec = (await (await gw.app.request(`${BASE}/reconcile/${callId}`)).json()) as { ok: boolean; status: string; movements: unknown[]; recordMatches: boolean }
    expect(rec).toMatchObject({ ok: true, status: 'released', recordMatches: true })
    expect(rec.movements).toHaveLength(3)
    const events = (await (await gw.app.request(`${BASE}/events?since=0`)).json()) as { name: string; callId: string }[]
    expect(events.map((e) => e.name)).toEqual(['held', 'released'])
    expect(await (await gw.app.request(`${BASE}/info`)).json()).toMatchObject({ network: 'stellar:testnet', escrow })
    const all = (await (await gw.app.request(`${BASE}/reconcile`)).json()) as { calls: { held: number; failing: string[] } }
    expect(all.calls).toMatchObject({ held: 1, failing: [] })
  })

  it('serves services, proofs, scores, discovery', async () => {
    expect(await (await gw.app.request(`${BASE}/services`)).json()).toMatchObject([{ serviceId: sid, price: '10000', endpoint: `/s/${sid}`, pay: { mpp: ['fermata'], x402: ['fermata'] } }])
    const proof = await gw.app.request(`${BASE}/proofs/${'11'.repeat(32)}`)
    expect(new Uint8Array(await proof.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]))
    expect((await gw.app.request(`${BASE}/openapi.json`)).status).toBe(200)
    expect(await (await gw.app.request(`${BASE}/llms.txt`)).text()).toContain(`/s/${sid}`)
    expect((await gw.app.request(`${BASE}/s/${'99'.repeat(32)}/x`)).status).toBe(404)
    chain.events.push({ name: 'service_registered', serviceId: sid, owner: vendor, token, label: '00'.repeat(12), payout: vendor, verifier: signerKey, pricePerCall: 10_000n, settlementWindow: 120, ledger: 0, txHash: h('r'), id: '0000000000-0000000001' })
    const scores = (await (await gw.app.request(`${BASE}/scores`)).json()) as { scores: { serviceId: string; known: boolean }[] }
    expect(scores.scores).toMatchObject([{ serviceId: sid, known: true }])
  })
})

describe('gateway, x402', () => {
  it('the fermata scheme: holds through the facilitator, proves, settles, and answers with PAYMENT-RESPONSE', async () => {
    attestor.next = (i) => verdict(i.callId, 1, { status: 200, body: '{"price":2}' })
    const { res, accepted } = await payX402()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ price: 2 })
    const settled = decodePaymentResponseHeader(res.headers.get('payment-response')!)
    expect(settled).toMatchObject({ success: true, payer: agent })
    const callId = holdTermsOf(accepted).callId
    expect(res.headers.get('x-fermata-call')).toBe(callId)
    expect(res.headers.get('x-fermata-outcome')).toBe('DELIVERED')
    expect(await store.get(callId)).toMatchObject({ status: 'released', paidWith: 'x402', sponsored: true, holdTx: settled.transaction })
  })

  it('refuses a replayed payment, a payment for another request and a requirement it did not issue', async () => {
    attestor.next = (i) => verdict(i.callId, 1, { status: 200, body: '{}' })
    const { header } = await payX402()
    expect((await gw.app.request(`${BASE}${QUOTE}`, { headers: { 'payment-signature': header } })).status).toBe(402)
    expect((await gw.app.request(`${BASE}/s/${sid}/v1/quote?symbol=ETH-USD`, { headers: { 'payment-signature': header } })).status).toBe(402)
    const forged = encodePaymentSignatureHeader({
      x402Version: 2,
      accepted: { scheme: 'fermata', network: 'stellar:testnet', asset: token, amount: '10000', payTo: escrow, maxTimeoutSeconds: 60, extra: { escrow, serviceId: sid, requestHash: requestHash(sid, 'GET', '/v1/quote?symbol=BTC-USD'), callId: 'ff'.repeat(32), salt: '00'.repeat(16), expires: 9_999_999_999, areFeesSponsored: true } },
      payload: { transaction: 'signed-hold' },
    })
    const res = await gw.app.request(`${BASE}${QUOTE}`, { headers: { 'payment-signature': forged } })
    expect(res.status).toBe(402)
    expect(decodePaymentRequiredHeader(res.headers.get('payment-required')!).error).toMatch(/did not issue/)
    expect(attestor.calls).toHaveLength(1)
  })

  it('a payload the facilitator refuses holds nothing', async () => {
    const { res } = await payX402(QUOTE, 'garbage')
    expect(res.status).toBe(402)
    expect(chain.holds.size).toBe(0)
    expect(await store.list()).toEqual([])
  })
})

describe('gateway, unprotected fallback', () => {
  it('offers Stellar MPP Charge and x402 exact for a service that configures one, and pays the vendor directly', async () => {
    const recipient = vendor
    const exactCalls: string[] = []
    const exact: X402Facilitator = {
      verify: async () => ({ isValid: true, payer: agent }),
      settle: async (_p, req) => {
        exactCalls.push(req.payTo)
        return { success: true, transaction: 'ab'.repeat(32), network: req.network, payer: agent }
      },
    }
    store = new CallStore(mkdtempSync(path.join(tmpdir(), 'fermata-gw-')))
    const { charge } = await import('@stellar/mpp/charge/server')
    const chargeHandler = charge({ recipient, currency: token, network: 'stellar:testnet', rpcUrl: 'https://127.0.0.1:1', store: Store.memory() })
    const fb = await createGateway({
      config: { ...config({ services: [{ serviceId: sid, upstream, unprotected: { recipient } }] }), storageDir: store.dir },
      chain, attestor, store, secretKey: SECRET, fermataHandler: fakeFermataServer(chain), chargeHandler,
      x402: { fermata: new FakeFermataFacilitator(chain), exact }, indexer: indexer(), log: () => {},
      fetchUpstream: async () => Response.json({ price: 3 }, { headers: { 'content-type': 'application/json' } }),
    })
    const res402 = await fb.app.request(`${BASE}${QUOTE}`)
    expect(Challenge.fromResponseList(res402).map((c) => c.method).sort()).toEqual(['fermata', 'stellar'])
    const charged = Challenge.fromResponseList(res402).find((c) => c.method === 'stellar')!.request as Record<string, unknown>
    expect(charged).toMatchObject({ amount: '10000', currency: token, recipient })
    const accepts = decodePaymentRequiredHeader(res402.headers.get('payment-required')!).accepts
    expect(accepts.map((a) => a.scheme)).toEqual(['fermata', 'exact'])
    const exactReq = accepts[1]!
    expect(exactReq).toMatchObject({ payTo: recipient, asset: token, amount: '10000' })
    const res = await fb.app.request(`${BASE}${QUOTE}`, {
      headers: { 'payment-signature': encodePaymentSignatureHeader({ x402Version: 2, accepted: exactReq, payload: { transaction: 'signed-transfer' } }) },
    })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ price: 3 })
    expect(res.headers.get('x-fermata-unprotected')).toBe('true')
    expect(exactCalls).toEqual([recipient])
    expect(attestor.calls).toEqual([]) // nothing proved
  })

  it('formats base units for the Charge offer', () => {
    expect([toDecimal(100_000n), toDecimal(10_000_000n), toDecimal(1n), toDecimal(0n)]).toEqual(['0.01', '1', '0.0000001', '0'])
  })
})

describe('gateway, sessions', () => {
  const B = 2
  beforeEach(async () => {
    gw = await build({}, {}, { batchSize: B })
  })
  const QUOTE_ETH = `/s/${sid}/v1/quote?symbol=ETH-USD`
  const QUOTE_SOL = `/s/${sid}/v1/quote?symbol=SOL-USD`

  it('offers the session intent beside the hold, with the session contract and the gateway’s limits', async () => {
    const res = await gw.app.request(`${BASE}${QUOTE}`)
    expect(res.status).toBe(402)
    const challenges = Challenge.fromResponseList(res)
    expect(challenges.map((c) => `${c.method}/${c.intent}`)).toEqual(['fermata/charge', 'fermata/session'])
    const s = challenges[1]!.request as Record<string, unknown>
    expect(s).toMatchObject({
      amount: '10000', currency: token, escrow, sessionContract, network: 'stellar:testnet', serviceId: sid,
      requestHash: requestHash(sid, 'GET', '/v1/quote?symbol=BTC-USD'), batchSize: B, maxCalls: 50, maxDuration: 3_600, sponsored: true,
    })
    expect(s.sessionId).toBeUndefined()
    const services = (await (await gw.app.request(`${BASE}/services`)).json()) as Record<string, any>[]
    expect(services[0]!.pay.mpp).toEqual(['fermata', 'fermata session'])
    expect(services[0]!.sessions).toMatchObject({ contract: sessionContract, batchSize: B })
  })

  it('opens a session on the first call, proves every call with its ticket, and settles every B calls', async () => {
    const a = sessionAgent({ maxCalls: 5 })
    attestor.sessionNext = (i) => sessionEntry(i, i.n === 2 ? 2 : 1)
    const first = await a.fetch(QUOTE, { headers: { accept: 'application/json' } })
    expect(first.status).toBe(200)
    expect(await first.json()).toEqual({ price: 1 })
    const sessionId = a.state.sessionId!
    expect(receiptOf(first)).toMatchObject({ method: 'fermata', sessionId, n: 1, outcome: 'DELIVERED' })
    expect(first.headers.get('x-fermata-open-tx')).toBe(h(`open ${sessionId}`))
    expect(chain.sessions.get(sessionId)).toMatchObject({ status: SessionStatus.Open, maxCalls: 5 })

    const second = await a.fetch(QUOTE_ETH)
    expect(second.status).toBe(500) // the vendor's proved answer
    expect(receiptOf(second)).toMatchObject({ sessionId, n: 2, outcome: 'FAILED' })
    // Two recorded calls make a batch: settled at once.
    await gw.settleSession(sessionId)
    expect(chain.batches).toEqual([{ sessionId, from: 0, to: 2, results: [1, 2] }])
    // The attestor saw each call with its ticket, in order, and the gateway's credentials.
    expect(attestor.sessionCalls.map((c) => [c.n, c.url, c.headers.authorization])).toEqual([
      [1, `${upstream}/v1/quote?symbol=BTC-USD`, 'Bearer vendor-secret'],
      [2, `${upstream}/v1/quote?symbol=ETH-USD`, 'Bearer vendor-secret'],
    ])
    const record = await sessionStore.get(sessionId)
    expect(record).toMatchObject({ status: 'open', settled: 2, maxCalls: 5 })
    expect(record!.calls.map((c) => [c.n, c.status, c.outcome])).toEqual([
      [1, 'recorded', 'DELIVERED'],
      [2, 'recorded', 'FAILED'],
    ])
    // chain(2) as the agent computed it.
    expect(record!.calls[1]!.chain).toBe(a.state.chains[2])
  })

  it('names the call it expects next when the agent names its session', async () => {
    const a = sessionAgent()
    await a.fetch(QUOTE)
    const res = await gw.app.request(`${BASE}${QUOTE_ETH}`, { headers: { 'x-fermata-session': a.state.sessionId! } })
    const s = Challenge.fromResponseList(res).find((c) => c.intent === 'session')!.request as Record<string, unknown>
    expect(s).toMatchObject({ sessionId: a.state.sessionId, next: 2, chain: a.state.chains[1] })
  })

  it('settles what is left after the expiry, and closes the session after its deadline', async () => {
    const a = sessionAgent({ maxCalls: 5, seconds: 300 })
    attestor.sessionNext = (i) => (i.n === 3 ? { kind: 'unanswered', n: 3, chain: '', detail: 'no-transcript: vendor silent' } : sessionEntry(i, 1))
    for (const p of [QUOTE, QUOTE_ETH, QUOTE_SOL]) await a.fetch(p)
    const sessionId = a.state.sessionId!
    await gw.sweep()
    expect(chain.batches.map((b) => [b.from, b.to])).toEqual([[0, 2]])
    // After the expiry the last call settles alone; after the deadline the session closes.
    chain.time += 301n
    await gw.sweep()
    expect(chain.batches.map((b) => [b.from, b.to, b.results])).toEqual([
      [0, 2, [1, 1]],
      [2, 3, [4]],
    ])
    expect(chain.closes).toEqual([])
    chain.time += 121n
    await gw.sweep()
    expect(chain.closes).toEqual([sessionId])
    expect(await sessionStore.get(sessionId)).toMatchObject({ status: 'closed', settled: 3, closeTx: h(`close ${sessionId}`) })
    // Reconciled from the session contract's events: 2 calls paid, 1 refunded, 2 never made.
    const r = (await (await gw.app.request(`${BASE}/sessions/${sessionId}/reconcile`)).json()) as Record<string, any>
    expect(r).toMatchObject({ ok: true, status: 'closed', settled: 3, paidCalls: 2, remaining: '0', recordMatches: true })
    const all = (await (await gw.app.request(`${BASE}/reconcile/sessions`)).json()) as Record<string, any>
    expect(all).toMatchObject({ ok: true, sessions: { opened: 1, closed: 1, failing: [] } })
  })

  it('a session full after its last call is closed by its last batch', async () => {
    const a = sessionAgent({ maxCalls: 3 })
    for (const p of [QUOTE, QUOTE_ETH, QUOTE_SOL]) await a.fetch(p)
    await gw.sweep()
    expect(chain.batches.map((b) => [b.from, b.to])).toEqual([
      [0, 2],
      [2, 3],
    ])
    expect(chain.sessions.get(a.state.sessionId!)!.status).toBe(SessionStatus.Closed)
    expect(await sessionStore.get(a.state.sessionId!)).toMatchObject({ status: 'closed', settled: 3 })
    expect(chain.closes).toEqual([])
  })

  it('refuses a call out of order, a ticket over another request, and a replayed credential', async () => {
    const a = sessionAgent()
    await a.fetch(QUOTE)
    const sessionId = a.state.sessionId!
    // A ticket for call 2 signed over another request.
    const res402 = await gw.app.request(`${BASE}${QUOTE_ETH}`)
    const challenge = Challenge.fromResponseList(res402).find((c) => c.intent === 'session')!
    const seed = new Uint8Array(32).fill(0x7c)
    const domain = { networkPassphrase: PASSPHRASE, contract: sessionContract }
    const other = chainNext(a.state.chains[1]!, requestHash(sid, 'GET', '/v1/quote?symbol=SOL-USD'))
    const wrongTicket = await signTicket(seed, domain, sessionId, 2, other)
    const pay = (payload: Record<string, unknown>) =>
      gw.app.request(`${BASE}${QUOTE_ETH}`, { headers: { authorization: Credential.serialize({ challenge, payload } as never) } })
    expect((await pay({ action: 'call', sessionId, n: 2, ticket: wrongTicket })).status).toBe(402)
    // Call 3 before call 2.
    const right3 = await signTicket(seed, domain, sessionId, 3, chainNext(a.state.chains[1]!, challenge.request.requestHash as string))
    expect((await pay({ action: 'call', sessionId, n: 3, ticket: right3 })).status).toBe(402)
    // The right ticket works once; replayed, it is refused.
    const right2 = await signTicket(seed, domain, sessionId, 2, chainNext(a.state.chains[1]!, challenge.request.requestHash as string))
    expect((await pay({ action: 'call', sessionId, n: 2, ticket: right2 })).status).toBe(200)
    expect((await pay({ action: 'call', sessionId, n: 2, ticket: right2 })).status).toBe(402)
    expect(attestor.sessionCalls.map((c) => c.n)).toEqual([1, 2])
  })

  it('a call the attestor did not record blocks the session until the sweeper records it unanswered', async () => {
    const a = sessionAgent()
    await a.fetch(QUOTE)
    attestor.unreachable = true
    const cut = await a.fetch(QUOTE_ETH)
    expect(cut.status).toBe(504)
    expect(receiptOf(cut)).toMatchObject({ n: 2, outcome: null })
    const sessionId = a.state.sessionId!
    expect((await sessionStore.get(sessionId))!.calls[1]).toMatchObject({ n: 2, status: 'unrecorded' })
    // Call 3 is refused while call 2 is unrecorded.
    attestor.unreachable = false
    expect((await a.fetch(QUOTE_SOL)).status).toBe(402)
    await gw.sweep()
    expect(attestor.unansweredCalls.map((c) => [c.n, c.ticket])).toEqual([[2, (await sessionStore.get(sessionId))!.calls[1]!.ticket]])
    expect((await sessionStore.get(sessionId))!.calls[1]).toMatchObject({ status: 'recorded', outcome: 'UNANSWERED' })
    expect(chain.batches).toEqual([{ sessionId, from: 0, to: 2, results: [1, 4] }])
  })

  it('an opening that never landed is closed after 15 minutes', async () => {
    chain.openFails = true
    const a = sessionAgent()
    const res = await a.fetch(QUOTE)
    expect(res.status).toBe(402)
    const sessionId = a.state.sessionId!
    expect(await sessionStore.get(sessionId)).toMatchObject({ status: 'opening' })
    await gw.sweep()
    expect(await sessionStore.get(sessionId)).toMatchObject({ status: 'opening' })
    const old = await sessionStore.get(sessionId)
    await sessionStore.put({ ...old!, createdAt: new Date(Date.now() - 16 * 60_000).toISOString() })
    await gw.sweep()
    expect(await sessionStore.get(sessionId)).toMatchObject({ status: 'closed', error: 'open_session never landed' })
  })

  it('refuses to start when the attestor proves another session contract', async () => {
    attestor.sessionContract = contractAddress(new Uint8Array(32).fill(0x77))
    await expect(
      createGateway({
        config: { ...config(), storageDir: store.dir }, chain, attestor, store, secretKey: SECRET, fermataHandler: fakeFermataServer(chain),
        sessions: { handler: fakeSessionServer(chain, sessionStore), store: sessionStore, batchSize: B, maxCalls: 50, maxDurationSeconds: 3_600 },
        log: () => {},
      }),
    ).rejects.toThrow(/proves sessions of/)
  })
})
