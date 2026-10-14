// The Fermata gateway on Stellar: a paid-API proxy. A paid request holds the price in the escrow,
// the attestor proves the vendor's HTTPS response with TLSNotary, and the gateway settles the
// verdict: the vendor is paid on DELIVERED, the agent refunded on FAILED, and without a verdict the
// sweeper refunds the agent after the window.
//
// Ported from Fermata `apps/gateway/src/app.ts` @ d7cc642 (github.com/bilgin-kocak/fermata, MIT).
// Kept: the paid route `/s/:serviceId/*`, the services checked against the chain and the attestor at
// start, admission control, fulfil → prove → settle, the proved response returned byte for byte,
// the receipt fields, the call store, the read API, offline re-verification against the chain, the
// non-overlapping sweeper, the dashboard and discovery. Changed for Stellar:
// - one 402 offers four ways to pay: the `fermata` MPP method and Stellar's MPP Charge
//   (`WWW-Authenticate`), and the `fermata` x402 scheme and x402 `exact` (`PAYMENT-REQUIRED`);
//   Charge and `exact` pay the vendor directly and are unprotected, like Fermata's `tempo`;
// - scores, the live feed and reconciliation read the event indexer instead of `eth_getLogs`, and
//   reconciliation joins the escrow's events with the token's transfers instead of memos;
// - sponsored holds are recorded before they are submitted (status `holding`).
// Not ported (later milestones): the MCP endpoint, self-serve onboarding, the public demo.
//
// Sessions (docs/session-escrow.md, phase 1, with a session contract configured): the 402 also
// offers the `fermata` method's `session` intent. The first call opens a session (the gateway
// submits the agent's `open_session`), each later call carries the agent's ticket; every call is
// proved, and the sweeper settles the recorded calls in batches with the attestor's statements and
// closes the session after its deadline.
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { serveStatic } from '@hono/node-server/serve-static'
import { Hono, type Context } from 'hono'
import { Challenge, Credential, Receipt, type Method } from 'mppx'
import { discovery } from 'mppx/hono'
import { Mppx } from 'mppx/server'
import { decodePaymentSignatureHeader, encodePaymentRequiredHeader, encodePaymentResponseHeader } from '@x402/core/http'
import type { Network, PaymentPayload, PaymentRequirements, SettleResponse, VerifyResponse } from '@x402/core/types'
import {
  aggregateScores,
  chainNext,
  eventToJson,
  eventually,
  fermataRequirements,
  fermataRequirementsProblem,
  holdTermsOf,
  HoldStatus,
  originHash,
  predicateHash,
  reconcileCall,
  reconcileEscrow,
  reconcileSession,
  reconcileSessions,
  requestHash,
  SessionStatus as OnchainSessionStatus,
  type fermataMethod,
  type fermataSessionMethod,
  type FermataOffer,
  type Hex,
  type IndexedEvent,
} from 'fermata-stellar-sdk'
import type { Attestor, ProvedResponse } from './attestor.ts'
import type { GatewayChain } from './chain.ts'
import type { GatewayConfig, ServiceConfig } from './config.ts'
import { nextOf, type SessionCall, type SessionRecord, type SessionStore } from './sessions.ts'
import { FINAL, type CallRecord, type CallStore } from './store.ts'

/** An x402 facilitator as the gateway uses it: in process, or OpenZeppelin's over HTTP. */
export type X402Facilitator = {
  verify(payload: PaymentPayload, requirements: PaymentRequirements): Promise<VerifyResponse>
  settle(payload: PaymentPayload, requirements: PaymentRequirements): Promise<SettleResponse>
}

/** The event index the read API serves from (fermata-stellar-sdk `EscrowIndexer`). */
export type EventSource = {
  readonly events: readonly IndexedEvent[]
  readonly gaps: readonly { from: number; to: number }[]
  readonly latestLedger: number
  poll(): Promise<number>
}

export type GatewayDeps = {
  config: GatewayConfig
  chain: GatewayChain
  attestor: Attestor
  store: CallStore
  /** mppx HMAC secret (≥ 32 bytes); it also keys the x402 call ids. */
  secretKey: string
  /** The `fermata` MPP method's server side (`fermataServer`; a fake in unit tests). */
  fermataHandler: Method.Server<typeof fermataMethod>
  /** Stellar's MPP Charge, the unprotected MPP fallback (`@stellar/mpp`); none when absent. */
  chargeHandler?: Method.AnyServer
  /** x402 facilitators: the `fermata` scheme's and `exact`'s. A scheme without one is not offered. */
  x402?: { fermata?: X402Facilitator; exact?: X402Facilitator }
  indexer?: EventSource
  /**
   * Sessions, when the chain has a session contract: the `session` intent's server side
   * (`fermataSessionServer`; a fake in unit tests), the gateway's records, its limits, and the
   * session contract's event index.
   */
  sessions?: {
    handler: Method.Server<typeof fermataSessionMethod>
    store: SessionStore
    /** B: the calls per batch, which `open_session` must use. */
    batchSize: number
    /** The most calls one session may hold a deposit for. */
    maxCalls: number
    /** The longest a session may take calls, in seconds. */
    maxDurationSeconds: number
    indexer?: EventSource
  }
  env?: Record<string, string | undefined>
  /** Upstream fetch for the unprotected fallback (needs the vendor's CA). */
  fetchUpstream?: (url: string, init: RequestInit) => Promise<Response>
  log?: (msg: string) => void
  /** Built dashboard (apps/dashboard/dist), served at /dashboard. */
  dashboardDir?: string
  /**
   * What a third party needs to re-verify a proof offline: the vendor CA the demo vendors'
   * certificates chain to (served at /ca.pem) and the directories holding the predicates (served at
   * /predicates/:hash; the caller checks the hash against the chain).
   */
  verifierFiles?: { caPath?: string; predicateDirs: string[] }
}

/** JSON-safe copy (bigints as decimal strings). */
const plain = <T>(v: T): unknown => JSON.parse(JSON.stringify(v, (_, x) => (typeof x === 'bigint' ? x.toString() : x)))

export type Service = ServiceConfig & { price: bigint; token: string; window: number; verifier: Hex; predicateHash: Hex; payout: string }

const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'transfer-encoding', 'content-length', 'upgrade', 'proxy-connection', 'te', 'trailer'])
const ZERO_HASH = '00'.repeat(32)
const RESULT_DELIVERED = 1
const DECIMALS = 7

/** Base units to the decimal string Stellar's MPP Charge takes (classic assets have 7 decimals). */
export function toDecimal(units: bigint, decimals = DECIMALS): string {
  const s = units.toString().padStart(decimals + 1, '0')
  const whole = s.slice(0, -decimals)
  const frac = s.slice(-decimals).replace(/0+$/, '')
  return frac ? `${whole}.${frac}` : whole
}

/** The vendor's response as proved by the attestor, returned to the agent byte for byte. */
export function provedToResponse(p: ProvedResponse): Response {
  if (p.status == null) {
    return Response.json({ error: 'upstream response is not HTTP', detail: p.error }, { status: 502 })
  }
  const headers = new Headers()
  for (const [k, v] of p.headers ?? []) if (!HOP_BY_HOP.has(k.toLowerCase())) headers.append(k, v)
  const body = [204, 304].includes(p.status) ? null : Buffer.from(p.bodyBase64 ?? '', 'base64')
  return new Response(body, { status: p.status, headers })
}

/** A configured service checked against the chain: registered, settled by this attestor, same origin. */
async function checkService(deps: GatewayDeps, signerKey: Hex, cfg: ServiceConfig): Promise<Service> {
  const s = await deps.chain.service(cfg.serviceId)
  if (!s) throw new Error(`service ${cfg.serviceId} is not registered on ${deps.chain.escrow}`)
  if (s.verifier !== signerKey.toLowerCase()) throw new Error(`service ${cfg.serviceId} is settled by ${s.verifier}, not this attestor (${signerKey})`)
  if (originHash(cfg.upstream) !== s.originHash) throw new Error(`service ${cfg.serviceId}: upstream ${cfg.upstream} is not the registered origin`)
  return { ...cfg, serviceId: s.serviceId, price: s.pricePerCall, token: s.token, window: s.settlementWindow, verifier: s.verifier, predicateHash: s.predicateHash, payout: s.payout }
}

/** Checks every configured service against the chain and the attestor; refuses to start on mismatch. */
export async function loadServices(deps: GatewayDeps): Promise<Map<string, Service>> {
  const health = await deps.attestor.health()
  if (health.escrow !== deps.chain.escrow) throw new Error(`attestor serves escrow ${health.escrow}, gateway ${deps.chain.escrow}`)
  if (health.network !== deps.chain.networkPassphrase) throw new Error(`attestor on "${health.network}", gateway on "${deps.chain.networkPassphrase}"`)
  if (deps.sessions && health.sessionContract !== deps.chain.sessionContract) {
    throw new Error(`attestor proves sessions of ${health.sessionContract ?? 'no session contract'}, gateway ${deps.chain.sessionContract}`)
  }
  const out = new Map<string, Service>()
  for (const cfg of deps.config.services) {
    const s = await checkService(deps, health.signerKey, cfg)
    out.set(s.serviceId, s)
  }
  return out
}

export async function createGateway(deps: GatewayDeps) {
  const log = deps.log ?? ((m: string) => console.log(`[gateway] ${m}`))
  const services = await loadServices(deps)
  const { chain, store, attestor, fermataHandler, chargeHandler } = deps
  const { signerKey } = await attestor.health()
  const network = deps.config.network as Network
  const sessions = deps.sessions
  const methods: unknown[] = [fermataHandler, ...(sessions ? [sessions.handler] : []), ...(chargeHandler ? [chargeHandler] : [])]
  const mppx = Mppx.create({ secretKey: deps.secretKey, realm: deps.config.realm, methods: methods as never })

  const fermataOffer = (svc: Service, rh: Hex): FermataOffer => ({ network, escrow: chain.escrow, token: svc.token, amount: svc.price, serviceId: svc.serviceId, requestHash: rh })
  const unprotectedAmount = (svc: Service) => BigInt(svc.unprotected?.amount ?? svc.price)

  /**
   * The MPP offers for one request: `fermata` (a hold), its `session` intent when sessions are
   * enabled (with the gateway's view of the agent's session, `view`), and Stellar's Charge when the
   * service has a fallback.
   */
  const offers = (svc: Service, rh: Hex, view?: { sessionId: Hex; next: number; chain: Hex }) => {
    const list: [unknown, Record<string, unknown>][] = [
      [fermataHandler, { amount: svc.price.toString(), currency: svc.token, escrow: chain.escrow, network: deps.config.network, serviceId: svc.serviceId, requestHash: rh }],
    ]
    if (sessions && chain.sessionContract) {
      list.push([
        sessions.handler,
        {
          amount: svc.price.toString(),
          currency: svc.token,
          escrow: chain.escrow,
          sessionContract: chain.sessionContract,
          network: deps.config.network,
          serviceId: svc.serviceId,
          requestHash: rh,
          batchSize: sessions.batchSize,
          maxCalls: sessions.maxCalls,
          maxDuration: sessions.maxDurationSeconds,
          ...(view ?? {}),
        },
      ])
    }
    if (svc.unprotected && chargeHandler) {
      list.push([chargeHandler, { amount: toDecimal(unprotectedAmount(svc)), currency: svc.token, recipient: svc.unprotected.recipient }])
    }
    return mppx.compose(...(list as never as Parameters<typeof mppx.compose>))
  }

  /** The x402 requirements for one request: the `fermata` scheme, and `exact` for a fallback. */
  const exactRequirements = (svc: Service): PaymentRequirements | undefined =>
    svc.unprotected && deps.x402?.exact
      ? { scheme: 'exact', network, asset: svc.token, amount: unprotectedAmount(svc).toString(), payTo: svc.unprotected.recipient, maxTimeoutSeconds: 60, extra: { areFeesSponsored: true } }
      : undefined
  const x402Accepts = (svc: Service, rh: Hex): PaymentRequirements[] => {
    const out: PaymentRequirements[] = []
    if (deps.x402?.fermata) out.push(fermataRequirements(fermataOffer(svc, rh), deps.secretKey))
    const exact = exactRequirements(svc)
    if (exact) out.push(exact)
    return out
  }

  /** A 402 carrying the MPP challenges and, in `PAYMENT-REQUIRED`, the x402 requirements. */
  async function paymentRequired(svc: Service, rh: Hex, url: string, base?: Response, error?: string): Promise<Response> {
    const res = base ?? Response.json({ error: error ?? 'payment required' }, { status: 402 })
    const headers = new Headers(res.headers)
    const accepts = x402Accepts(svc, rh)
    if (accepts.length) {
      headers.set(
        'PAYMENT-REQUIRED',
        encodePaymentRequiredHeader({ x402Version: 2, ...(error ? { error } : {}), resource: { url, description: svc.summary ?? 'Paid call (escrowed, released on proof)' }, accepts }),
      )
    }
    return new Response(await res.arrayBuffer(), { status: 402, headers })
  }

  const upstreamHeaders = (svc: Service, incoming: Headers) => {
    const headers: Record<string, string> = {}
    for (const name of svc.forwardHeaders ?? ['content-type', 'accept']) {
      const v = incoming.get(name)
      if (v) headers[name] = v
    }
    if (svc.upstreamAuth) {
      const secret = (deps.env ?? process.env)[svc.upstreamAuth.env]
      if (secret) headers[svc.upstreamAuth.header.toLowerCase()] = secret
    }
    return headers
  }

  const fermataHeaders = (headers: Headers, record: CallRecord) => {
    headers.set('X-Fermata-Call', record.callId)
    headers.set('X-Fermata-Status', record.status)
    if (record.outcome) headers.set('X-Fermata-Outcome', record.outcome)
    if (record.holdTx) headers.set('X-Fermata-Hold-Tx', record.holdTx)
    if (record.settleTx) headers.set('X-Fermata-Settle-Tx', record.settleTx)
  }

  const withFermataReceipt = (res: Response, record: CallRecord) => {
    const base = Receipt.fromResponse(res)
    const receipt = {
      ...base,
      callId: record.callId,
      holdTx: record.holdTx,
      txHash: record.settleTx ?? null,
      presentationHash: record.presentationHash ?? null,
      outcome: record.outcome ?? (record.status === 'awaiting-timeout' ? 'AWAITING_TIMEOUT' : null),
      status: base.status,
    }
    res.headers.set('Payment-Receipt', Receipt.serialize(receipt as never))
    fermataHeaders(res.headers, record)
    return res
  }

  async function settleVerdict(record: CallRecord): Promise<CallRecord> {
    const result = await chain.settle(record.callId, record.verdict!, record.signature!)
    if (result.ok) {
      log(`call ${record.callId.slice(0, 8)} ${record.outcome} settled in ${result.txHash}`)
      return store.update(record.callId, { status: record.outcome === 'DELIVERED' ? 'released' : 'refunded', settleTx: result.txHash, error: undefined })
    }
    log(`call ${record.callId.slice(0, 8)} settle failed: ${result.error}`)
    return store.update(record.callId, { status: 'settle-pending', error: `settle: ${result.error}` })
  }

  // Calls a request in this process is paying for or proving, from before the call's first record
  // is written until the response is sent. The sweeper leaves them alone whatever their status: it
  // would otherwise act on a record the request is about to move on (it once wrote 'awaiting-timeout'
  // over a call that was being proved). A non-final record outside this set was interrupted (a
  // restart): the sweeper ends it with claim_timeout, so the agent is still refunded.
  const inFlight = new Set<string>()
  // Proofs are serialised in the attestor: past this many in flight, new payers get 503 before paying.
  const maxInFlight = Number(deps.env?.GATEWAY_MAX_IN_FLIGHT ?? process.env.GATEWAY_MAX_IN_FLIGHT ?? 4)
  const saturated = () => inFlight.size >= maxInFlight

  /** Runs `run` with `callId` marked in flight, unless a caller up the stack already marked it. */
  async function inFlightDuring<T>(callId: string, run: () => Promise<T>): Promise<T> {
    if (inFlight.has(callId)) return run()
    inFlight.add(callId)
    try {
      return await run()
    } finally {
      inFlight.delete(callId)
    }
  }

  /** The call id of an MPP `fermata` credential whose challenge this gateway signed, if any. */
  function fermataCallOf(request: Request): string | undefined {
    try {
      const credential = Credential.fromRequest(request)
      if (credential.challenge.method !== 'fermata' || !Challenge.verify(credential.challenge, { secretKey: deps.secretKey })) return undefined
      const callId = (credential.challenge.request as { callId?: unknown }).callId
      return typeof callId === 'string' && /^[0-9a-f]{64}$/i.test(callId) ? callId.toLowerCase() : undefined
    } catch {
      return undefined
    }
  }

  type Req = { method: string; target: string; headers: Headers; body: Uint8Array; rh: Hex }
  type Paid = { callId: Hex; holdTx?: Hex; paidWith: 'mpp' | 'x402'; sponsored: boolean }

  /** After a valid hold: record it, prove the vendor's answer, settle the verdict. */
  function fulfil(svc: Service, req: Req, paid: Paid): Promise<{ response: Response; record: CallRecord }> {
    return inFlightDuring(paid.callId, () => prove(svc, req, paid))
  }

  async function prove(svc: Service, req: Req, paid: Paid): Promise<{ response: Response; record: CallRecord }> {
    const { callId } = paid
    // The hold was just checked; a lagging or failing RPC must not stop the record being written
    // (without it the sweeper could never claim this hold's timeout refund).
    const hold = await eventually(() => chain.hold(callId), (h) => h !== undefined, 6).catch(() => undefined)
    const now = new Date().toISOString()
    const prior = await store.get(callId)
    let record = await store.put({
      ...(prior ?? { createdAt: now }),
      callId,
      serviceId: svc.serviceId,
      method: req.method,
      target: req.target,
      requestHash: req.rh,
      paidWith: paid.paidWith,
      sponsored: paid.sponsored,
      holdTx: paid.holdTx ?? prior?.holdTx,
      agent: hold?.agent,
      deadline: (hold?.deadline ?? 0n).toString(),
      status: 'held',
      createdAt: prior?.createdAt ?? now,
      updatedAt: now,
    })

    const result = await attestor.attest({
      callId,
      url: `${svc.upstream}${req.target}`,
      method: req.method,
      headers: upstreamHeaders(svc, req.headers),
      body: Buffer.from(req.body).toString('utf8'),
    })

    if (result.kind !== 'verdict') {
      // No transcript (vendor silent, TLS failure, notary or prover down) or a failed binding check:
      // never a verdict. Only claim_timeout can end the hold; the sweeper sends it after the window.
      const detail = result.kind === 'rejected' ? `${result.check}: ${result.detail}` : result.detail
      log(`call ${callId.slice(0, 8)} has NO VERDICT (${result.kind}: ${detail}); awaiting timeout at ${hold?.deadline ?? '?'}`)
      record = await store.update(callId, { status: 'awaiting-timeout', error: `${result.kind}: ${detail}` })
      const response = Response.json(
        {
          error: result.kind,
          detail,
          callId,
          status: 'awaiting-timeout',
          refundAfter: hold?.deadline.toString() ?? null,
          reclaim: 'claim_timeout(call_id) on the escrow after refundAfter (anyone can send it; the gateway does)',
        },
        { status: result.kind === 'rejected' ? 502 : 504 },
      )
      return { response, record }
    }

    record = await store.update(callId, {
      outcome: result.signed.outcome,
      failures: result.signed.failures,
      verdict: result.signed.verdict,
      signature: result.signed.signature,
      presentationHash: result.presentationHash,
      proveMs: result.proveMs,
      signer: result.signed.signer,
    })
    record = await settleVerdict(record)
    return { response: provedToResponse(result.response), record }
  }

  /** Unprotected fallback (Charge, `exact`): the vendor was paid directly; no escrow, no proof. */
  async function unprotected(svc: Service, req: Req): Promise<Response> {
    const upstream = await (deps.fetchUpstream ?? fetch)(`${svc.upstream}${req.target}`, {
      method: req.method,
      headers: upstreamHeaders(svc, req.headers),
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.from(req.body),
    })
    const headers = new Headers()
    upstream.headers.forEach((v, k) => !HOP_BY_HOP.has(k.toLowerCase()) && headers.set(k, v))
    headers.set('X-Fermata-Unprotected', 'true')
    return new Response(await upstream.arrayBuffer(), { status: upstream.status, headers })
  }

  async function payX402(c: Context, svc: Service, req: Req, header: string): Promise<Response> {
    const url = c.req.url
    let payload: PaymentPayload
    try {
      payload = decodePaymentSignatureHeader(header)
    } catch {
      return paymentRequired(svc, req.rh, url, undefined, 'unreadable PAYMENT-SIGNATURE')
    }
    const accepted = payload.accepted
    const facilitator = deps.x402?.fermata
    if (accepted?.scheme === 'fermata' && facilitator) {
      const problem = fermataRequirementsProblem(accepted, fermataOffer(svc, req.rh), deps.secretKey)
      if (problem) return paymentRequired(svc, req.rh, url, undefined, problem)
      const verified = await facilitator.verify(payload, accepted)
      if (!verified.isValid) return paymentRequired(svc, req.rh, url, undefined, verified.invalidMessage ?? verified.invalidReason)
      const { callId } = holdTermsOf(accepted)
      // Marked in flight before its first record, with no await in between: a concurrent copy of
      // this payment is turned away here, and the sweeper leaves the call alone until it is answered.
      if (inFlight.has(callId)) return paymentRequired(svc, req.rh, url, undefined, 'this payment is already being processed')
      return inFlightDuring(callId, async () => {
        if (await store.get(callId)) return paymentRequired(svc, req.rh, url, undefined, 'this payment was already used')
        const now = new Date().toISOString()
        await store.put({
          callId, serviceId: svc.serviceId, method: req.method, target: req.target, requestHash: req.rh, paidWith: 'x402', sponsored: true,
          agent: verified.payer, deadline: '0', status: 'holding', createdAt: now, updatedAt: now,
        })
        const settled = await facilitator.settle(payload, accepted)
        if (!settled.success) {
          await store.update(callId, { error: `hold: ${settled.errorMessage ?? settled.errorReason}` })
          return paymentRequired(svc, req.rh, url, undefined, settled.errorMessage ?? settled.errorReason)
        }
        const { response, record } = await fulfil(svc, req, { callId, holdTx: settled.transaction, paidWith: 'x402', sponsored: true })
        const headers = new Headers(response.headers)
        headers.set('PAYMENT-RESPONSE', encodePaymentResponseHeader(settled))
        fermataHeaders(headers, record)
        return new Response(response.body, { status: response.status, headers })
      })
    }
    const exact = exactRequirements(svc)
    if (accepted?.scheme === 'exact' && exact && deps.x402?.exact) {
      const same = (['scheme', 'network', 'asset', 'amount', 'payTo'] as const).every((k) => accepted[k] === exact[k])
      if (!same) return paymentRequired(svc, req.rh, url, undefined, 'the payment is for other requirements')
      const verified = await deps.x402.exact.verify(payload, exact)
      if (!verified.isValid) return paymentRequired(svc, req.rh, url, undefined, verified.invalidMessage ?? verified.invalidReason)
      const settled = await deps.x402.exact.settle(payload, exact)
      if (!settled.success) return paymentRequired(svc, req.rh, url, undefined, settled.errorMessage ?? settled.errorReason)
      const res = await unprotected(svc, req)
      res.headers.set('PAYMENT-RESPONSE', encodePaymentResponseHeader(settled))
      return res
    }
    return paymentRequired(svc, req.rh, url, undefined, `scheme ${accepted?.scheme ?? '?'} is not offered here`)
  }

  // ------------------------------------------------------------------------------ sessions

  // A session's calls and its settlements run one at a time, in order: each writes the session's
  // record, and the attestor takes a session's calls in order.
  const sessionQueues = new Map<string, Promise<unknown>>()
  function sessionQueue<T>(sessionId: string, task: () => Promise<T>): Promise<T> {
    const run = (sessionQueues.get(sessionId) ?? Promise.resolve()).then(task, task)
    const settled = run.then(
      () => undefined,
      () => undefined,
    )
    sessionQueues.set(sessionId, settled)
    void settled.then(() => sessionQueues.get(sessionId) === settled && sessionQueues.delete(sessionId))
    return run
  }

  /** The gateway's view of the session an agent names in `X-Fermata-Session`, for this service. */
  async function sessionViewFor(svc: Service, headers: Headers) {
    const id = headers.get('x-fermata-session')?.trim().toLowerCase()
    if (!sessions || !id || !/^[0-9a-f]{64}$/.test(id)) return undefined
    const r = await sessions.store.get(id)
    if (!r || r.serviceId !== svc.serviceId || r.status !== 'open') return undefined
    return { sessionId: id, ...nextOf(r) }
  }

  const sessionHeaders = (headers: Headers, record: SessionRecord, call: SessionCall) => {
    headers.set('X-Fermata-Session', record.sessionId)
    headers.set('X-Fermata-Session-Status', record.status)
    headers.set('X-Fermata-Call-N', String(call.n))
    if (call.outcome) headers.set('X-Fermata-Outcome', call.outcome)
    if (record.openTx) headers.set('X-Fermata-Open-Tx', record.openTx)
  }

  const withSessionReceipt = (res: Response, record: SessionRecord, call: SessionCall) => {
    const base = Receipt.fromResponse(res)
    const receipt = {
      ...base,
      sessionId: record.sessionId,
      n: call.n,
      chain: call.chain,
      outcome: call.outcome ?? null,
      presentationHash: call.presentationHash ?? null,
    }
    res.headers.set('Payment-Receipt', Receipt.serialize(receipt as never))
    sessionHeaders(res.headers, record, call)
    return res
  }

  /** Recorded calls right after the contract's settled ones, in a row: what a batch can settle. */
  function readyCalls(r: SessionRecord): number {
    let ready = 0
    for (const c of [...r.calls].filter((x) => x.n > r.settled).sort((a, b) => a.n - b.n)) {
      if (c.n !== r.settled + ready + 1 || c.status !== 'recorded') break
      ready++
    }
    return ready
  }

  /** After a valid session credential: record the call, prove it, record its entry. */
  function sessionCall(svc: Service, req: Req, payload: { action: 'open' | 'call'; sessionId: string; n?: number; ticket: string }, openTx?: Hex) {
    const store = sessions!.store
    const sessionId = payload.sessionId.toLowerCase()
    const n = payload.action === 'open' ? 1 : payload.n!
    return sessionQueue(sessionId, async () => {
      let record = await store.get(sessionId)
      if (!record) throw new Error(`no record of session ${sessionId}`)
      if (payload.action === 'open') {
        const onchain = await eventually(() => chain.session(sessionId), (x) => x !== undefined, 6).catch(() => undefined)
        record = await store.update(sessionId, { status: 'open', openTx, ...(onchain ? { deadline: onchain.deadline.toString() } : {}) })
        log(`session ${sessionId.slice(0, 8)} opened for ${record.maxCalls} calls in ${openTx}`)
      }
      const { next, chain: prev } = nextOf(record)
      if (n !== next) throw new Error(`call ${n} of session ${sessionId} is not the next one (${next})`)
      const call: SessionCall = {
        n,
        method: req.method,
        target: req.target,
        requestHash: req.rh,
        chain: chainNext(prev, req.rh),
        ticket: payload.ticket.toLowerCase(),
        status: 'proving',
        createdAt: new Date().toISOString(),
      }
      record = await store.put({ ...record, calls: [...record.calls, call] })
      const result = await attestor.sessionAttest({
        sessionId,
        n,
        ticket: payload.ticket,
        url: `${svc.upstream}${req.target}`,
        method: req.method,
        headers: upstreamHeaders(svc, req.headers),
        body: Buffer.from(req.body).toString('utf8'),
      })
      let response: Response
      if (result.kind === 'entry') {
        record = await store.updateCall(sessionId, n, {
          status: 'recorded',
          outcome: result.outcome,
          presentationHash: result.presentationHash,
          failures: result.failures,
          proveMs: result.proveMs,
        })
        response = provedToResponse(result.response)
      } else if (result.kind === 'unanswered') {
        log(`session ${sessionId.slice(0, 8)} call ${n}: no proof (${result.detail}); refunded with its batch`)
        record = await store.updateCall(sessionId, n, { status: 'recorded', outcome: 'UNANSWERED', error: result.detail })
        response = Response.json(
          { error: 'no-proof', detail: result.detail, sessionId, n, outcome: 'UNANSWERED', refund: 'this call is refunded when its batch settles' },
          { status: 502 },
        )
      } else {
        const detail = result.kind === 'refused' ? `${result.check ?? result.status}: ${result.detail}` : result.detail
        log(`session ${sessionId.slice(0, 8)} call ${n} NOT RECORDED by the attestor (${detail})`)
        record = await store.updateCall(sessionId, n, { status: 'unrecorded', error: detail })
        response = Response.json(
          { error: result.kind, detail, sessionId, n, status: 'unrecorded', refund: 'the gateway has this call recorded unanswered, refunded with its batch' },
          { status: result.kind === 'unreachable' ? 504 : 502 },
        )
      }
      if (readyCalls(record) >= record.batchSize) void settleSession(sessionId)
      return { response, record, call: record.calls.find((c) => c.n === n)! }
    })
  }

  const settlingQueued = new Set<string>()

  /**
   * Settles what is due of a session, in its queue: batches of B recorded calls; after its expiry,
   * or when it is full, what is left; after its deadline it closes the session. Calls the attestor
   * did not record are first recorded as unanswered.
   */
  function settleSession(sessionId: Hex): Promise<SessionRecord | undefined> {
    if (!sessions || settlingQueued.has(sessionId)) return Promise.resolve(undefined)
    settlingQueued.add(sessionId)
    return sessionQueue(sessionId, async () => {
      settlingQueued.delete(sessionId)
      try {
        return await settleNow(sessionId)
      } catch (e) {
        log(`session ${sessionId.slice(0, 8)} settlement failed: ${(e as Error).message}`)
        return undefined
      }
    })
  }

  async function settleNow(sessionId: Hex): Promise<SessionRecord | undefined> {
    const store = sessions!.store
    let record = await store.get(sessionId)
    if (!record || record.status === 'closed') return record
    const onchain = await chain.session(sessionId)
    if (record.status === 'opening') {
      if (!onchain) {
        // A sponsored opening that never landed: its authorization expires within minutes.
        if (Date.now() - Date.parse(record.createdAt) > 15 * 60_000) {
          return store.update(sessionId, { status: 'closed', error: record.error ?? 'open_session never landed' })
        }
        return record
      }
      record = await store.update(sessionId, { status: 'open', deadline: onchain.deadline.toString() })
    }
    if (!onchain) return record
    if (onchain.status === OnchainSessionStatus.Closed) {
      return store.update(sessionId, { status: 'closed', settled: onchain.settled })
    }
    if (onchain.settled !== record.settled) record = await store.update(sessionId, { settled: onchain.settled })
    for (const c of record.calls.filter((x) => x.status === 'unrecorded')) {
      const svc = services.get(record.serviceId)
      const r = await attestor.sessionUnanswered({
        sessionId,
        n: c.n,
        ticket: c.ticket,
        url: `${svc?.upstream ?? ''}${c.target}`,
        method: c.method,
        headers: {},
        body: '',
      })
      if (r.kind !== 'unanswered' && r.kind !== 'entry') {
        log(`session ${sessionId.slice(0, 8)} call ${c.n} is still not recorded: ${r.detail}`)
        break
      }
      record = await store.updateCall(sessionId, c.n, { status: 'recorded', outcome: r.kind === 'entry' ? r.outcome : 'UNANSWERED' })
    }
    const now = await chain.now()
    while (now <= BigInt(record.deadline)) {
      const ready = readyCalls(record)
      const due = ready > 0 && (ready >= record.batchSize || now >= BigInt(record.expiresAt) || record.settled + ready === record.maxCalls)
      if (!due) break
      const to = record.settled + Math.min(ready, record.batchSize)
      const st = await attestor.sessionStatement({ sessionId, to })
      if (!st.ok) {
        log(`session ${sessionId.slice(0, 8)} statement to ${to} refused: ${st.detail}`)
        return store.update(sessionId, { error: `statement: ${st.detail}` })
      }
      const tx = await chain.settleBatch({
        sessionId,
        to,
        requestHashes: st.signed.requestHashes,
        ticket: st.signed.ticket,
        seed: ZERO_HASH,
        entries: st.signed.entries,
        statement: st.signed.signature,
      })
      if (!tx.ok) {
        log(`session ${sessionId.slice(0, 8)} settle_batch to ${to} failed: ${tx.error}`)
        return store.update(sessionId, { error: `settle_batch: ${tx.error}` })
      }
      const paid = st.signed.entries.filter((e) => e.result === RESULT_DELIVERED).length
      log(`session ${sessionId.slice(0, 8)} calls ${record.settled + 1}-${to} settled (${paid} paid) in ${tx.txHash}`)
      record = await store.put({
        ...record,
        settled: to,
        status: to === record.maxCalls ? 'closed' : record.status,
        batches: [...record.batches, { from: record.settled, to, paid, txHash: tx.txHash, at: new Date().toISOString() }],
        error: undefined,
      })
      if (record.status === 'closed') return record
    }
    if (record.status === 'open' && now > BigInt(record.deadline)) {
      const tx = await chain.closeSession(sessionId)
      if (!tx.ok) {
        log(`session ${sessionId.slice(0, 8)} close_session failed: ${tx.error}`)
        return store.update(sessionId, { error: `close_session: ${tx.error}` })
      }
      log(`session ${sessionId.slice(0, 8)} closed after its deadline in ${tx.txHash}`)
      record = await store.update(sessionId, { status: 'closed', closeTx: tx.txHash, error: undefined })
    }
    return record
  }

  const app = new Hono()
  // Errors as JSON (the dashboard shows `error`), never Hono's plain-text 500.
  app.onError((e, c) => {
    log(`${c.req.method} ${c.req.path} failed: ${e.message}`)
    return c.json({ error: e.message.split('\n')[0] }, 500)
  })

  const paid = async (c: Context) => {
    const sidParam = (c.req.param('serviceId') ?? '').toLowerCase()
    const svc = services.get(sidParam)
    if (!svc) return c.json({ error: `unknown service ${sidParam}` }, 404)
    const url = new URL(c.req.url)
    const prefix = `/s/${c.req.param('serviceId')}`
    const target = (url.pathname.slice(prefix.length) || '/') + url.search
    const method = c.req.method.toUpperCase()
    const body = new Uint8Array(await c.req.raw.clone().arrayBuffer())
    const req: Req = { method, target, headers: c.req.raw.headers, body, rh: requestHash(svc.serviceId, method, target, body) }

    const mpp = /^payment /i.test(c.req.header('authorization') ?? '')
    const x402 = c.req.header('payment-signature') ?? c.req.header('x-payment')
    // Admission control: refuse new payers (no credential yet) while proving is saturated, so no one
    // holds money for a call that would only wait out its window. Paid credentials are always served.
    if (saturated() && !mpp && !x402) {
      return c.json({ error: 'busy: other calls are being proved; retry in a few seconds' }, 503, { 'Retry-After': '5' })
    }
    if (x402 && !mpp) return payX402(c, svc, req, x402)

    // A `fermata` credential's call is marked in flight before the method submits its hold (and,
    // for a sponsored hold, before the gateway first records it); see inFlight.
    const payMpp = async () => {
      const r = await offers(svc, req.rh, await sessionViewFor(svc, c.req.raw.headers))(c.req.raw)
      if (r.status === 402) return paymentRequired(svc, req.rh, c.req.url, r.challenge)

      const credential = Credential.fromRequest(c.req.raw)
      if (credential.challenge.method !== 'fermata') return r.withReceipt(await unprotected(svc, req))
      if (credential.challenge.intent === 'session') {
        const payload = credential.payload as { action: 'open' | 'call'; sessionId: string; n?: number; ticket: string }
        // For an opening, the receipt's reference is its transaction.
        const reference = Receipt.fromResponse(r.withReceipt(new Response(null))).reference
        const { response, record, call } = await sessionCall(svc, req, payload, payload.action === 'open' ? reference : undefined)
        return withSessionReceipt(r.withReceipt(response), record, call)
      }

      // The hold transaction: the receipt's reference (for a sponsored hold, known only now).
      const holdTx = Receipt.fromResponse(r.withReceipt(new Response(null))).reference
      const payload = credential.payload as { type: string }
      const callId = (credential.challenge.request as { callId: Hex }).callId
      const { response, record } = await fulfil(svc, req, { callId, holdTx, paidWith: 'mpp', sponsored: payload.type === 'transaction' })
      return withFermataReceipt(r.withReceipt(response), record)
    }
    const callId = mpp ? fermataCallOf(c.req.raw) : undefined
    return callId ? inFlightDuring(callId, payMpp) : payMpp()
  }
  app.all('/s/:serviceId', paid)
  app.all('/s/:serviceId/*', paid)

  app.get('/services', (c) =>
    c.json(
      [...services.values()].map((s) =>
        plain({
          serviceId: s.serviceId,
          endpoint: `/s/${s.serviceId}`,
          examplePath: s.examplePath ?? null,
          summary: s.summary ?? null,
          upstream: s.upstream,
          price: s.price,
          token: s.token,
          settlementWindow: s.window,
          verifier: s.verifier,
          predicateHash: s.predicateHash,
          escrow: chain.escrow,
          network: deps.config.network,
          sessions: sessions ? { contract: chain.sessionContract, batchSize: sessions.batchSize, maxCalls: sessions.maxCalls, maxDuration: sessions.maxDurationSeconds } : null,
          pay: {
            mpp: ['fermata', ...(sessions ? ['fermata session'] : []), ...(s.unprotected && chargeHandler ? ['stellar (unprotected)'] : [])],
            x402: [...(deps.x402?.fermata ? ['fermata'] : []), ...(exactRequirements(s) ? ['exact (unprotected)'] : [])],
          },
          unprotected: s.unprotected ?? null,
        }),
      ),
    ),
  )

  // The index the read API serves from, refreshed at most every 2 s, so dashboards polling
  // /events cost one small getEvents per refresh, not one per viewer.
  let indexedAt = 0
  const freshEvents = async (): Promise<readonly IndexedEvent[]> => {
    if (!deps.indexer) return []
    if (Date.now() - indexedAt > 2_000) {
      indexedAt = Date.now()
      await deps.indexer.poll().catch((e) => log(`indexer: ${(e as Error).message}`))
    }
    return deps.indexer.events
  }

  // Only services whose verdicts this gateway's attestor signs are ranked: a service registered with
  // its own key as verifier could "release" calls with no proof at all.
  app.get('/scores', async (c) => {
    const all = aggregateScores(await freshEvents())
    const scores = all
      .filter((s) => s.verifier === signerKey.toLowerCase())
      .map((s) => {
        const svc = services.get(s.serviceId)
        return { ...s, known: !!svc, upstream: svc?.upstream ?? null, summary: svc?.summary ?? null, fewCalls: s.settled < 20 }
      })
    return c.json(
      plain({
        escrow: chain.escrow,
        network: deps.config.network,
        indexedTo: deps.indexer?.latestLedger ?? null,
        gaps: deps.indexer?.gaps ?? [],
        verifier: signerKey,
        method: 'Wilson 95 % lower bound of released / (released + proven failures), from service_registered, held, released, refunded and timed_out events only; timeouts are shown but not ranked',
        caveats: [
          'Only calls paid through Fermata count.',
          `Only services settled by this attestor (${signerKey}) are ranked; ${all.length - scores.length} other service(s) on this escrow are not.`,
          'Timeouts are shown but not ranked: anyone can hold a call and never present it.',
          'A vendor could pay itself to inflate its score; distinct agents are shown for that reason.',
          'Events older than the index (see gaps) are not counted.',
        ],
        scores,
      }),
    )
  })

  app.get('/calls', async (c) => c.json(await store.list()))
  app.get('/calls/:callId', async (c) => {
    const record = await store.get(c.req.param('callId')).catch(() => undefined)
    return record ? c.json(record) : c.json({ error: 'unknown call' }, 404)
  })
  app.get('/proofs/:callId', async (c) => {
    const id = c.req.param('callId').replace(/\.tlsn$/, '').replace(/^0x/, '').toLowerCase()
    const bytes = /^[0-9a-f]{64}$/.test(id) ? await attestor.presentation(id) : undefined
    if (!bytes) return c.json({ error: 'no presentation for this call' }, 404)
    return new Response(Buffer.from(bytes), { headers: { 'content-type': 'application/octet-stream', 'content-disposition': `attachment; filename="${id}.tlsn"` } })
  })
  // Inputs for an independent offline re-verification. Neither needs trusting: the caller checks a
  // predicate's sha256 against the service's on-chain predicate hash, and the CA only lets the
  // verifier accept the demo vendors' certificates (real vendors chain to Mozilla's roots).
  app.get('/ca.pem', (c) => {
    const ca = deps.verifierFiles?.caPath
    return ca && existsSync(ca) ? c.body(readFileSync(ca, 'utf8'), 200, { 'content-type': 'application/x-pem-file' }) : c.json({ error: 'no vendor CA here' }, 404)
  })
  app.get('/predicates/:hash', (c) => {
    const want = c.req.param('hash').toLowerCase().replace(/\.json$/, '').replace(/^0x/, '')
    if (!/^[0-9a-f]{64}$/.test(want)) return c.json({ error: 'predicate hash: 64 hex characters' }, 400)
    for (const dir of deps.verifierFiles?.predicateDirs ?? []) {
      if (!existsSync(dir)) continue
      for (const name of readdirSync(dir).filter((n) => n.endsWith('.json'))) {
        const bytes = readFileSync(path.join(dir, name))
        if (predicateHash(bytes) === want) return c.body(bytes.toString('utf8'), 200, { 'content-type': 'application/json' })
      }
    }
    return c.json({ error: 'no predicate with this hash' }, 404)
  })

  app.get('/info', (c) =>
    c.json({
      network: deps.config.network,
      networkPassphrase: chain.networkPassphrase,
      escrow: chain.escrow,
      sessionContract: chain.sessionContract ?? null,
      explorer: deps.config.explorer ?? null,
      services: services.size,
      verifier: signerKey,
      indexer: deps.indexer ? { latestLedger: deps.indexer.latestLedger, events: deps.indexer.events.length, gaps: deps.indexer.gaps } : null,
    }),
  )

  /** The newest `limit` (default 200) call events from ledger `since`, oldest first, with their token transfers. */
  app.get('/events', async (c) => {
    const since = Number(c.req.query('since') ?? 0) || 0
    const limit = Math.min(Math.max(Number(c.req.query('limit') ?? 200) || 200, 1), 1000)
    const events = (await freshEvents()).filter((e) => e.ledger >= since && ['held', 'released', 'refunded', 'timed_out'].includes(e.name)).slice(-limit)
    return c.json(events.map((e) => eventToJson(e)))
  })

  const tokenOf = (serviceId: Hex) => services.get(serviceId)?.token

  if (sessions) {
    let sessionsIndexedAt = 0
    const freshSessionEvents = async (): Promise<readonly IndexedEvent[]> => {
      if (!sessions.indexer) return []
      if (Date.now() - sessionsIndexedAt > 2_000) {
        sessionsIndexedAt = Date.now()
        await sessions.indexer.poll().catch((e) => log(`session indexer: ${(e as Error).message}`))
      }
      return sessions.indexer.events
    }
    const sessionOpts = async () => ({
      tokenOf,
      payoutOf: (serviceId: Hex) => services.get(serviceId)?.payout,
      treasury: await chain.treasury().catch(() => undefined),
    })

    app.get('/sessions', async (c) => c.json(await sessions.store.list()))
    app.get('/sessions/:sessionId', async (c) => {
      const record = await sessions.store.get(c.req.param('sessionId')).catch(() => undefined)
      return record ? c.json(record) : c.json({ error: 'unknown session' }, 404)
    })
    /** An accountant's view of one session: its events and transfers checked against each other and the gateway's record. */
    app.get('/sessions/:sessionId/reconcile', async (c) => {
      const id = c.req.param('sessionId').replace(/^0x/, '').toLowerCase()
      if (!/^[0-9a-f]{64}$/.test(id)) return c.json({ error: 'session id: 64 hex characters' }, 400)
      const record = await sessions.store.get(id)
      const r = reconcileSession(await freshSessionEvents(), id, chain.sessionContract!, await sessionOpts())
      if (r.status === 'unknown' && !record) return c.json({ error: 'unknown session' }, 404)
      const recordMatches = !record || (record.settled === r.settled && (record.status === 'closed') === (r.status === 'closed'))
      return c.json(plain({ ...r, record: record ? { status: record.status, settled: record.settled, batches: record.batches.length } : null, recordMatches, ok: r.ok && recordMatches }))
    })
    // Before `/reconcile/:callId`, which would take `sessions` for a call id.
    /** Every indexed session, and per token the contract's balance against the open sessions' deposits. */
    app.get('/reconcile/sessions', async (c) => {
      const events = await freshSessionEvents()
      const tokens = [...new Set(events.filter((e) => e.name === 'transfer').map((e) => (e as { token: string }).token))]
      const onchain: Record<string, bigint> = {}
      for (const t of tokens) onchain[t] = await chain.balance(t, chain.sessionContract!)
      const complete = (sessions.indexer?.gaps.length ?? 1) === 0
      const r = reconcileSessions(events, chain.sessionContract!, complete ? onchain : {}, await sessionOpts())
      return c.json(plain({ ...r, complete, note: complete ? null : 'the index does not start at the session contract’s deployment, so balances are not compared' }))
    })
  }


  /** An accountant's view of one call: its escrow events and token transfers, checked against each other. */
  app.get('/reconcile/:callId', async (c) => {
    const id = c.req.param('callId').replace(/^0x/, '').toLowerCase()
    if (!/^[0-9a-f]{64}$/.test(id)) return c.json({ error: 'call id: 64 hex characters' }, 400)
    const record = await store.get(id)
    const r = reconcileCall(await freshEvents(), id, chain.escrow, { tokenOf })
    if (r.status === 'unknown' && !record) return c.json({ error: 'unknown call' }, 404)
    // The gateway's record must agree with the chain.
    const expected: Record<string, string> = { released: 'released', refunded: 'refunded', 'timed-out': 'timed_out' }
    const recordOk = !record || !(record.status in expected) || expected[record.status] === r.status
    return c.json(plain({ ...r, record: record ? { status: record.status, holdTx: record.holdTx ?? null, settleTx: record.settleTx ?? record.timeoutTx ?? null } : null, recordMatches: recordOk, ok: r.ok && recordOk }))
  })

  /** The whole escrow: every indexed call, and per token the balance against the open holds and the chain. */
  app.get('/reconcile', async (c) => {
    const events = await freshEvents()
    const tokens = [...new Set(events.filter((e) => e.name === 'transfer').map((e) => (e as { token: string }).token))]
    const onchain: Record<string, bigint> = {}
    for (const t of tokens) onchain[t] = await chain.balance(t, chain.escrow)
    const complete = (deps.indexer?.gaps.length ?? 1) === 0 && events.some((e) => e.name === 'treasury_updated')
    const r = reconcileEscrow(events, chain.escrow, complete ? onchain : {}, { tokenOf })
    return c.json(plain({ ...r, complete, note: complete ? null : 'the index does not start at the escrow’s deployment, so balances are not compared' }))
  })

  /** Re-verify a call's proof offline (attestor, no key) and compare every hash with the chain. */
  app.post('/proofs/:callId/verify', async (c) => {
    const record = await store.get(c.req.param('callId').replace(/^0x/, '').toLowerCase()).catch(() => undefined)
    if (!record) return c.json({ error: 'unknown call' }, 404)
    const onchainSvc = await chain.service(record.serviceId)
    if (!onchainSvc) return c.json({ error: 'service not registered' }, 404)
    const re = await attestor.reverify({ callId: record.callId, serviceId: record.serviceId, predicateHash: onchainSvc.predicateHash })
    if ('error' in re) return c.json(re, 422)
    const hold = await chain.hold(record.callId)
    const events = await freshEvents()
    const final = events.find((e) => (e.name === 'released' || e.name === 'refunded') && e.callId === record.callId) as
      | { name: 'released' | 'refunded'; presentationHash: Hex }
      | undefined
    const onchain = {
      requestHash: hold?.requestHash ?? null,
      originHash: onchainSvc.originHash,
      notaryKeyHash: onchainSvc.notaryKeyHash,
      predicateHash: onchainSvc.predicateHash,
      presentationHash: final?.presentationHash ?? null,
      outcome: final ? (final.name === 'released' ? 'DELIVERED' : 'FAILED') : null,
    }
    const same = (a: unknown, b: unknown) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase()
    const checks = [
      { name: 'presentationHash', recomputed: re.presentationHash, onchain: onchain.presentationHash, ok: same(re.presentationHash, onchain.presentationHash) },
      { name: 'requestHash', recomputed: re.requestHash, onchain: onchain.requestHash, ok: same(re.requestHash, onchain.requestHash) },
      { name: 'originHash', recomputed: re.originHash, onchain: onchain.originHash, ok: same(re.originHash, onchain.originHash) },
      { name: 'notaryKeyHash', recomputed: re.notaryKeyHash, onchain: onchain.notaryKeyHash, ok: same(re.notaryKeyHash, onchain.notaryKeyHash) },
      { name: 'predicateHash', recomputed: re.predicateHash, onchain: onchain.predicateHash, ok: same(re.predicateHash, onchain.predicateHash) },
      { name: 'outcome', recomputed: re.outcome, onchain: onchain.outcome, ok: re.outcome === onchain.outcome },
      { name: 'callId header', recomputed: re.callHeader ?? null, onchain: record.callId, ok: re.callHeaderMatches },
    ]
    return c.json(plain({ callId: record.callId, ok: checks.every((k) => k.ok), checks, transcript: { request: re.request, response: re.response }, notaryKey: re.notaryKey, sessionTime: re.sessionTime }))
  })

  if (deps.dashboardDir && existsSync(deps.dashboardDir)) {
    app.get('/', (c) => c.redirect('/dashboard/'))
    app.get('/dashboard', (c) => c.redirect('/dashboard/'))
    app.use('/dashboard/*', serveStatic({ root: deps.dashboardDir, rewriteRequestPath: (p) => p.replace(/^\/dashboard/, '') }))
  }

  app.get('/llms.txt', (c) =>
    c.text(
      [
        '# Fermata gateway (Stellar)',
        'Paid API proxy. Pay with the `fermata` MPP method or the `fermata` x402 scheme (escrowed: released only on a TLSNotary proof of delivery), or with Stellar MPP Charge or x402 `exact` (unprotected, where offered).',
        ...[...services.values()].map((s) => `- ${s.summary ?? 'service'}: ANY /s/${s.serviceId}${s.examplePath ?? '/'}`),
        'GET /services, GET /calls/:callId, GET /reconcile/:callId, GET /proofs/:callId (re-verify offline with `fermata-attest verify --offline`).',
      ].join('\n'),
    ),
  )
  discovery(app as never, mppx as never, {
    routes: [...services.values()].map((s) => ({
      handler: offers(s, ZERO_HASH) as never,
      method: 'GET',
      path: `/s/${s.serviceId}${(s.examplePath ?? '/').split('?')[0]}`,
      summary: s.summary ?? 'Paid call (fermata: escrowed, pay on proof)',
    })),
    serviceInfo: { name: 'fermata-stellar-gateway', description: 'Pay on proof: escrowed machine payments on Stellar, released on TLSNotary evidence' } as never,
  } as never)

  /**
   * One sweep: retry pending settlements inside the window; claim_timeout after it. Sweeps never
   * overlap: a caller that arrives mid-sweep shares it.
   */
  let sweeping: Promise<string[]> | undefined
  function sweep(): Promise<string[]> {
    sweeping ??= sweepOnce().finally(() => {
      sweeping = undefined
    })
    return sweeping
  }

  async function sweepOnce() {
    const now = await chain.now()
    const done: string[] = []
    if (sessions) {
      for (const { sessionId, status } of await sessions.store.list()) {
        if (status !== 'closed') await settleSession(sessionId)
      }
    }
    for (const { callId } of await store.list()) {
      // Read each record again when its turn comes: the list is a snapshot, and a request may have
      // moved the call on since. Calls a request is still handling are left to it.
      const record = await store.get(callId)
      if (!record || FINAL.includes(record.status) || inFlight.has(callId)) continue
      const hold = await chain.hold(record.callId)
      if (inFlight.has(callId)) continue
      if (!hold) {
        // A sponsored hold that never landed: its authorization expires within minutes.
        if (record.status === 'holding' && Date.now() - Date.parse(record.createdAt) > 15 * 60_000) {
          await store.update(record.callId, { status: 'closed', error: record.error ?? 'the hold never landed' })
        }
        continue
      }
      if (hold.status !== HoldStatus.Held) {
        // Finalised by someone else (anyone may settle a signed verdict or claim a timeout).
        const status = hold.status === HoldStatus.Released ? 'released' : hold.status === HoldStatus.Refunded ? 'refunded' : 'timed-out'
        await store.update(record.callId, { status, error: `finalised on-chain by another transaction (escrow status ${hold.status})` })
        continue
      }
      if (record.status === 'holding') {
        // It landed although its submission's outcome was lost, and nothing was proved for it.
        await store.update(record.callId, { status: 'awaiting-timeout', agent: hold.agent, deadline: hold.deadline.toString() })
      }
      if (now <= hold.deadline) {
        if (record.status === 'settle-pending') await settleVerdict(record)
        continue
      }
      const result = await chain.claimTimeout(record.callId)
      if (result.ok) {
        log(`call ${record.callId.slice(0, 8)} timed out: agent refunded in ${result.txHash}`)
        await store.update(record.callId, { status: 'timed-out', timeoutTx: result.txHash })
        done.push(record.callId)
      } else {
        log(`call ${record.callId.slice(0, 8)} claim_timeout failed: ${result.error}`)
      }
    }
    return done
  }

  return { app, services, sweep, mppx, settleSession }
}
