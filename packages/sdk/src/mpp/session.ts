// The `fermata` MPP method's `session` intent (docs/session-escrow.md, phase 1: every call proved).
//
// New in this repository. Where the `charge` intent holds the price of each call in the escrow
// (method.ts), a session holds one deposit in the session contract for many calls of a service:
// - the first paid call opens the session: the agent signs only the authorization of
//   `open_session`, which the server submits and pays for, as for a sponsored hold; with it comes
//   the agent's ticket for call 1;
// - every later call carries the agent's ticket for call n, an Ed25519 signature over chain(n), the
//   hash chain of the session's request hashes; no transaction per call;
// - the gateway proves each call (the attestor checks the ticket again) and settles them in
//   batches with the verifier's statements; after the session's deadline it closes it, and what is
//   left of the deposit returns to the agent.
// The credential shapes follow Stellar's MPP `channel` intent (an `action` per credential), and the
// session keys follow MPP's challenge binding: a challenge names the session contract, the service,
// this request's hash, the price and the gateway's limits, and, when the agent names its session in
// `X-Fermata-Session`, the call the gateway expects next and the chain before it.
import { Credential, Errors, Method, Store, z, type Receipt } from 'mppx'
import * as ed from '@noble/ed25519'
import type { Keypair } from '@stellar/stellar-sdk'
import type { ChannelsConfig } from '../channels.ts'
import { toHex, type Hex } from '../hex.ts'
import { EXPIRY_SKEW_LEDGERS, LEDGER_SECONDS } from '../hold.ts'
import { networkPassphrase as passphraseOf } from '../network.ts'
import { EscrowReader } from '../reader.ts'
import type { Relayer } from '../relayer.ts'
import { isTrustedService } from '../serviceId.ts'
import { chainNext, signTicket, verifyTicket } from '../session.ts'
import {
  SessionReader,
  checkSponsoredOpen,
  decodeOpenSession,
  signSponsoredOpen,
  simulateSponsoredOpen,
  submitSponsoredOpen,
  type OpenTerms,
} from '../sessionTx.ts'
import { rpcServer } from '../soroban.ts'
import type { Domain } from '../verdict.ts'

const ZERO = '00'.repeat(32)

export const fermataSessionMethod = Method.from({
  name: 'fermata',
  intent: 'session',
  schema: {
    request: z.object({
      /** Price per call in token base units (digits), the service's price. */
      amount: z.string(),
      /** The token contract (`C…`). */
      currency: z.string(),
      /** The escrow whose service this is (`C…`). */
      escrow: z.string(),
      /** The session contract (`C…`), which reads that escrow. */
      sessionContract: z.string(),
      /** CAIP-2 network id. */
      network: z.string(),
      serviceId: z.string(),
      requestHash: z.string(),
      /** The batch size B the gateway settles with: `open_session` must use it. */
      batchSize: z.number(),
      /** The most calls one session may hold a deposit for. */
      maxCalls: z.number(),
      /** The longest a session may take calls, in seconds from now. */
      maxDuration: z.number(),
      /** The server submits `open_session` and pays its fee. */
      sponsored: z.optional(z.boolean()),
      /** With `X-Fermata-Session`: the session the gateway knows, the call it expects and chain(next − 1). */
      sessionId: z.optional(z.string()),
      next: z.optional(z.number()),
      chain: z.optional(z.string()),
    }),
    credential: {
      payload: z.discriminatedUnion('action', [
        /** Call 1: `open_session` with the agent's signed authorization, and the ticket for call 1. */
        z.object({
          action: z.literal('open'),
          transaction: z.string().check(z.maxLength(16_384)),
          sessionId: z.string(),
          ticket: z.string(),
        }),
        /** Call n of an open session: the agent's ticket for it. */
        z.object({ action: z.literal('call'), sessionId: z.string(), n: z.number(), ticket: z.string() }),
      ]),
    },
  },
})

export type FermataSessionRequest = z.output<(typeof fermataSessionMethod)['schema']['request']>

/** The Payment-Receipt of a session call through a Fermata gateway: mppx's receipt plus the call. */
export type FermataSessionReceipt = Receipt.Receipt & {
  sessionId?: string
  n?: number
  /** chain(n), as the gateway recorded it. */
  chain?: string
  outcome?: 'DELIVERED' | 'FAILED' | 'UNANSWERED' | null
  presentationHash?: string | null
}

const fail = (reason: string): never => {
  throw new Errors.VerificationFailedError({ reason })
}
const reason = (e: unknown) => (e instanceof Error ? e.message : String(e))
const same = (a: string, b: string) => a.toLowerCase().replace(/^0x/, '') === b.toLowerCase().replace(/^0x/, '')

// ----------------------------------------------------------------------------------- server

/** What the gateway knows about a session it took calls for. */
export type SessionView = {
  serviceId: Hex
  agent: string
  ticketKey: Hex
  maxCalls: number
  expiresAt: bigint
  /** The next call number the gateway takes. */
  next: number
  /** chain(next − 1): the session id before the first call. */
  chain: Hex
  open: boolean
}

/** The terms of a session the server opened, for the gateway's record. */
export type OpenedSession = OpenTerms & { agent: string }

export type FermataSessionServerOptions = {
  rpcUrl: string
  network: string
  networkPassphrase?: string
  escrow: string
  sessionContract: string
  /** The mppx HMAC secret of the server using this method. */
  secretKey: string
  /** Replay store: each opening and each call number is claimed once. Default: in memory. */
  store?: Store.AtomicStore
  channels?: ChannelsConfig
  relayer?: Relayer
  /** The longest an agent's signed authorization may stay valid, in seconds. Default 300. */
  maxAuthorizationSeconds?: number
  /** The gateway's view of a session (undefined for one it does not know). */
  lookup: (sessionId: Hex) => Promise<SessionView | undefined>
  /** Called with an opening's terms just before it is submitted, so the gateway records it first. */
  onOpen?: (opened: OpenedSession) => Promise<void> | void
}

/**
 * Server side of the `session` intent. `validate` accepts an `open` credential only when its
 * `open_session` is for this route's service and token, k = 1, the gateway's batch size, at most
 * its calls and duration, with a deposit of exactly calls × price, signed by the agent as a
 * sponsored hold is (checkSponsoredOpen), with a ticket for call 1 over this request, and when it
 * simulates moving exactly the deposit; and a `call` credential only for the next call of a session
 * the gateway took calls for, before its expiry, with a ticket over this request. `broadcast`
 * claims the opening or the call number once and submits the opening.
 */
export function fermataSessionServer(opts: FermataSessionServerOptions): Method.Server<typeof fermataSessionMethod> {
  const { escrow, sessionContract, network, store = Store.memory() } = opts
  const passphrase = opts.networkPassphrase ?? passphraseOf(network)
  const server = rpcServer(opts.rpcUrl)
  const sponsoring = !!(opts.channels || opts.relayer)
  const sponsors = opts.relayer ? [opts.relayer.address] : []
  const domain: Domain = { networkPassphrase: passphrase, contract: sessionContract }
  const ledgerNow = async () => BigInt((await server.getLatestLedger()).closeTime)

  /** The opening's terms, checked against this challenge and the server's limits. */
  async function checkOpen(payload: { transaction: string; sessionId: string; ticket: string }, c: FermataSessionRequest, expires?: string) {
    let args: ReturnType<typeof decodeOpenSession>
    try {
      args = decodeOpenSession(payload.transaction, passphrase)
    } catch (e) {
      return fail(reason(e))
    }
    if (args.contract !== sessionContract) fail('open_session calls another contract')
    if (!same(args.sessionId, payload.sessionId)) fail('the credential names another session id')
    if (!same(args.serviceId, c.serviceId)) fail('the session is for another service')
    if (args.sampleK !== 1 || !same(args.seed, ZERO)) fail('this gateway proves every call (k = 1, no seed)')
    if (args.batchSize !== c.batchSize) fail(`the batch size must be ${c.batchSize}`)
    if (args.maxCalls < 1 || args.maxCalls > c.maxCalls) fail(`a session holds 1 to ${c.maxCalls} calls`)
    const now = await ledgerNow()
    if (args.expiresAt <= now || args.expiresAt > now + BigInt(c.maxDuration)) {
      fail(`the session must expire within ${c.maxDuration} s of the chain's time ${now}`)
    }
    const terms: OpenTerms = { ...args, token: c.currency, deposit: BigInt(c.amount) * BigInt(args.maxCalls) }
    const latest = (await server.getLatestLedger()).sequence
    const untilExpiry = expires ? Math.floor((Date.parse(expires) - Date.now()) / 1000) : Number.POSITIVE_INFINITY
    if (untilExpiry <= 0) fail('the challenge has expired')
    const seconds = Math.min(untilExpiry, opts.maxAuthorizationSeconds ?? 300)
    let open: ReturnType<typeof checkSponsoredOpen>
    try {
      open = checkSponsoredOpen({
        transaction: payload.transaction,
        networkPassphrase: passphrase,
        terms,
        latestLedger: latest,
        maxLedger: latest + Math.ceil(seconds / LEDGER_SECONDS) + EXPIRY_SKEW_LEDGERS,
        sponsors,
      })
    } catch (e) {
      return fail(`the signed open_session was refused: ${reason(e)}`)
    }
    const chain1 = chainNext(terms.sessionId, c.requestHash)
    if (!(await verifyTicket(terms.ticketKey, domain, terms.sessionId, 1, chain1, payload.ticket))) {
      fail('the ticket for call 1 does not cover this request')
    }
    return { open, terms }
  }

  return Method.toServer(fermataSessionMethod, {
    request: ({ request }) => ({ ...request, sponsored: sponsoring }),
    stableBinding: (r) => ({
      amount: r.amount,
      currency: r.currency,
      escrow: r.escrow,
      sessionContract: r.sessionContract,
      network: r.network,
      serviceId: r.serviceId.toLowerCase(),
      requestHash: r.requestHash.toLowerCase(),
      batchSize: r.batchSize,
      maxCalls: r.maxCalls,
      maxDuration: r.maxDuration,
    }),
    async validate({ credential, request }) {
      const c = credential.challenge.request
      if (c.escrow !== escrow) fail('challenge names another escrow')
      if (c.sessionContract !== sessionContract) fail('challenge names another session contract')
      if (c.network !== network) fail('challenge names another network')
      const payload = credential.payload
      let details: Record<string, unknown>
      if (payload.action === 'open') {
        if (!sponsoring) fail('this server does not submit session openings')
        const { open, terms } = await checkOpen(payload, c, credential.challenge.expires)
        await simulateSponsoredOpen({ server, networkPassphrase: passphrase, open, terms }).catch((e) =>
          fail(`the signed open_session does not simulate: ${reason(e)}`),
        )
        details = { sessionId: terms.sessionId, n: 1, agent: open.agent, sponsored: true }
      } else {
        const view = await opts.lookup(payload.sessionId.toLowerCase())
        if (!view || !view.open) return fail('no open session with this id at this gateway')
        if (!same(view.serviceId, c.serviceId)) fail('the session is for another service')
        if (payload.n !== view.next) fail(`call ${payload.n} is not the next call of the session (${view.next})`)
        if (payload.n > view.maxCalls) fail('the session has no calls left')
        if ((await ledgerNow()) >= view.expiresAt) fail('the session has expired')
        const chain = chainNext(view.chain, c.requestHash)
        if (!(await verifyTicket(view.ticketKey, domain, payload.sessionId, payload.n, chain, payload.ticket))) {
          fail(`the ticket for call ${payload.n} does not cover this request`)
        }
        details = { sessionId: payload.sessionId.toLowerCase(), n: payload.n, agent: view.agent }
      }
      return {
        challenge: credential.challenge,
        credential,
        details,
        intent: 'session',
        method: 'fermata',
        request: request as never,
        source: credential.source,
      }
    },
    async broadcast({ credential }) {
      const payload = credential.payload
      const sessionId = payload.sessionId.toLowerCase()
      const expires = Date.parse(credential.challenge.expires ?? '') || Date.now() + 3_600_000
      const key = payload.action === 'open' ? `fermata:session:${sessionId}` : `fermata:session:${sessionId}:${payload.n}`
      if (!(await Store.tryClaim(store as never, key, expires))) fail('this credential was already used')
      let reference = `${sessionId}:${payload.action === 'open' ? 1 : payload.n}`
      if (payload.action === 'open') {
        // Settlement checks again: it must not rely on validate having run.
        const { open, terms } = await checkOpen(payload, credential.challenge.request, credential.challenge.expires)
        await opts.onOpen?.({ ...terms, agent: open.agent })
        const landed = await submitSponsoredOpen({
          server,
          networkPassphrase: passphrase,
          open,
          terms,
          relayer: opts.relayer,
          channels: opts.channels,
        }).catch((e) => fail(`open_session was not submitted: ${reason(e)}`))
        reference = landed.hash
      }
      return { method: 'fermata', reference, status: 'success', timestamp: new Date().toISOString() }
    },
  })
}

// ----------------------------------------------------------------------------------- client

type AgentSession = {
  sessionContract: string
  serviceId: Hex
  sessionId: Hex
  ticketSeed: Uint8Array
  maxCalls: number
  expiresAt: bigint
  /** chains[n] = chain(n); chains[0] is the session id. */
  chains: Hex[]
  /** The next call number. */
  next: number
}

/**
 * The agent's sessions, one per (session contract, service). Send `sessionId(serviceId)` as the
 * `X-Fermata-Session` header so the gateway's challenge says which call it expects next.
 */
export class FermataSessions {
  readonly byKey = new Map<string, AgentSession>()

  /** The session the agent uses for a service, if it has one. */
  sessionId(serviceId: string): Hex | undefined {
    for (const s of this.byKey.values()) if (same(s.serviceId, serviceId)) return s.sessionId
    return undefined
  }

  /** How many calls of the current session for a service were made. */
  calls(serviceId: string): number {
    for (const s of this.byKey.values()) if (same(s.serviceId, serviceId)) return s.next - 1
    return 0
  }
}

export type FermataSessionClientOptions = {
  keypair: Keypair
  rpcUrl: string
  network: string
  networkPassphrase?: string
  /** Verifier keys the agent accepts (`G…` or hex). */
  trustedVerifiers: readonly string[]
  /** Escrow deployments the agent accepts (`C…`). */
  escrows: readonly string[]
  /** Session contracts the agent accepts (`C…`); each must read one of `escrows`. */
  sessionContracts: readonly string[]
  /** Calls per session the agent deposits for (default 20; never more than the gateway takes). */
  callsPerSession?: number
  /** How long a session takes calls, in seconds (default 600; never more than the gateway allows). */
  sessionSeconds?: number
  /** Highest deposit for one session, in base units. Default: no cap. */
  maxDeposit?: bigint
  /** Highest price per call, in base units. Default: no cap. */
  maxAmount?: bigint
  /** Longest settlement window the agent accepts, in seconds (default 3600). */
  maxSettlementWindow?: number
  /** How long the signed authorization of `open_session` stays valid, in seconds (default 120). */
  authorizationSeconds?: number
  /** Where the agent's sessions are kept (to read the session id for `X-Fermata-Session`). */
  sessions?: FermataSessions
  /** Called when a session is opened (signed for the server to submit). Errors it throws are ignored. */
  onSession?: (s: { sessionId: Hex; serviceId: Hex; sessionContract: string; maxCalls: number; deposit: bigint; expiresAt: bigint }) => void
}

/**
 * Pays `fermata` session challenges: opens a session on the first call to a service (the gateway
 * submits it), then signs one ticket per call. Before opening it checks, as the `charge` client does,
 * the escrow, the network, the service's verifier, token and price, and its own limits; and that
 * the session contract reads that escrow. A session that the gateway's view contradicts, that is
 * full or about to expire is left (its rest returns to the agent after its deadline) and a new one
 * is opened.
 *
 * What it cannot check, as for holds: that a challenge belongs to the URL being fetched. Pay only
 * challenges from gateways you trust.
 */
export function fermataSession(opts: FermataSessionClientOptions): Method.Client<typeof fermataSessionMethod> {
  const passphrase = opts.networkPassphrase ?? passphraseOf(opts.network)
  const server = rpcServer(opts.rpcUrl)
  const sessions = opts.sessions ?? new FermataSessions()
  const escrowOf = new Map<string, string>()

  async function checkTerms(r: FermataSessionRequest) {
    if (!opts.escrows.includes(r.escrow)) throw new Error(`untrusted escrow ${r.escrow}`)
    if (!opts.sessionContracts.includes(r.sessionContract)) throw new Error(`untrusted session contract ${r.sessionContract}`)
    if (r.network !== opts.network) throw new Error(`challenge is for ${r.network}, the agent pays on ${opts.network}`)
    let reads = escrowOf.get(r.sessionContract)
    if (!reads) escrowOf.set(r.sessionContract, (reads = await new SessionReader(r.sessionContract, opts.rpcUrl, passphrase).escrow()))
    if (reads !== r.escrow) throw new Error(`session contract ${r.sessionContract} reads ${reads}, not ${r.escrow}`)
    const service = await new EscrowReader(r.escrow, opts.rpcUrl, passphrase).service(r.serviceId)
    if (!service) throw new Error(`unknown service ${r.serviceId}`)
    if (!isTrustedService(service, { trustedVerifiers: opts.trustedVerifiers, expectedToken: r.currency })) {
      throw new Error(`service ${r.serviceId} is settled by ${service.verifier}, not a trusted verifier (or pays in another token)`)
    }
    const amount = BigInt(r.amount)
    if (amount !== service.pricePerCall) throw new Error(`challenged amount ${amount} ≠ registered price ${service.pricePerCall}`)
    if (opts.maxAmount !== undefined && amount > opts.maxAmount) throw new Error(`price ${amount} is above maxAmount ${opts.maxAmount}`)
    if (service.settlementWindow > (opts.maxSettlementWindow ?? 3600)) {
      throw new Error(`service ${r.serviceId} keeps a session's deposit ${service.settlementWindow} s past its expiry, above maxSettlementWindow`)
    }
    return { service, amount }
  }

  return Method.toClient(fermataSessionMethod, {
    async createCredential({ challenge }) {
      const r = challenge.request
      const key = `${r.sessionContract}:${r.serviceId.toLowerCase()}`
      const domain: Domain = { networkPassphrase: passphrase, contract: r.sessionContract }
      const rh = r.requestHash.toLowerCase()
      let s = sessions.byKey.get(key)

      // The gateway's view of this session: continue from it when it agrees with the agent's own.
      if (s && r.sessionId && same(r.sessionId, s.sessionId) && r.next !== undefined && r.chain !== undefined) {
        const mine = s.chains[r.next - 1]
        if (r.next <= s.next && mine !== undefined && same(mine, r.chain)) {
          s.next = r.next
          s.chains = s.chains.slice(0, r.next)
        } else {
          s = undefined
        }
      }
      const now = BigInt((await server.getLatestLedger()).closeTime)
      if (s && s.next <= s.maxCalls && now + 15n < s.expiresAt) {
        const n = s.next
        const chain = chainNext(s.chains[n - 1]!, rh)
        const ticket = await signTicket(s.ticketSeed, domain, s.sessionId, n, chain)
        s.chains[n] = chain
        s.next = n + 1
        return serialize(challenge, { action: 'call', sessionId: s.sessionId, n, ticket })
      }

      // A new session.
      const { service, amount } = await checkTerms(r)
      if (!r.sponsored) throw new Error('the gateway does not submit session openings; this client only opens sponsored sessions')
      const maxCalls = Math.min(opts.callsPerSession ?? 20, r.maxCalls)
      const deposit = amount * BigInt(maxCalls)
      if (opts.maxDeposit !== undefined && deposit > opts.maxDeposit) throw new Error(`deposit ${deposit} is above maxDeposit ${opts.maxDeposit}`)
      const seconds = Math.min(opts.sessionSeconds ?? 600, r.maxDuration - 30)
      if (seconds <= 30) throw new Error(`the gateway allows sessions of ${r.maxDuration} s, too short to use`)
      const ticketSeed = crypto.getRandomValues(new Uint8Array(32))
      const sessionId = toHex(crypto.getRandomValues(new Uint8Array(32)))
      const terms: OpenTerms = {
        contract: r.sessionContract,
        token: service.token,
        sessionId,
        serviceId: service.serviceId,
        maxCalls,
        ticketKey: toHex(await ed.getPublicKeyAsync(ticketSeed)),
        sampleK: 1,
        batchSize: r.batchSize,
        seed: ZERO,
        expiresAt: now + BigInt(seconds),
        deposit,
      }
      const untilExpiry = challenge.expires ? Math.floor((Date.parse(challenge.expires) - Date.now()) / 1000) : Number.POSITIVE_INFINITY
      const validForSeconds = Math.min(opts.authorizationSeconds ?? 120, untilExpiry)
      if (validForSeconds <= 0) throw new Error('the challenge has expired')
      const { transaction } = await signSponsoredOpen({ server, networkPassphrase: passphrase, keypair: opts.keypair, terms, validForSeconds })
      const chain1 = chainNext(sessionId, rh)
      const ticket = await signTicket(ticketSeed, domain, sessionId, 1, chain1)
      sessions.byKey.set(key, {
        sessionContract: r.sessionContract,
        serviceId: service.serviceId,
        sessionId,
        ticketSeed,
        maxCalls,
        expiresAt: terms.expiresAt,
        chains: [sessionId, chain1],
        next: 2,
      })
      try {
        opts.onSession?.({ sessionId, serviceId: service.serviceId, sessionContract: r.sessionContract, maxCalls, deposit, expiresAt: terms.expiresAt })
      } catch {
        // ignored: the credential must still reach the gateway
      }
      return serialize(challenge, { action: 'open', transaction, sessionId, ticket })
    },
  })
}

function serialize(challenge: unknown, payload: Record<string, unknown>): string {
  return Credential.serialize({ challenge, payload } as never)
}
