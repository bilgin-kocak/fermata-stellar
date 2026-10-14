// Server side of the `fermata` MPP method on Stellar.
//
// Ported from Fermata `packages/sdk/src/server.ts` @ d7cc642 (github.com/bilgin-kocak/fermata, MIT).
// Kept: the call id minted per challenge and echoed only from challenges this server signed; the
// stable binding; validation of the hold before anything is served; the call id claimed once in
// `broadcast`; every rejection a `VerificationFailedError` (HTTP 402). Changed for Stellar: a hold is
// read from its transaction's `held` event and from `get_hold`, and a `transaction` credential (the
// agent's signed authorization) is checked, simulated in enforce mode and submitted by this server,
// through OpenZeppelin Channels or a relayer account (src/hold.ts).
import { Challenge, Errors, Method, Store } from 'mppx'
import { rpc } from '@stellar/stellar-sdk'
import type { ChannelsConfig } from '../channels.ts'
import { eventually } from '../eventually.ts'
import { toHex } from '../hex.ts'
import {
  EXPIRY_SKEW_LEDGERS,
  LEDGER_SECONDS,
  checkHoldTransaction,
  checkSponsoredHold,
  simulateSponsoredHold,
  submitSponsoredHold,
  type HoldTerms,
} from '../hold.ts'
import { networkPassphrase as passphraseOf } from '../network.ts'
import { EscrowReader, HoldStatus } from '../reader.ts'
import type { Relayer } from '../relayer.ts'
import { rpcServer } from '../soroban.ts'
import { fermataMethod } from './method.ts'

const fail = (reason: string): never => {
  throw new Errors.VerificationFailedError({ reason })
}
const sameHex = (a: string, b: string) => a.toLowerCase().replace(/^0x/, '') === b.toLowerCase().replace(/^0x/, '')
const reason = (e: unknown) => (e instanceof Error ? e.message : String(e))

export type FermataServerOptions = {
  rpcUrl: string
  /** CAIP-2 network id. */
  network: string
  /** The network's passphrase; derived from `network` when omitted. */
  networkPassphrase?: string
  /** The escrow contract (`C…`). */
  escrow: string
  /** The mppx HMAC secret of the server using this method (the same `secretKey` as `Mppx.create`). */
  secretKey: string
  /**
   * Replay store: each call id is claimed once. Defaults to an in-memory store, which protects one
   * process only: when more than one instance serves the same escrow, pass a shared store.
   */
  store?: Store.AtomicStore
  /** Submit agents' signed holds through OpenZeppelin's Channels service (it pays the fees)… */
  channels?: ChannelsConfig
  /** …or from this account. With neither, only `hold` credentials (agent-submitted holds) are accepted. */
  relayer?: Relayer
  /** How long to look for a hold the RPC does not show yet (a node behind the agent's), in ms. Default 6000. */
  lagToleranceMs?: number
  /** The longest an agent's signed authorization may stay valid, in seconds. Default 300. */
  maxAuthorizationSeconds?: number
  /**
   * Called just before a sponsored hold is submitted, so the caller can record the call first: if
   * the submission's outcome is lost (a timeout) and the hold lands anyway, the record lets the
   * caller find it and have it refunded after the window.
   */
  onSponsoredHold?: (call: { callId: string; agent: string; serviceId: string; requestHash: string }) => Promise<void> | void
}

/**
 * Server side of the `fermata` method, for a gateway (or a vendor hosting the method itself).
 * - `request` mints a fresh call id per challenge and echoes it on the paid pass, but only from a
 *   challenge this server signed: call ids are public on-chain, so echoing any call id a caller
 *   names would let a stranger obtain a valid challenge for someone else's hold and redeem it first;
 * - `stableBinding` binds a credential to this route's service, request hash, price, token, escrow
 *   and network, but not to the per-challenge call id;
 * - `validate` accepts a `hold` credential only for a successful transaction on this escrow whose
 *   `held` event has this call id, service, request hash and amount, and whose hold is still open;
 *   and a `transaction` credential only if the agent's signed authorization is exactly this hold and
 *   its simulation moves only the price into the escrow;
 * - `broadcast` claims the call id once (replay protection), submits a `transaction` credential's
 *   hold, and returns the receipt with the hold's transaction hash.
 */
export function fermataServer(opts: FermataServerOptions): Method.Server<typeof fermataMethod> {
  const { escrow, network, secretKey, store = Store.memory() } = opts
  const passphrase = opts.networkPassphrase ?? passphraseOf(network)
  const server = rpcServer(opts.rpcUrl)
  const reader = new EscrowReader(escrow, opts.rpcUrl, passphrase)
  const tries = Math.max(1, Math.round((opts.lagToleranceMs ?? 6_000) / 500))
  const sponsoring = !!(opts.channels || opts.relayer)
  const sponsors = opts.relayer ? [opts.relayer.address] : []

  const termsOf = (r: { escrow: string; callId?: string; serviceId: string; requestHash: string; currency: string; amount: string }): HoldTerms => ({
    escrow: r.escrow,
    callId: r.callId ?? fail('challenge carries no callId'),
    serviceId: r.serviceId,
    requestHash: r.requestHash,
    token: r.currency,
    amount: BigInt(r.amount),
  })

  async function checkTransaction(transaction: string, terms: HoldTerms, expires: string | undefined) {
    const latest = (await server.getLatestLedger()).sequence
    const untilExpiry = expires ? Math.floor((Date.parse(expires) - Date.now()) / 1000) : Number.POSITIVE_INFINITY
    if (untilExpiry <= 0) fail('the challenge has expired')
    const seconds = Math.min(untilExpiry, opts.maxAuthorizationSeconds ?? 300)
    try {
      return checkSponsoredHold({
        transaction,
        networkPassphrase: passphrase,
        terms,
        latestLedger: latest,
        maxLedger: latest + Math.ceil(seconds / LEDGER_SECONDS) + EXPIRY_SKEW_LEDGERS,
        sponsors,
      })
    } catch (e) {
      return fail(`the signed hold was refused: ${reason(e)}`)
    }
  }

  return Method.toServer(fermataMethod, {
    request({ credential, request }) {
      const signedByUs = !!credential && Challenge.verify(credential.challenge, { secretKey })
      const echoed = signedByUs ? (credential.challenge.request as { callId?: string }).callId : undefined
      return { ...request, callId: echoed ?? toHex(crypto.getRandomValues(new Uint8Array(32))), sponsored: sponsoring }
    },
    stableBinding: (r) => ({
      amount: r.amount,
      currency: r.currency,
      escrow: r.escrow,
      network: r.network,
      serviceId: r.serviceId.toLowerCase(),
      requestHash: r.requestHash.toLowerCase(),
    }),
    async validate({ credential, request }) {
      const challenged = credential.challenge.request
      const terms = termsOf(challenged)
      const payload = credential.payload
      if (!sameHex(payload.callId, terms.callId)) fail('credential callId does not match the challenge')
      if (challenged.escrow !== escrow) fail('challenge names another escrow')
      if (challenged.network !== network) fail('challenge names another network')

      let details: Record<string, unknown>
      if (payload.type === 'transaction') {
        if (!sponsoring) fail('this server does not submit holds: submit the hold and send its hash')
        const hold = await checkTransaction(payload.transaction, terms, credential.challenge.expires)
        await simulateSponsoredHold({ server, networkPassphrase: passphrase, hold, terms }).catch((e) =>
          fail(`the signed hold does not simulate: ${reason(e)}`),
        )
        details = { callId: terms.callId, agent: hold.agent, sponsored: true }
      } else {
        const tx = await eventually(
          async () => {
            const r = await server.getTransaction(payload.txHash)
            if (r.status === rpc.Api.GetTransactionStatus.NOT_FOUND) throw new Error('not found')
            return r
          },
          undefined,
          tries,
        ).catch(() => fail(`hold transaction ${payload.txHash} not found`))
        if (tx.status !== rpc.Api.GetTransactionStatus.SUCCESS) return fail('hold transaction failed')
        let agent: string
        try {
          agent = checkHoldTransaction(tx, terms).agent
        } catch (e) {
          return fail(reason(e))
        }
        const hold = await eventually(() => reader.hold(terms.callId), (h) => h !== undefined, tries)
        if (hold?.status !== HoldStatus.Held) fail(`hold is no longer open (status ${hold?.status})`)
        const now = await reader.now()
        if (now > hold!.deadline) fail(`the hold's settlement window closed at ${hold!.deadline}: reclaim it with claim_timeout`)
        details = { callId: terms.callId, agent, holdTx: payload.txHash, deadline: hold!.deadline.toString() }
      }
      return {
        challenge: credential.challenge,
        credential,
        details,
        intent: 'charge',
        method: 'fermata',
        request: request as never,
        source: credential.source,
      }
    },
    async broadcast({ credential }) {
      const challenged = credential.challenge.request
      const terms = termsOf(challenged)
      const payload = credential.payload
      const expires = Date.parse(credential.challenge.expires ?? '') || Date.now() + 3_600_000
      if (!(await Store.tryClaim(store as never, `fermata:call:${terms.callId.toLowerCase()}`, expires))) {
        fail('callId already used')
      }
      let reference = payload.type === 'hold' ? payload.txHash : ''
      if (payload.type === 'transaction') {
        // Settlement checks again: it must not rely on validate having run.
        const hold = await checkTransaction(payload.transaction, terms, credential.challenge.expires)
        await opts.onSponsoredHold?.({ callId: terms.callId, agent: hold.agent, serviceId: terms.serviceId, requestHash: terms.requestHash })
        const landed = await submitSponsoredHold({
          server,
          networkPassphrase: passphrase,
          hold,
          terms,
          relayer: opts.relayer,
          channels: opts.channels,
        }).catch((e) => fail(`the hold was not submitted: ${reason(e)}`))
        reference = landed.hash
      }
      return { method: 'fermata', reference, status: 'success', timestamp: new Date().toISOString() }
    },
  })
}
