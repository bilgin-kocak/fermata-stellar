// Client side of the `fermata` MPP method on Stellar, for `mppx/client`.
//
// Ported from Fermata `packages/sdk/src/client.ts` @ d7cc642 (github.com/bilgin-kocak/fermata, MIT).
// Kept: the checks before any money moves (trusted escrow, network, trusted verifier, the challenged
// token and price against the registered service, the agent's price and window limits), one
// agent-submitted hold at a time, and the cache that answers a repeated challenge for the same call
// with the same hold. Changed for Stellar: no permit; the agent either signs only the authorization
// of `hold` for the server to submit (when the challenge says the server sponsors it), or submits
// the hold itself.
import { Credential, Method } from 'mppx'
import type { Keypair } from '@stellar/stellar-sdk'
import type { Hex } from '../hex.ts'
import { signSponsoredHold, submitOwnHold, type HoldTerms } from '../hold.ts'
import { networkPassphrase as passphraseOf } from '../network.ts'
import { EscrowReader } from '../reader.ts'
import { isTrustedService } from '../serviceId.ts'
import { rpcServer } from '../soroban.ts'
import { fermataMethod } from './method.ts'

export type FermataClientOptions = {
  /** The agent's key. */
  keypair: Keypair
  rpcUrl: string
  /** The CAIP-2 network the agent pays on; challenges for any other network are refused. */
  network: string
  networkPassphrase?: string
  /** Verifier keys the agent accepts (`G…` or hex). A service settled by anyone else is refused. */
  trustedVerifiers: readonly string[]
  /** Escrow deployments the agent accepts (`C…`). */
  escrows: readonly string[]
  /** Highest price per call the agent pays, in token base units. Default: no cap. */
  maxAmount?: bigint
  /**
   * Longest settlement window the agent accepts, in seconds (default 3600): when a call is never
   * settled, its money stays held that long before the timeout refund.
   */
  maxSettlementWindow?: number
  /** `sponsored` (the default, when the challenge offers it) or `direct` (the agent submits and pays the fee). */
  mode?: 'sponsored' | 'direct'
  /** How long a signed authorization stays valid, in seconds (default 120, and never past the challenge's expiry). */
  authorizationSeconds?: number
  /**
   * Called once the hold is signed or submitted, e.g. to keep the call id for `claim_timeout` should
   * the paid call then fail. Errors it throws are ignored.
   */
  onHold?: (hold: { callId: Hex; serviceId: Hex; escrow: string; amount: bigint; txHash?: Hex; sponsored: boolean }) => void
}

// One agent-submitted hold at a time per agent account: each spends the account's next sequence number.
const holdQueues = new Map<string, Promise<unknown>>()
function oneAtATime<T>(key: string, task: () => Promise<T>): Promise<T> {
  const run = (holdQueues.get(key) ?? Promise.resolve()).then(task, task)
  const settled = run.then(
    () => undefined,
    () => undefined,
  )
  holdQueues.set(key, settled)
  void settled.then(() => holdQueues.get(key) === settled && holdQueues.delete(key))
  return run
}

/**
 * Pays a `fermata` challenge by holding the price in the escrow. Before any money moves it checks
 * that the escrow and network are expected, that the service is settled by a trusted verifier in
 * the challenged token, that the challenged amount is the registered price, and that the price and
 * the settlement window are within the agent's limits.
 *
 * What it cannot check: a challenge is not bound to the URL being fetched, and its request hash is
 * not re-derived here. A server that relays a gateway's challenge can make the agent pay, at a
 * trusted service's registered price, for a request of the relay's choosing; and a trusted verifier
 * does not vouch for every service that names it. Pay only challenges from gateways you trust.
 */
export function fermata(opts: FermataClientOptions): Method.Client<typeof fermataMethod> {
  const passphrase = opts.networkPassphrase ?? passphraseOf(opts.network)
  const server = rpcServer(opts.rpcUrl)
  const readers = new Map<string, EscrowReader>()
  const readerFor = (escrow: string) => {
    let r = readers.get(escrow)
    if (!r) readers.set(escrow, (r = new EscrowReader(escrow, opts.rpcUrl, passphrase)))
    return r
  }
  // This agent's holds by call id. A gateway that challenges again with the same call id (its RPC
  // did not show the hold yet, or the paid retry was lost) gets the same hold back: a second hold
  // would fail with CallIdUsed and leave the first one to the timeout refund.
  const holds = new Map<string, { payload: { type: 'transaction'; transaction: string } | { type: 'hold'; txHash: string }; terms: string }>()

  return Method.toClient(fermataMethod, {
    async createCredential({ challenge }) {
      const r = challenge.request
      const callId = r.callId
      if (!callId || !/^[0-9a-f]{64}$/.test(callId)) throw new Error('fermata challenge carries no valid callId')
      if (!opts.escrows.includes(r.escrow)) throw new Error(`untrusted escrow ${r.escrow}`)
      if (r.network !== opts.network) throw new Error(`challenge is for ${r.network}, the agent pays on ${opts.network}`)
      const termsKey = JSON.stringify([r.escrow, r.serviceId.toLowerCase(), r.requestHash.toLowerCase(), r.amount, r.currency])

      const prior = holds.get(callId)
      if (prior) {
        if (prior.terms !== termsKey) throw new Error(`call ${callId} is already held for other terms`)
        return Credential.serialize({ challenge, payload: { ...prior.payload, callId } })
      }

      const service = await readerFor(r.escrow).service(r.serviceId)
      if (!service) throw new Error(`unknown service ${r.serviceId}`)
      if (!isTrustedService(service, { trustedVerifiers: opts.trustedVerifiers, expectedToken: r.currency })) {
        throw new Error(`service ${r.serviceId} is settled by ${service.verifier}, not a trusted verifier (or pays in another token)`)
      }
      const amount = BigInt(r.amount)
      if (amount !== service.pricePerCall) throw new Error(`challenged amount ${amount} ≠ registered price ${service.pricePerCall}`)
      if (opts.maxAmount !== undefined && amount > opts.maxAmount) throw new Error(`price ${amount} is above maxAmount ${opts.maxAmount}`)
      const maxWindow = opts.maxSettlementWindow ?? 3600
      if (service.settlementWindow > maxWindow) {
        throw new Error(
          `service ${r.serviceId} keeps an unsettled payment held for ${service.settlementWindow} s, above maxSettlementWindow (${maxWindow} s)`,
        )
      }
      const terms: HoldTerms = { escrow: r.escrow, callId, serviceId: service.serviceId, requestHash: r.requestHash.toLowerCase(), token: service.token, amount }

      let payload: { type: 'transaction'; transaction: string } | { type: 'hold'; txHash: string }
      if (r.sponsored && (opts.mode ?? 'sponsored') === 'sponsored') {
        const untilExpiry = challenge.expires ? Math.floor((Date.parse(challenge.expires) - Date.now()) / 1000) : Number.POSITIVE_INFINITY
        const validForSeconds = Math.min(opts.authorizationSeconds ?? 120, untilExpiry)
        if (validForSeconds <= 0) throw new Error('the challenge has expired')
        const { transaction } = await signSponsoredHold({ server, networkPassphrase: passphrase, keypair: opts.keypair, terms, validForSeconds })
        payload = { type: 'transaction', transaction }
      } else {
        const { hash } = await oneAtATime(opts.keypair.publicKey(), () =>
          submitOwnHold({ server, networkPassphrase: passphrase, keypair: opts.keypair, terms }),
        ).catch((e: Error) => {
          throw new Error(
            `hold for call ${callId} was sent but not confirmed (${e.message}). If it lands and the call is never settled, claim_timeout refunds it after the settlement window.`,
          )
        })
        payload = { type: 'hold', txHash: hash }
      }
      holds.set(callId, { payload, terms: termsKey })
      if (holds.size > 1000) holds.delete(holds.keys().next().value!)
      try {
        opts.onHold?.({
          callId,
          serviceId: terms.serviceId,
          escrow: r.escrow,
          amount,
          sponsored: payload.type === 'transaction',
          ...(payload.type === 'hold' ? { txHash: payload.txHash } : {}),
        })
      } catch {
        // ignored: the credential must still reach the gateway
      }
      return Credential.serialize({ challenge, payload: { ...payload, callId } })
    },
  })
}
