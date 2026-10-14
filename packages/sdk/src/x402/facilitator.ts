// Facilitator side of the `fermata` x402 scheme: an `@x402/core` SchemeNetworkFacilitator. It runs
// inside the gateway (OpenZeppelin's hosted x402 facilitator accepts only `exact`), and it can also
// be registered in an `x402Facilitator` served on its own. `verify` checks the agent's signed hold
// and simulates it; `settle` checks it again and submits it, through OpenZeppelin's Channels service
// when configured (it pays the fee) or from the relayer account. Settling the hold is x402's
// `authorize`; paying the vendor or refunding the agent is the escrow's `settle` on a verdict,
// after the resource has run, and is the gateway's job.
import type {
  Network,
  PaymentPayload,
  PaymentRequirements,
  SchemeNetworkFacilitator,
  SettleResponse,
  VerifyResponse,
} from '@x402/core/types'
import type { ChannelsConfig } from '../channels.ts'
import { EXPIRY_SKEW_LEDGERS, LEDGER_SECONDS, checkSponsoredHold, simulateSponsoredHold, submitSponsoredHold, type SponsoredHold } from '../hold.ts'
import { networkPassphrase as passphraseOf } from '../network.ts'
import type { Relayer } from '../relayer.ts'
import { rpcServer } from '../soroban.ts'
import { FERMATA_SCHEME, fermataExtra, holdTermsOf } from './scheme.ts'

export type FermataX402FacilitatorOptions = {
  rpcUrl: string
  /** The network served (CAIP-2). */
  network: Network
  networkPassphrase?: string
  /** Escrows whose holds this facilitator submits (`C…`). */
  escrows: readonly string[]
  channels?: ChannelsConfig
  relayer?: Relayer
}

const reasonOf = (e: unknown) => (e instanceof Error ? e.message : String(e))

export class FermataX402Facilitator implements SchemeNetworkFacilitator {
  readonly scheme = FERMATA_SCHEME
  readonly caipFamily = 'stellar:*'
  private readonly passphrase: string

  constructor(private readonly opts: FermataX402FacilitatorOptions) {
    if (!opts.channels && !opts.relayer) throw new Error('the fermata facilitator needs Channels or a relayer to submit holds')
    this.passphrase = opts.networkPassphrase ?? passphraseOf(opts.network)
  }

  getExtra(): Record<string, unknown> {
    return { areFeesSponsored: true }
  }

  getSigners(): string[] {
    return this.opts.relayer ? [this.opts.relayer.address] : []
  }

  /** Static checks of the payload against the requirements; returns the hold to submit. */
  private async check(payload: PaymentPayload, requirements: PaymentRequirements): Promise<SponsoredHold> {
    if (payload.x402Version !== 2) throw new Error('only x402 version 2 is supported')
    if (payload.accepted.scheme !== FERMATA_SCHEME || requirements.scheme !== FERMATA_SCHEME) throw new Error('not a fermata payment')
    if (payload.accepted.network !== requirements.network || requirements.network !== this.opts.network) throw new Error('another network')
    if (JSON.stringify(payload.accepted) !== JSON.stringify(requirements)) {
      // The resource server passes the requirements it accepted; anything else is a different payment.
      const a = holdTermsOf(payload.accepted)
      const b = holdTermsOf(requirements)
      if (a.callId !== b.callId || a.amount !== b.amount || a.token !== b.token || a.escrow !== b.escrow) throw new Error('the payload is for other requirements')
    }
    const extra = fermataExtra(requirements)
    const terms = holdTermsOf(requirements)
    if (!this.opts.escrows.includes(terms.escrow) || requirements.payTo !== terms.escrow) throw new Error(`escrow ${terms.escrow} is not served here`)
    const transaction = (payload.payload as { transaction?: unknown }).transaction
    if (typeof transaction !== 'string' || transaction.length > 16_384) throw new Error('the payload carries no transaction')
    const now = Math.floor(Date.now() / 1000)
    const seconds = Math.min(requirements.maxTimeoutSeconds, extra.expires - now)
    if (seconds <= 0) throw new Error('the payment requirements have expired')
    const latest = (await rpcServer(this.opts.rpcUrl).getLatestLedger()).sequence
    return checkSponsoredHold({
      transaction,
      networkPassphrase: this.passphrase,
      terms,
      latestLedger: latest,
      maxLedger: latest + Math.ceil(seconds / LEDGER_SECONDS) + EXPIRY_SKEW_LEDGERS,
      sponsors: this.getSigners(),
    })
  }

  async verify(payload: PaymentPayload, requirements: PaymentRequirements): Promise<VerifyResponse> {
    try {
      const hold = await this.check(payload, requirements)
      await simulateSponsoredHold({ server: rpcServer(this.opts.rpcUrl), networkPassphrase: this.passphrase, hold, terms: holdTermsOf(requirements) })
      return { isValid: true, payer: hold.agent }
    } catch (e) {
      return { isValid: false, invalidReason: 'invalid_fermata_payload', invalidMessage: reasonOf(e) }
    }
  }

  async settle(payload: PaymentPayload, requirements: PaymentRequirements): Promise<SettleResponse> {
    try {
      // Settlement checks again: it must not rely on verify having run.
      const hold = await this.check(payload, requirements)
      const landed = await submitSponsoredHold({
        server: rpcServer(this.opts.rpcUrl),
        networkPassphrase: this.passphrase,
        hold,
        terms: holdTermsOf(requirements),
        relayer: this.opts.relayer,
        channels: this.opts.channels,
      })
      return { success: true, transaction: landed.hash, network: requirements.network, payer: hold.agent }
    } catch (e) {
      return { success: false, errorReason: 'fermata_hold_failed', errorMessage: reasonOf(e), transaction: '', network: requirements.network }
    }
  }
}
