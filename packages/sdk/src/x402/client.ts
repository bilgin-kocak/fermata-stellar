// Client side of the `fermata` x402 scheme: an `@x402/core` SchemeNetworkClient, so a standard x402
// client (`@x402/fetch`, `x402Client`) can pay with it. Before signing it makes the same checks as
// the MPP client (src/mpp/client.ts): trusted escrow, network, trusted verifier, the requirement's
// token and price against the registered service, and the agent's limits.
import type { Keypair } from '@stellar/stellar-sdk'
import type { PaymentPayloadContext, PaymentPayloadResult, PaymentRequirements, SchemeNetworkClient } from '@x402/core/types'
import { signSponsoredHold } from '../hold.ts'
import { networkPassphrase as passphraseOf } from '../network.ts'
import { EscrowReader } from '../reader.ts'
import { isTrustedService } from '../serviceId.ts'
import { rpcServer } from '../soroban.ts'
import { FERMATA_SCHEME, fermataExtra, holdTermsOf } from './scheme.ts'

export type FermataX402ClientOptions = {
  keypair: Keypair
  rpcUrl: string
  /** The network's passphrase; derived from the requirement's CAIP-2 network when omitted. */
  networkPassphrase?: string
  /** Verifier keys the agent accepts (`G…` or hex). */
  trustedVerifiers: readonly string[]
  /** Escrow deployments the agent accepts (`C…`). */
  escrows: readonly string[]
  maxAmount?: bigint
  /** Longest settlement window the agent accepts, in seconds (default 3600). */
  maxSettlementWindow?: number
}

export class FermataX402Client implements SchemeNetworkClient {
  readonly scheme = FERMATA_SCHEME
  private readonly readers = new Map<string, EscrowReader>()

  constructor(private readonly opts: FermataX402ClientOptions) {}

  async createPaymentPayload(x402Version: number, requirements: PaymentRequirements, context?: PaymentPayloadContext): Promise<PaymentPayloadResult> {
    const o = this.opts
    if (requirements.scheme !== FERMATA_SCHEME) throw new Error(`not a ${FERMATA_SCHEME} requirement`)
    const extra = fermataExtra(requirements)
    const terms = holdTermsOf(requirements)
    if (!o.escrows.includes(terms.escrow) || requirements.payTo !== terms.escrow) throw new Error(`untrusted escrow ${terms.escrow}`)
    const passphrase = o.networkPassphrase ?? passphraseOf(requirements.network)
    let reader = this.readers.get(terms.escrow)
    if (!reader) this.readers.set(terms.escrow, (reader = new EscrowReader(terms.escrow, o.rpcUrl, passphrase)))
    const service = await reader.service(terms.serviceId)
    if (!service) throw new Error(`unknown service ${terms.serviceId}`)
    if (!isTrustedService(service, { trustedVerifiers: o.trustedVerifiers, expectedToken: terms.token })) {
      throw new Error(`service ${terms.serviceId} is settled by ${service.verifier}, not a trusted verifier (or pays in another token)`)
    }
    if (terms.amount !== service.pricePerCall) throw new Error(`requirement amount ${terms.amount} ≠ registered price ${service.pricePerCall}`)
    if (o.maxAmount !== undefined && terms.amount > o.maxAmount) throw new Error(`price ${terms.amount} is above maxAmount ${o.maxAmount}`)
    if (context?.maxAmountPerPayment !== undefined && terms.amount > BigInt(context.maxAmountPerPayment)) {
      throw new Error(`price ${terms.amount} is above the client's spending cap`)
    }
    const maxWindow = o.maxSettlementWindow ?? 3600
    if (service.settlementWindow > maxWindow) {
      throw new Error(`service ${terms.serviceId} keeps an unsettled payment held for ${service.settlementWindow} s, above ${maxWindow} s`)
    }
    const untilExpiry = extra.expires - Math.floor(Date.now() / 1000)
    const validForSeconds = Math.min(requirements.maxTimeoutSeconds, untilExpiry)
    if (validForSeconds <= 0) throw new Error('the payment requirements have expired')
    const { transaction } = await signSponsoredHold({
      server: rpcServer(o.rpcUrl),
      networkPassphrase: passphrase,
      keypair: o.keypair,
      terms,
      validForSeconds,
    })
    return { x402Version, payload: { transaction } }
  }
}
