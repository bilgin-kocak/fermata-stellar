// The `fermata` x402 scheme on Stellar: an escrowed payment, next to `exact`.
//
// Shape: the escrow flow of x402's `auth-capture` draft (specs/schemes/auth-capture, v1.1). The
// client authorizes a hold of the price in the escrow (`authorize`); after the resource runs, a
// verdict signed by the service's verifier pays the vendor (`capture`) or refunds the client
// (`void`); without a verdict inside the settlement window anyone can refund the client
// (`reclaim` = `claim_timeout`). Unlike `auth-capture` there is no partial capture and no refund
// after capture, and the verdict, not the resource server, decides between capture and void, so
// this is its own scheme name. The payload and the facilitator's checks follow `exact` on Stellar
// (specs/schemes/exact/scheme_exact_stellar.md): the client signs only the authorization entry and
// the facilitator submits the transaction and pays its fee.
//
// PaymentRequirements:
//   scheme "fermata", network (CAIP-2), asset = the service's token (`C…`), amount = its price,
//   payTo = the escrow (`C…`), maxTimeoutSeconds, and extra = { escrow, serviceId, requestHash,
//   callId, salt, expires, areFeesSponsored: true }.
// The call id binds the payment to one HTTP request: the resource server mints it as an HMAC of the
// escrow, service, request hash, salt and expiry under its secret, and accepts a payment only for
// a call id it minted, for this request, before it expires.
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import type { Network, PaymentRequirements } from '@x402/core/types'
import { concatBytes, fromHex, toHex, utf8, type Hex } from '../hex.ts'
import type { HoldTerms } from '../hold.ts'

export const FERMATA_SCHEME = 'fermata'
const CALL_TAG = 'FERMATA_X402_CALL_V1'

export type FermataExtra = {
  escrow: string
  serviceId: Hex
  requestHash: Hex
  callId: Hex
  salt: Hex
  /** Unix seconds after which the server refuses a payment for this call id. */
  expires: number
  areFeesSponsored: true
}

/** The call id the server mints for one request: HMAC-SHA256 under its secret. */
export function mintCallId(secretKey: string, x: { escrow: string; serviceId: Hex; requestHash: Hex; salt: Hex; expires: number }): Hex {
  const expires = new Uint8Array(8)
  new DataView(expires.buffer).setBigUint64(0, BigInt(x.expires))
  const message = concatBytes(utf8(CALL_TAG), utf8(x.escrow), fromHex(x.serviceId, 32), fromHex(x.requestHash, 32), fromHex(x.salt, 16), expires)
  return toHex(hmac(sha256, utf8(secretKey), message))
}

export type FermataOffer = {
  network: Network
  escrow: string
  token: string
  amount: bigint
  serviceId: Hex
  requestHash: Hex
}

/** Requirements for one request, with a fresh call id the server can recognise later. */
export function fermataRequirements(
  offer: FermataOffer,
  secretKey: string,
  opts: { maxTimeoutSeconds?: number; lifetimeSeconds?: number; now?: number } = {},
): PaymentRequirements {
  const salt = toHex(crypto.getRandomValues(new Uint8Array(16)))
  const expires = Math.floor((opts.now ?? Date.now()) / 1000) + (opts.lifetimeSeconds ?? 300)
  const serviceId = offer.serviceId.toLowerCase()
  const requestHash = offer.requestHash.toLowerCase()
  const callId = mintCallId(secretKey, { escrow: offer.escrow, serviceId, requestHash, salt, expires })
  const extra: FermataExtra = { escrow: offer.escrow, serviceId, requestHash, callId, salt, expires, areFeesSponsored: true }
  return {
    scheme: FERMATA_SCHEME,
    network: offer.network,
    asset: offer.token,
    amount: offer.amount.toString(),
    payTo: offer.escrow,
    maxTimeoutSeconds: opts.maxTimeoutSeconds ?? 60,
    extra,
  }
}

/** The extra fields of `fermata` requirements, or an error naming what is malformed. */
export function fermataExtra(r: PaymentRequirements): FermataExtra {
  const e = r.extra as Partial<FermataExtra>
  const hex = (v: unknown, n: number) => typeof v === 'string' && new RegExp(`^[0-9a-f]{${2 * n}}$`).test(v)
  if (
    typeof e?.escrow !== 'string' ||
    !hex(e.serviceId, 32) ||
    !hex(e.requestHash, 32) ||
    !hex(e.callId, 32) ||
    !hex(e.salt, 16) ||
    typeof e.expires !== 'number' ||
    !Number.isSafeInteger(e.expires)
  ) {
    throw new Error('malformed fermata requirements')
  }
  return e as FermataExtra
}

/**
 * The resource server's check that `accepted` are requirements it minted for this request (same
 * offer, a call id under its secret, not expired). Returns why not, or undefined.
 */
export function fermataRequirementsProblem(accepted: PaymentRequirements, offer: FermataOffer, secretKey: string, now = Date.now()): string | undefined {
  if (accepted.scheme !== FERMATA_SCHEME) return 'not a fermata payment'
  let e: FermataExtra
  try {
    e = fermataExtra(accepted)
  } catch (err) {
    return (err as Error).message
  }
  if (accepted.network !== offer.network) return 'another network'
  if (accepted.payTo !== offer.escrow || e.escrow !== offer.escrow) return 'another escrow'
  if (accepted.asset !== offer.token || accepted.amount !== offer.amount.toString()) return 'another token or price'
  if (e.serviceId !== offer.serviceId.toLowerCase()) return 'another service'
  if (e.requestHash !== offer.requestHash.toLowerCase()) return 'another request'
  if (e.expires < Math.floor(now / 1000)) return 'the payment requirements have expired'
  if (mintCallId(secretKey, e) !== e.callId) return 'a call id this server did not issue'
  return undefined
}

/** The hold `fermata` requirements ask for. */
export function holdTermsOf(r: PaymentRequirements): HoldTerms {
  const e = fermataExtra(r)
  return { escrow: e.escrow, callId: e.callId, serviceId: e.serviceId, requestHash: e.requestHash, token: r.asset, amount: BigInt(r.amount) }
}
