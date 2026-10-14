// Service ids on Stellar, and the agent-side check of who settles a service.
//
// On Tempo a service id was the owner's 20-byte address followed by a 12-byte label (Fermata
// `packages/sdk/src/serviceId.ts` @ d7cc642, MIT). A Stellar address does not fit next to a label
// in 32 bytes, so the escrow derives the id from the authenticated owner instead, exactly as
// `fermata-verdict`'s `service_id` does:
//
//   service_id = sha256("FERMATA_STELLAR_SERVICE_V1" ‖ XDR(ScVal::Address(owner)) ‖ label[12])
//
// `isTrustedService` is Fermata's, adapted to Ed25519 verifier keys.
import { sha256 } from '@noble/hashes/sha2.js'
import { Address } from '@stellar/stellar-sdk'
import { concatBytes, fromHex, toHex, utf8, type Hex } from './hex.ts'
import { contractIdBytes, publicKeyBytes } from './keys.ts'

export const SERVICE_TAG = 'FERMATA_STELLAR_SERVICE_V1'
export const LABEL_LEN = 12

/**
 * A 12-byte label: ASCII text of 1 to 12 bytes, right-padded with zeros, or `0x` followed by
 * 24 hex characters.
 */
export function label(text: string): Uint8Array {
  if (text.startsWith('0x')) return fromHex(text, LABEL_LEN)
  const bytes = utf8(text)
  if (bytes.length === 0 || bytes.length > LABEL_LEN || !/^[\x01-\x7f]+$/.test(text)) {
    throw new Error(`invalid label ${JSON.stringify(text)}: 1 to 12 bytes of ASCII`)
  }
  const out = new Uint8Array(LABEL_LEN)
  out.set(bytes)
  return out
}

/** The label as text when it is printable ASCII followed by zero padding. */
export function labelText(bytes: Uint8Array): string | undefined {
  const end = bytes.indexOf(0) === -1 ? bytes.length : bytes.indexOf(0)
  const text = bytes.subarray(0, end)
  const printable = text.length > 0 && text.every((b) => b >= 0x20 && b < 0x7f)
  const padded = bytes.subarray(end).every((b) => b === 0)
  return printable && padded ? new TextDecoder().decode(text) : undefined
}

/** XDR of `ScVal::Address(owner)` for a `G…` account or `C…` contract: what `owner.to_xdr(&env)` gives. */
export function ownerXdr(owner: string): Uint8Array {
  return new Uint8Array(new Address(owner.trim()).toScVal().toXDR())
}

/** The id `register_service` returns for `owner` and `label`. */
export function serviceId(owner: string, serviceLabel: string | Uint8Array): Hex {
  const l = typeof serviceLabel === 'string' ? label(serviceLabel) : serviceLabel
  if (l.length !== LABEL_LEN) throw new Error(`label must be ${LABEL_LEN} bytes`)
  return toHex(sha256(concatBytes(utf8(SERVICE_TAG), ownerXdr(owner), l)))
}

/**
 * Agent-side check before holding money: the service must be settled by a verifier the agent
 * trusts. A vendor that registers its own verifier could approve its own deliveries.
 * `verifier` is the service's 32-byte key (hex); trusted keys may be `G…` addresses or hex.
 */
export function isTrustedService(
  service: { verifier: string | Uint8Array; token?: string },
  opts: { trustedVerifiers: readonly string[]; expectedToken?: string },
): boolean {
  const key = toHex(typeof service.verifier === 'string' ? fromHex(service.verifier, 32) : service.verifier)
  const verifierOk = opts.trustedVerifiers.some((v) => toHex(publicKeyBytes(v)) === key)
  const tokenOk =
    opts.expectedToken === undefined ||
    (service.token !== undefined && toHex(contractIdBytes(service.token)) === toHex(contractIdBytes(opts.expectedToken)))
  return verifierOk && tokenOk
}
