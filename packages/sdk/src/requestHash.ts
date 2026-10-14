// Ported from Fermata `packages/sdk/src/requestHash.ts` @ d7cc642 (github.com/bilgin-kocak/fermata,
// MIT) with the definition unchanged; @noble/hashes instead of viem, hex without `0x`.
import { sha256 } from '@noble/hashes/sha2.js'
import { asBytes, concatBytes, toHex, utf8, type Hex } from './hex.ts'

/**
 * requestHash = sha256(serviceId ‖ METHOD ‖ request-target ‖ sha256(body)), no separators.
 * - serviceId: 32 raw bytes
 * - METHOD: upper-case ASCII (unambiguous: methods are [A-Z]+ and targets start with "/")
 * - request-target: verbatim from the request line (origin-form, including "?query")
 * - body: the raw bytes as sent (no JSON canonicalisation in v1); empty body → sha256("")
 * Identical in the attestor, `fermata-verdict` and here.
 */
export function requestHash(
  serviceId: string | Uint8Array,
  method: string,
  target: string,
  body: string | Uint8Array = '',
): Hex {
  if (!target.startsWith('/')) throw new Error(`request-target must be origin-form ("/…"), got ${target}`)
  const bodyBytes = typeof body === 'string' ? utf8(body) : body
  return toHex(
    sha256(concatBytes(asBytes(serviceId, 32), utf8(method.toUpperCase()), utf8(target), sha256(bodyBytes))),
  )
}
