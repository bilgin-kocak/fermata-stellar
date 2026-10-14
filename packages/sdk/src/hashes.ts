// The hashes a vendor registers with a service and the attestor checks a presentation against.
//
// Ported from Fermata `packages/sdk/src/hashes.ts` @ d7cc642 (github.com/bilgin-kocak/fermata, MIT)
// with the definitions unchanged: the escrow stores these as opaque 32-byte values, so moving from
// Tempo to Stellar does not change them. Changed: @noble/hashes instead of viem, and hex output
// without the `0x` prefix (inputs take either form).
import { keccak_256 } from '@noble/hashes/sha3.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { asBytes, toHex, utf8, type Hex } from './hex.ts'

/**
 * Canonical HTTPS origin: `https://` + lower-case DNS host + `:port` unless 443. Rejects anything
 * that is not a bare origin (other schemes, paths, queries, user info). Same rules as the
 * attestor's `Origin::parse`.
 */
export function canonicalOrigin(origin: string): string {
  const m = /^https:\/\/([A-Za-z0-9.-]+)(?::(\d{1,5}))?\/?$/.exec(origin)
  if (!m) throw new Error(`not a bare https origin: ${origin}`)
  const host = m[1]!.toLowerCase()
  const port = m[2] === undefined ? 443 : Number(m[2])
  if (port < 1 || port > 65535) throw new Error(`bad port in ${origin}`)
  return port === 443 ? `https://${host}` : `https://${host}:${port}`
}

/** `originHash = keccak256(canonical origin)`: what `register_service` stores and the attestor checks. */
export function originHash(origin: string): Hex {
  return toHex(keccak_256(utf8(canonicalOrigin(origin))))
}

/** `notaryKeyHash = keccak256(33-byte compressed SEC1 notary verifying key)`. */
export function notaryKeyHash(compressedKey: string | Uint8Array): Hex {
  const key = asBytes(compressedKey)
  if (key.length !== 33) throw new Error(`expected a 33-byte compressed key, got ${key.length} bytes`)
  return toHex(keccak_256(key))
}

/** `predicateHash = sha256(predicate JSON bytes exactly as registered)`: never re-serialise. */
export function predicateHash(predicate: string | Uint8Array): Hex {
  return toHex(sha256(typeof predicate === 'string' ? utf8(predicate) : predicate))
}
