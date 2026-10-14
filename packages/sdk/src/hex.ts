import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'

/** Lower-case hex without a prefix: how the Stellar CLI, the attestor and this SDK write bytes. */
export type Hex = string

export function toHex(bytes: Uint8Array): Hex {
  return bytesToHex(bytes)
}

/** Parses hex with or without a `0x` prefix; `length` is the expected byte length. */
export function fromHex(hex: string, length?: number): Uint8Array {
  const digits = hex.trim().replace(/^0x/, '')
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(digits)) throw new Error(`invalid hex: ${hex}`)
  const bytes = hexToBytes(digits.toLowerCase())
  if (length !== undefined && bytes.length !== length) {
    throw new Error(`expected ${length} bytes, got ${bytes.length}`)
  }
  return bytes
}

/** Bytes from hex (with or without `0x`) or a byte array, checked against `length`. */
export function asBytes(value: string | Uint8Array, length?: number): Uint8Array {
  if (typeof value === 'string') return fromHex(value, length)
  if (length !== undefined && value.length !== length) {
    throw new Error(`expected ${length} bytes, got ${value.length}`)
  }
  return value
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s)
