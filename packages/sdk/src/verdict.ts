// The verdict and the exact bytes a verifier signs, as the escrow rebuilds them before calling the
// host's `ed25519_verify` (docs/PORTING_NOTES.md, section 3):
//
//   "FERMATA_STELLAR_VERDICT_V1" ‖ sha256(network passphrase) ‖ escrow contract id ‖ canonical(verdict)
//
// canonical(verdict) = call_id ‖ service_id ‖ request_hash ‖ predicate_hash ‖ outcome (u32 BE) ‖
// presentation_hash ‖ response_hash ‖ issued_at (u64 BE): 204 bytes, 294 with the domain.
//
// The `Verdict` fields are those of Fermata's EIP-712 verdict (`packages/sdk/src/verdict.ts` @
// d7cc642, MIT), in the same order. They use the snake_case names and plain hex of the attestor's
// JSON and of the contract, so a verdict from `POST /v1/attest` can be passed on as it is.
import { sha256 } from '@noble/hashes/sha2.js'
import * as ed from '@noble/ed25519'
import { Buffer } from 'buffer'
import type { Verdict as ContractVerdict } from './escrow/bindings.ts'
import { asBytes, concatBytes, fromHex, toHex, utf8, type Hex } from './hex.ts'
import { contractIdBytes, publicKeyBytes, secretSeedBytes } from './keys.ts'

export const VERDICT_TAG = 'FERMATA_STELLAR_VERDICT_V1'
export const CANONICAL_LEN = 6 * 32 + 4 + 8
export const MESSAGE_LEN = VERDICT_TAG.length + 32 + 32 + CANONICAL_LEN

/** Verdict outcomes, as stored in `Verdict.outcome` (0 is invalid). */
export const Outcome = { Delivered: 1, Failed: 2 } as const
export type Outcome = (typeof Outcome)[keyof typeof Outcome]

export const NETWORK_PASSPHRASES = {
  testnet: 'Test SDF Network ; September 2015',
  mainnet: 'Public Global Stellar Network ; September 2015',
  futurenet: 'Test SDF Future Network ; October 2022',
  local: 'Standalone Network ; February 2017',
} as const

/** The verifier's decision about one call. 32-byte values are hex, with or without `0x`. */
export type Verdict = {
  call_id: string
  service_id: string
  request_hash: string
  predicate_hash: string
  outcome: number
  presentation_hash: string
  response_hash: string
  /** Unix seconds. Signed, not checked on-chain. */
  issued_at: number | bigint | string
}

/** Where a verdict is valid: one network and one escrow contract (`C…` or its 32-byte id in hex). */
export type Domain = { networkPassphrase: string; contract: string }

/** sha256(network passphrase): Stellar's network id. */
export function networkId(networkPassphrase: string): Uint8Array {
  return sha256(utf8(networkPassphrase))
}

function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error(`not a u32: ${n}`)
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n)
  return out
}

function u64be(n: number | bigint | string): Uint8Array {
  const v = BigInt(n)
  if (v < 0n || v > 0xffffffffffffffffn) throw new Error(`not a u64: ${n}`)
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, v)
  return out
}

/** The eight fields concatenated in order, integers big-endian (204 bytes). */
export function canonicalVerdict(v: Verdict): Uint8Array {
  return concatBytes(
    fromHex(v.call_id, 32),
    fromHex(v.service_id, 32),
    fromHex(v.request_hash, 32),
    fromHex(v.predicate_hash, 32),
    u32be(v.outcome),
    fromHex(v.presentation_hash, 32),
    fromHex(v.response_hash, 32),
    u64be(v.issued_at),
  )
}

/** The 294 bytes a verifier signs for `verdict` on `domain`; the escrow's `verdict_message`. */
export function verdictMessage(domain: Domain, v: Verdict): Uint8Array {
  return concatBytes(
    utf8(VERDICT_TAG),
    networkId(domain.networkPassphrase),
    contractIdBytes(domain.contract),
    canonicalVerdict(v),
  )
}

/** Ed25519 signature (hex) over the verdict message. `secret`: an `S…` seed, hex or 32 bytes. */
export async function signVerdict(secret: string | Uint8Array, domain: Domain, v: Verdict): Promise<Hex> {
  const seed = typeof secret === 'string' ? secretSeedBytes(secret) : asBytes(secret, 32)
  return toHex(await ed.signAsync(verdictMessage(domain, v), seed))
}

/**
 * Checks a verdict signature before relaying it. Verification follows RFC 8032 (canonical
 * encodings, `S < L`), the stricter of @noble/ed25519's modes; the host's `verify_strict` also
 * rejects small-order keys. The escrow's check on `settle` is the one that counts.
 * `publicKey`: the service's verifier, as a `G…` address, hex or 32 bytes.
 */
export async function verifyVerdict(
  publicKey: string | Uint8Array,
  domain: Domain,
  v: Verdict,
  signature: string | Uint8Array,
): Promise<boolean> {
  const key = typeof publicKey === 'string' ? publicKeyBytes(publicKey) : asBytes(publicKey, 32)
  try {
    return await ed.verifyAsync(asBytes(signature, 64), verdictMessage(domain, v), key, { zip215: false })
  } catch {
    return false
  }
}

/** The verdict as the escrow client's `settle` takes it (32-byte values as Buffers, `issued_at` a bigint). */
export function toContractVerdict(v: Verdict): ContractVerdict {
  const b = (h: string) => Buffer.from(fromHex(h, 32))
  if (v.outcome !== Outcome.Delivered && v.outcome !== Outcome.Failed) {
    throw new Error(`invalid outcome ${v.outcome}`)
  }
  return {
    call_id: b(v.call_id),
    service_id: b(v.service_id),
    request_hash: b(v.request_hash),
    predicate_hash: b(v.predicate_hash),
    outcome: v.outcome,
    presentation_hash: b(v.presentation_hash),
    response_hash: b(v.response_hash),
    issued_at: BigInt(v.issued_at),
  }
}
