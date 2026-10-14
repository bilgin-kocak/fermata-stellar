// Stellar strkeys (`G…`, `C…`, `S…`) and raw hex, as `fermata-verdict`'s `keys` module reads them.
import { StrKey } from '@stellar/stellar-sdk'
import { Buffer } from 'buffer'
import { fromHex } from './hex.ts'

/** A 32-byte Ed25519 public key from a `G…` address or 64 hex characters. */
export function publicKeyBytes(key: string): Uint8Array {
  const k = key.trim()
  return k.startsWith('G') ? new Uint8Array(StrKey.decodeEd25519PublicKey(k)) : fromHex(k, 32)
}

/** A contract id from a `C…` address or 64 hex characters. */
export function contractIdBytes(contract: string): Uint8Array {
  const c = contract.trim()
  return c.startsWith('C') ? new Uint8Array(StrKey.decodeContract(c)) : fromHex(c, 32)
}

/** An Ed25519 seed from a Stellar secret (`S…`) or 64 hex characters. */
export function secretSeedBytes(secret: string): Uint8Array {
  const s = secret.trim()
  return s.startsWith('S') ? new Uint8Array(StrKey.decodeEd25519SecretSeed(s)) : fromHex(s, 32)
}

export function accountAddress(publicKey: Uint8Array): string {
  return StrKey.encodeEd25519PublicKey(Buffer.from(publicKey))
}

export function contractAddress(contractId: Uint8Array): string {
  return StrKey.encodeContract(Buffer.from(contractId))
}
