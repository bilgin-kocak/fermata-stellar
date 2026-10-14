// Sessions (docs/session-escrow.md, section 10): the bytes an agent's ticket key and a service's
// verifier sign, built exactly as the session contract (`contracts/session/src/messages.rs`) and
// `fermata-verdict` (`crates/fermata-verdict/src/session.rs`) build them, and checked against
// test-vectors/session-v1.json. Fixed-width fields, integers big-endian:
//
//   chain(0)     = session_id
//   chain(n)     = sha256(chain(n−1) ‖ request_hash of call n)
//   ticket(n)    = "FERMATA_STELLAR_TICKET_V1" ‖ network ‖ contract ‖ session_id ‖ n ‖ chain(n)     157 bytes
//   entry        = result (u32) ‖ presentation_hash ‖ response_hash                                 68 bytes
//   statement    = "FERMATA_STELLAR_BATCH_V1" ‖ network ‖ contract ‖ session_id ‖ service_id
//                  ‖ predicate_hash ‖ from ‖ to ‖ chain(to) ‖ seed ‖ sha256(entries)                288 bytes
//   call_id(n)   = sha256("FERMATA_STELLAR_SESSION_CALL_V1" ‖ contract ‖ session_id ‖ n)
//
// `network` is sha256 of the network passphrase and `contract` the session contract's 32-byte id.
// As for verdicts, 32-byte values are lower-case hex without a prefix (inputs take `0x` too).
import { sha256 } from '@noble/hashes/sha2.js'
import * as ed from '@noble/ed25519'
import { asBytes, concatBytes, fromHex, toHex, utf8, type Hex } from './hex.ts'
import { contractIdBytes, publicKeyBytes, secretSeedBytes } from './keys.ts'
import { networkId, type Domain } from './verdict.ts'

export const TICKET_TAG = 'FERMATA_STELLAR_TICKET_V1'
export const BATCH_TAG = 'FERMATA_STELLAR_BATCH_V1'
export const SESSION_CALL_TAG = 'FERMATA_STELLAR_SESSION_CALL_V1'
export const TICKET_LEN = TICKET_TAG.length + 32 * 3 + 4 + 32
export const ENTRY_LEN = 4 + 32 + 32
export const STATEMENT_LEN = BATCH_TAG.length + 32 * 5 + 4 + 4 + 32 * 3

/** One call's result in a batch: proved (DELIVERED, FAILED) or not (ANSWERED, UNANSWERED). */
export const SessionResult = { Delivered: 1, Failed: 2, Answered: 3, Unanswered: 4 } as const
export type SessionResult = (typeof SessionResult)[keyof typeof SessionResult]

const ZERO = '00'.repeat(32)

/** One call's entry. Proved results carry the presentation and response hashes; others zeros. */
export type SessionEntry = { result: number; presentation_hash: string; response_hash: string }

/** The verifier's account of calls `from + 1` through `to` of a session. */
export type BatchStatement = {
  session_id: string
  service_id: string
  predicate_hash: string
  from: number
  to: number
  /** chain(to). */
  chain: string
  /** The batch's revealed seed; 32 zero bytes when nothing is sampled (k = 1). */
  seed: string
  entries_hash: string
}

function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error(`not a u32: ${n}`)
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n)
  return out
}

/** A proved entry: DELIVERED or FAILED, with its presentation and response hashes. */
export function provedEntry(delivered: boolean, presentationHash: string, responseHash: string): SessionEntry {
  return {
    result: delivered ? SessionResult.Delivered : SessionResult.Failed,
    presentation_hash: toHex(fromHex(presentationHash, 32)),
    response_hash: toHex(fromHex(responseHash, 32)),
  }
}

/** An unproved entry: ANSWERED (the vendor answered) or UNANSWERED. */
export function unprovedEntry(answered: boolean): SessionEntry {
  return {
    result: answered ? SessionResult.Answered : SessionResult.Unanswered,
    presentation_hash: ZERO,
    response_hash: ZERO,
  }
}

/** chain(n) from chain(n−1) and the request hash of call n. */
export function chainNext(chain: string | Uint8Array, requestHash: string | Uint8Array): Hex {
  return toHex(sha256(concatBytes(asBytes(chain, 32), asBytes(requestHash, 32))))
}

/** Extends `chain` over the request hashes of the next calls, in order (chain(0) is the session id). */
export function extendChain(chain: string | Uint8Array, requestHashes: readonly (string | Uint8Array)[]): Hex {
  return requestHashes.reduce<Hex>((c, h) => chainNext(c, h), toHex(asBytes(chain, 32)))
}

/** The 157 bytes the agent's ticket key signs for call `n`; the contract's `ticket_message`. */
export function ticketMessage(domain: Domain, sessionId: string, n: number, chain: string): Uint8Array {
  return concatBytes(
    utf8(TICKET_TAG),
    networkId(domain.networkPassphrase),
    contractIdBytes(domain.contract),
    fromHex(sessionId, 32),
    u32be(n),
    fromHex(chain, 32),
  )
}

function seedOf(secret: string | Uint8Array): Uint8Array {
  return typeof secret === 'string' ? secretSeedBytes(secret) : asBytes(secret, 32)
}

function keyOf(publicKey: string | Uint8Array): Uint8Array {
  return typeof publicKey === 'string' ? publicKeyBytes(publicKey) : asBytes(publicKey, 32)
}

async function verifyStrict(publicKey: Uint8Array, message: Uint8Array, signature: string | Uint8Array): Promise<boolean> {
  try {
    return await ed.verifyAsync(asBytes(signature, 64), message, publicKey, { zip215: false })
  } catch {
    return false
  }
}

/** The ticket for call `n` (hex signature). `secret`: the ticket key as `S…`, hex or 32 bytes. */
export async function signTicket(
  secret: string | Uint8Array,
  domain: Domain,
  sessionId: string,
  n: number,
  chain: string,
): Promise<Hex> {
  return toHex(await ed.signAsync(ticketMessage(domain, sessionId, n, chain), seedOf(secret)))
}

/** Checks a ticket under the session's ticket key (`G…`, hex or 32 bytes), strictly (RFC 8032). */
export async function verifyTicket(
  publicKey: string | Uint8Array,
  domain: Domain,
  sessionId: string,
  n: number,
  chain: string,
  signature: string | Uint8Array,
): Promise<boolean> {
  return verifyStrict(keyOf(publicKey), ticketMessage(domain, sessionId, n, chain), signature)
}

/** result (u32 BE) ‖ presentation_hash ‖ response_hash: 68 bytes. */
export function entryBytes(e: SessionEntry): Uint8Array {
  return concatBytes(u32be(e.result), fromHex(e.presentation_hash, 32), fromHex(e.response_hash, 32))
}

/** The entries concatenated in call order, as `settle_batch` takes them. */
export function entriesBytes(entries: readonly SessionEntry[]): Uint8Array {
  return concatBytes(...entries.map(entryBytes))
}

export function entriesHash(entries: readonly SessionEntry[]): Hex {
  return toHex(sha256(entriesBytes(entries)))
}

/** The 288 bytes the verifier signs for a batch; the contract's `statement_message`. */
export function statementMessage(domain: Domain, s: BatchStatement): Uint8Array {
  return concatBytes(
    utf8(BATCH_TAG),
    networkId(domain.networkPassphrase),
    contractIdBytes(domain.contract),
    fromHex(s.session_id, 32),
    fromHex(s.service_id, 32),
    fromHex(s.predicate_hash, 32),
    u32be(s.from),
    u32be(s.to),
    fromHex(s.chain, 32),
    fromHex(s.seed, 32),
    fromHex(s.entries_hash, 32),
  )
}

/** The verifier's signature (hex) over a batch statement. `secret`: `S…`, hex or 32 bytes. */
export async function signStatement(secret: string | Uint8Array, domain: Domain, s: BatchStatement): Promise<Hex> {
  return toHex(await ed.signAsync(statementMessage(domain, s), seedOf(secret)))
}

/** Checks a statement under the service's verifier key, strictly (RFC 8032). */
export async function verifyStatement(
  publicKey: string | Uint8Array,
  domain: Domain,
  s: BatchStatement,
  signature: string | Uint8Array,
): Promise<boolean> {
  return verifyStrict(keyOf(publicKey), statementMessage(domain, s), signature)
}

/** Whether call `n` is proved in a batch with this seed, sampling one call in `k` (always for k = 1). */
export function isSampled(seed: string | Uint8Array, n: number, k: number): boolean {
  if (k <= 1) return true
  const digest = sha256(concatBytes(asBytes(seed, 32), u32be(n)))
  return new DataView(digest.buffer, digest.byteOffset, 4).getUint32(0) % k === 0
}

/** The id call `n` of a session is proved against (its `X-Fermata-Call` header). */
export function sessionCallId(contract: string, sessionId: string, n: number): Hex {
  return toHex(sha256(concatBytes(utf8(SESSION_CALL_TAG), contractIdBytes(contract), fromHex(sessionId, 32), u32be(n))))
}

/**
 * The verifier's seed chain for `batches` batches: `seeds[0]` is the commitment that goes into
 * `open_session`, batch j reveals `seeds[j]`, and `sha256(seeds[j]) = seeds[j − 1]`.
 */
export function seedChain(secret: string | Uint8Array, batches: number): Hex[] {
  const seeds = [asBytes(secret, 32)]
  for (let i = 0; i < batches; i++) seeds.push(sha256(seeds[seeds.length - 1]!))
  return seeds.reverse().map(toHex)
}

/** Why an entry breaks the contract's rules for a call (sampled or not); undefined when it does not. */
export function entryProblem(e: SessionEntry, sampled: boolean): string | undefined {
  const presentation = toHex(fromHex(e.presentation_hash, 32))
  const blank = presentation === ZERO && toHex(fromHex(e.response_hash, 32)) === ZERO
  switch (e.result) {
    case SessionResult.Delivered:
    case SessionResult.Failed:
      if (!sampled) return 'a proved result on a call that is not sampled'
      return presentation === ZERO ? 'a proved result without a presentation hash' : undefined
    case SessionResult.Answered:
      if (sampled) return 'ANSWERED on a sampled call, which must be proved'
      return blank ? undefined : 'an unproved result with hashes'
    case SessionResult.Unanswered:
      return blank ? undefined : 'an unproved result with hashes'
    default:
      return `unknown result ${e.result}`
  }
}

/** `max(0, A + D − (k − 1) × F)`: the calls of a batch the vendor is paid for. */
export function paidCalls(entries: readonly SessionEntry[], k: number): number {
  const count = (r: number) => entries.filter((e) => e.result === r).length
  const paid = count(SessionResult.Answered) + count(SessionResult.Delivered) - (k - 1) * count(SessionResult.Failed)
  return Math.max(0, paid)
}
