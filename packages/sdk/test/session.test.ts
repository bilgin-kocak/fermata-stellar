// Golden-vector parity for sessions (test-vectors/session-v1.json): the SDK rebuilds every chain,
// call id, ticket and batch statement byte for byte like the session contract and
// `fermata-verdict`, reproduces every signature from the fixed seeds, samples the same calls and
// applies the same entry rules.
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import {
  ENTRY_LEN,
  NETWORK_PASSPHRASES,
  STATEMENT_LEN,
  SessionResult,
  TICKET_LEN,
  chainNext,
  entriesBytes,
  entriesHash,
  entryBytes,
  entryProblem,
  extendChain,
  isSampled,
  paidCalls,
  provedEntry,
  seedChain,
  sessionCallId,
  signStatement,
  signTicket,
  statementMessage,
  ticketMessage,
  toHex,
  unprovedEntry,
  verifyStatement,
  verifyTicket,
  type BatchStatement,
  type Domain,
  type SessionEntry,
} from '../src/index.ts'

const root = new URL('../../../', import.meta.url)
const doc = JSON.parse(readFileSync(new URL('test-vectors/session-v1.json', root), 'utf8'))
const domain: Domain = { networkPassphrase: doc.network_passphrase, contract: doc.contract }

type CallVector = { n: number; request_hash: string; chain: string; call_id: string; ticket_message: string; ticket_signature: string }
type BatchVector = {
  from: number
  to: number
  seed: string
  sampled: boolean[]
  entries: SessionEntry[]
  entries_hash: string
  statement: BatchStatement
  statement_message: string
  statement_signature: string
  paid_calls: number
}
type SessionVector = { name: string; session_id: string; sample_k: number; batch_size: number; seeds: string[]; calls: CallVector[]; batches: BatchVector[] }
const sessions = doc.sessions as SessionVector[]
const [plain, sampledSession] = sessions as [SessionVector, SessionVector]

describe('session-v1.json', () => {
  it('rebuilds every chain, call id and ticket, and reproduces every ticket signature', async () => {
    for (const s of sessions) {
      let chain = s.session_id
      for (const c of s.calls) {
        chain = chainNext(chain, c.request_hash)
        expect(chain, `${s.name} chain(${c.n})`).toBe(c.chain)
        expect(sessionCallId(doc.contract, s.session_id, c.n)).toBe(c.call_id)
        expect(sessionCallId(doc.contract_id, s.session_id, c.n)).toBe(c.call_id)
        const message = ticketMessage(domain, s.session_id, c.n, c.chain)
        expect(message.length).toBe(TICKET_LEN)
        expect(toHex(message), `${s.name} ticket(${c.n})`).toBe(c.ticket_message)
        expect(await signTicket(doc.ticket_key.seed, domain, s.session_id, c.n, c.chain)).toBe(c.ticket_signature)
        expect(await verifyTicket(doc.ticket_key.address, domain, s.session_id, c.n, c.chain, c.ticket_signature)).toBe(true)
      }
      expect(extendChain(s.session_id, s.calls.map((c) => c.request_hash))).toBe(s.calls.at(-1)!.chain)
    }
  })

  it('rebuilds every batch statement, reproduces its signature and counts the paid calls', async () => {
    for (const s of sessions) {
      for (const b of s.batches) {
        const label = `${s.name} ${b.from}..${b.to}`
        expect(entriesBytes(b.entries).length).toBe(ENTRY_LEN * (b.to - b.from))
        expect(entriesHash(b.entries), label).toBe(b.entries_hash)
        expect(b.statement.entries_hash).toBe(b.entries_hash)
        expect(b.statement.chain).toBe(s.calls[b.to - 1]!.chain)
        const message = statementMessage(domain, b.statement)
        expect(message.length).toBe(STATEMENT_LEN)
        expect(toHex(message), label).toBe(b.statement_message)
        expect(await signStatement(doc.verifier.seed, domain, b.statement)).toBe(b.statement_signature)
        expect(await verifyStatement(doc.verifier.address, domain, b.statement, b.statement_signature)).toBe(true)
        expect(paidCalls(b.entries, s.sample_k), label).toBe(b.paid_calls)
      }
    }
  })

  it('samples the same calls and accepts every recorded entry', () => {
    for (const s of sessions) {
      for (const b of s.batches) {
        b.entries.forEach((e, i) => {
          const n = b.from + 1 + i
          expect(isSampled(b.seed, n, s.sample_k), `${s.name} call ${n}`).toBe(b.sampled[i])
          expect(entryProblem(e, b.sampled[i]!), `${s.name} call ${n}`).toBeUndefined()
        })
      }
    }
  })

  it('reproduces the seed chain from its secret', () => {
    expect(plain.seeds).toEqual(['00'.repeat(32)])
    const secret = sampledSession.seeds.at(-1)!
    expect(seedChain(secret, sampledSession.seeds.length - 1)).toEqual(sampledSession.seeds)
    sampledSession.batches.forEach((b, j) => expect(b.seed).toBe(sampledSession.seeds[j + 1]))
  })

  it('a ticket does not verify for another key, session, call, chain or network', async () => {
    const c = plain.calls[0]!
    const id = plain.session_id
    const verify = (overrides: { key?: string; session?: string; n?: number; chain?: string; d?: Domain }) =>
      verifyTicket(
        overrides.key ?? doc.ticket_key.public_key,
        overrides.d ?? domain,
        overrides.session ?? id,
        overrides.n ?? c.n,
        overrides.chain ?? c.chain,
        c.ticket_signature,
      )
    expect(await verify({})).toBe(true)
    expect(await verify({ key: doc.verifier.public_key })).toBe(false)
    expect(await verify({ session: sampledSession.session_id })).toBe(false)
    expect(await verify({ n: 2 })).toBe(false)
    expect(await verify({ chain: plain.calls[1]!.chain })).toBe(false)
    expect(await verify({ d: { ...domain, networkPassphrase: NETWORK_PASSPHRASES.local } })).toBe(false)
    expect(await verify({ d: { ...domain, contract: '77'.repeat(32) } })).toBe(false)
  })

  it('every statement field is signed', async () => {
    const b = plain.batches[0]!
    const flip = (h: string) => (h.startsWith('0') ? '1' : '0') + h.slice(1)
    for (const f of ['session_id', 'service_id', 'predicate_hash', 'chain', 'seed', 'entries_hash'] as const) {
      const tampered = { ...b.statement, [f]: flip(b.statement[f]) }
      expect(await verifyStatement(doc.verifier.public_key, domain, tampered, b.statement_signature), f).toBe(false)
    }
    for (const tampered of [
      { ...b.statement, from: 1 },
      { ...b.statement, to: 4 },
    ]) {
      expect(await verifyStatement(doc.verifier.public_key, domain, tampered, b.statement_signature)).toBe(false)
    }
    expect(await verifyStatement(doc.ticket_key.public_key, domain, b.statement, b.statement_signature)).toBe(false)
  })
})

describe('the entry rules', () => {
  const p = '11'.repeat(32)
  const r = '22'.repeat(32)

  it('allows proved results only on sampled calls, and ANSWERED only on unsampled ones', () => {
    expect(entryProblem(provedEntry(true, p, r), true)).toBeUndefined()
    expect(entryProblem(provedEntry(false, p, '00'.repeat(32)), true)).toBeUndefined()
    expect(entryProblem(provedEntry(true, p, r), false)).toMatch(/not sampled/)
    expect(entryProblem(unprovedEntry(true), false)).toBeUndefined()
    expect(entryProblem(unprovedEntry(true), true)).toMatch(/must be proved/)
    // UNANSWERED is allowed on any call.
    expect(entryProblem(unprovedEntry(false), true)).toBeUndefined()
    expect(entryProblem(unprovedEntry(false), false)).toBeUndefined()
  })

  it('refuses hashes that do not match the result, and unknown results', () => {
    expect(entryProblem(provedEntry(true, '00'.repeat(32), r), true)).toMatch(/presentation/)
    expect(entryProblem({ ...unprovedEntry(false), response_hash: r }, true)).toMatch(/hashes/)
    expect(entryProblem({ ...unprovedEntry(true), presentation_hash: p }, false)).toMatch(/hashes/)
    expect(entryProblem({ ...provedEntry(true, p, r), result: 0 }, true)).toMatch(/unknown/)
    expect(entryProblem({ ...provedEntry(true, p, r), result: 5 }, true)).toMatch(/unknown/)
  })

  it('pays A + D − (k − 1) × F, never below zero', () => {
    const d = provedEntry(true, p, r)
    const f = provedEntry(false, p, r)
    const a = unprovedEntry(true)
    const u = unprovedEntry(false)
    expect(paidCalls([d, f, u], 1)).toBe(1)
    expect(paidCalls([a, a, a, d, f], 4)).toBe(1)
    expect(paidCalls([a, f, f], 4)).toBe(0)
    expect(SessionResult.Unanswered).toBe(4)
  })

  it('rejects malformed input', () => {
    expect(entryBytes(provedEntry(true, p, r)).length).toBe(ENTRY_LEN)
    expect(() => provedEntry(true, '11', r)).toThrow()
    expect(() => ticketMessage(domain, plain.session_id, -1, plain.calls[0]!.chain)).toThrow()
    expect(() => ticketMessage(domain, plain.session_id, 2 ** 32, plain.calls[0]!.chain)).toThrow()
    expect(() => chainNext('00', r)).toThrow()
  })
})
