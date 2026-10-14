// Reconciliation of sessions (contracts/session) on synthetic indexed events: an opening, batches,
// a session ended by its last batch and one closed after its deadline, and what breaks each check.
import { describe, expect, it } from 'vitest'
import { contractAddress, reconcileSession, reconcileSessions, type IndexedEvent } from '../src/index.ts'
import { A, agents, h, payout, token, treasury } from './fixtures.ts'

const contract = contractAddress(new Uint8Array(32).fill(0x5e))
const PRICE = 100_000n
const FEE = 500n
const opts = { tokenOf: () => token, payoutOf: () => payout, treasury }

let ledger = 100
let seq = 0
const pos = (tx: string) => {
  ledger++
  return { ledger, txHash: h(tx), id: `${String(ledger).padStart(10, '0')}-${String(seq++).padStart(10, '0')}` }
}
const transfer = (p: ReturnType<typeof pos>, from: string, to: string, amount: bigint, k: string): IndexedEvent => ({
  name: 'transfer',
  token,
  from,
  to,
  amount,
  ...p,
  id: `${p.id}${k}`,
})

/** A session of `maxCalls` calls, opened with its deposit. */
function open(sessionId: string, maxCalls: number, agent = agents[0]!): IndexedEvent[] {
  const p = pos(`open ${sessionId}`)
  return [
    { name: 'session_opened', sessionId, serviceId: A, agent, deposit: PRICE * BigInt(maxCalls), maxCalls, price: PRICE, sampleK: 1, batchSize: 4, deadline: 1_700_000_180n, ...p },
    transfer(p, agent, contract, PRICE * BigInt(maxCalls), 'a'),
  ]
}

/** A batch of calls from+1..to with `paid` of them paid; `rest` closes the session in the same transaction. */
function batch(sessionId: string, from: number, to: number, paid: number, rest?: bigint, agent = agents[0]!): IndexedEvent[] {
  const p = pos(`batch ${sessionId} ${from}`)
  const refund = BigInt(to - from - paid) * PRICE
  const out: IndexedEvent[] = [
    {
      name: 'batch_settled', sessionId, serviceId: A, from, to, delivered: paid, failed: to - from - paid, answered: 0, unanswered: 0, paid,
      payoutAmount: BigInt(paid) * (PRICE - FEE), fee: BigInt(paid) * FEE, refund, chain: h(`chain ${to}`), entriesHash: h(`entries ${to}`), ...p,
    },
  ]
  if (rest !== undefined) out.push({ name: 'session_closed', sessionId, serviceId: A, agent, refund: rest, ...p, id: `${p.id}z` })
  if (paid) out.push(transfer(p, contract, payout, BigInt(paid) * (PRICE - FEE), 'a'), transfer(p, contract, treasury, BigInt(paid) * FEE, 'b'))
  if (refund + (rest ?? 0n) > 0n) out.push(transfer(p, contract, agent, refund + (rest ?? 0n), 'c'))
  return out
}

function close(sessionId: string, refund: bigint, agent = agents[0]!): IndexedEvent[] {
  const p = pos(`close ${sessionId}`)
  return [{ name: 'session_closed', sessionId, serviceId: A, agent, refund, ...p }, ...(refund ? [transfer(p, contract, agent, refund, 'a')] : [])]
}

describe('reconcileSession', () => {
  it('an open session: the deposit in, two batches out, and what is left covers the calls not settled', () => {
    const id = h('s1')
    const events = [...open(id, 10), ...batch(id, 0, 4, 3), ...batch(id, 4, 6, 2)]
    const r = reconcileSession(events, id, contract, opts)
    expect(r).toMatchObject({ status: 'open', ok: true, settled: 6, paidCalls: 5, deposit: 1_000_000n })
    expect(r.paidOut).toBe(5n * (PRICE - FEE))
    expect(r.fees).toBe(5n * FEE)
    expect(r.refunded).toBe(PRICE)
    expect(r.remaining).toBe(4n * PRICE)
  })

  it('a session its last batch ends, and one closed after its deadline, are fully accounted for', () => {
    const a = h('s2')
    const ended = reconcileSession([...open(a, 6), ...batch(a, 0, 4, 4), ...batch(a, 4, 5, 0, PRICE)], a, contract, opts)
    expect(ended).toMatchObject({ status: 'closed', ok: true, settled: 5, remaining: 0n })
    const b = h('s3')
    const closed = reconcileSession([...open(b, 6), ...batch(b, 0, 2, 1), ...close(b, 4n * PRICE)], b, contract, opts)
    expect(closed).toMatchObject({ status: 'closed', ok: true, remaining: 0n })
    expect(closed.closed).toMatchObject({ refund: 4n * PRICE })
  })

  it('flags a batch that moved other amounts, a gap between batches and an opening that moved less', () => {
    const id = h('s4')
    const short = batch(id, 0, 4, 3).map((e) => (e.name === 'transfer' && e.to === payout ? { ...e, amount: 1n } : e))
    let r = reconcileSession([...open(id, 10), ...short], id, contract, opts)
    expect(r.ok).toBe(false)
    expect(r.checks.find((c) => !c.ok)?.name).toMatch(/moved exactly/)

    const gap = h('s5')
    r = reconcileSession([...open(gap, 10), ...batch(gap, 0, 2, 2), ...batch(gap, 3, 4, 1)], gap, contract, opts)
    expect(r.checks.find((c) => !c.ok)?.name).toMatch(/follows the previous one/)

    const less = h('s6')
    const opening = open(less, 10).map((e) => (e.name === 'transfer' ? { ...e, amount: 1n } : e))
    r = reconcileSession(opening, less, contract, opts)
    expect(r.checks.find((c) => !c.ok)?.name).toMatch(/opening moved the deposit/)
  })

  it('flags a transfer to someone else in a batch, and a session missing from the index', () => {
    const id = h('s7')
    const extra = [...batch(id, 0, 2, 1), transfer(pos(`batch ${id} 0`), contract, agents[1]!, 1n, 'x')]
    // The extra transfer sits in the batch's transaction.
    const sameTx = extra.map((e) => (e.name === 'transfer' && e.to === agents[1] ? { ...e, txHash: extra[0]!.txHash } : e))
    expect(reconcileSession([...open(id, 4), ...sameTx], id, contract, opts).ok).toBe(false)
    expect(reconcileSession([], h('nothing'), contract, opts)).toMatchObject({ status: 'unknown', ok: false })
  })
})

describe('reconcileSessions', () => {
  it("the contract's balance is what is left of the open sessions' deposits", () => {
    const [a, b] = [h('t1'), h('t2')]
    const events = [...open(a, 10), ...batch(a, 0, 4, 4), ...open(b, 4), ...batch(b, 0, 4, 2, 0n)]
    const r = reconcileSessions(events, contract, { [token]: 6n * PRICE }, opts)
    expect(r.sessions).toMatchObject({ opened: 2, open: 1, closed: 1, failing: [] })
    expect(r.tokens).toEqual([expect.objectContaining({ token, balance: 6n * PRICE, openDeposits: 6n * PRICE, onchain: 6n * PRICE, ok: true })])
    expect(r.ok).toBe(true)
    expect(reconcileSessions(events, contract, { [token]: 1n }, opts).ok).toBe(false)
  })

  it('counts a session of a service the caller does not know in the token its deposit came in', () => {
    const [a, b] = [h('u1'), h('u2')]
    const other = h('a service of another gateway')
    const elsewhere = open(b, 4).map((e) => ('serviceId' in e ? { ...e, serviceId: other } : e))
    const events = [...open(a, 10), ...batch(a, 0, 4, 4), ...elsewhere]
    const known = { ...opts, tokenOf: (id: string) => (id === A ? token : undefined), payoutOf: (id: string) => (id === A ? payout : undefined) }
    const r = reconcileSessions(events, contract, { [token]: 10n * PRICE }, known)
    expect(r.tokens).toEqual([expect.objectContaining({ token, balance: 10n * PRICE, openDeposits: 10n * PRICE, ok: true })])
    expect(r.ok).toBe(true)
  })

  it('lists a session in a token the index does not follow as untracked, not failing', () => {
    const [a, b] = [h('v1'), h('v2')]
    const other = h('a service in another token')
    const elsewhere = open(b, 4)
      .filter((e) => e.name !== 'transfer')
      .map((e) => ('serviceId' in e ? { ...e, serviceId: other } : e))
    const events = [...open(a, 10), ...batch(a, 0, 4, 4), ...elsewhere]
    const known = { ...opts, tokenOf: (id: string) => (id === A ? token : undefined) }
    const r = reconcileSessions(events, contract, { [token]: 6n * PRICE }, known)
    expect(r.sessions).toMatchObject({ opened: 2, open: 2, failing: [], untracked: [b] })
    expect(r.ok).toBe(true)
    // A session of a known service whose deposit is missing still fails.
    const missing = open(b, 4).filter((e) => e.name !== 'transfer')
    expect(reconcileSessions([...open(a, 10), ...missing], contract, {}, opts).sessions.failing).toEqual([b])
  })
})
