// Reconciliation of each call and of the escrow's balance, on synthetic indexed events.
import { describe, expect, it } from 'vitest'
import { reconcileCall, reconcileEscrow, type IndexedEvent } from '../src/index.ts'
import { A, agents, call, escrow, payout, registered, token, treasury } from './fixtures.ts'

const callIdOf = (events: IndexedEvent[]) => (events[0] as { callId: string }).callId

describe('reconcileCall', () => {
  it('a release paid price − fee to the payout and the fee to the treasury', () => {
    const c = call(A, 'released')
    const r = reconcileCall([...registered(A), ...c], callIdOf(c), escrow)
    expect(r).toMatchObject({ status: 'released', ok: true, token, amount: 10_000n, agent: agents[0] })
    expect(r.final).toMatchObject({ event: 'released', fee: 50n })
    expect(r.movements.map((m) => [m.from, m.to, m.amount])).toEqual([
      [agents[0], escrow, 10_000n],
      [escrow, payout, 9_950n],
      [escrow, treasury, 50n],
    ])
  })

  it('a refund and a timeout returned the price to the agent', () => {
    for (const outcome of ['failed', 'timeout'] as const) {
      const c = call(A, outcome)
      const r = reconcileCall([...registered(A), ...c], callIdOf(c), escrow)
      expect(r.ok).toBe(true)
      expect(r.status).toBe(outcome === 'failed' ? 'refunded' : 'timed_out')
    }
  })

  it('an open hold reconciles as held', () => {
    const c = call(A, 'open')
    expect(reconcileCall([...registered(A), ...c], callIdOf(c), escrow)).toMatchObject({ status: 'held', ok: true })
  })

  it('flags a release that paid the wrong amount, a second settlement, and a hold missing from the index', () => {
    const c = call(A, 'released')
    const short = c.map((e) => (e.name === 'transfer' && e.to === payout ? { ...e, amount: 9_000n } : e))
    const r = reconcileCall([...registered(A), ...short], callIdOf(c), escrow)
    expect(r.ok).toBe(false)
    expect(r.checks.find((x) => !x.ok)?.name).toMatch(/release paid/)

    const twice = [...registered(A), ...c, { ...c[2]!, id: 'zz', txHash: 'ff'.repeat(32) }]
    expect(reconcileCall(twice, callIdOf(c), escrow).checks.find((x) => !x.ok)?.name).toMatch(/at most once/)

    const missing = reconcileCall([...registered(A), ...c.slice(2)], callIdOf(c), escrow)
    expect(missing).toMatchObject({ status: 'released', ok: false })
  })

  it("takes the service's token from the gateway when the registration predates the index", () => {
    const c = call(A, 'failed')
    const withoutRegistration = reconcileCall(c, callIdOf(c), escrow)
    expect(withoutRegistration.ok).toBe(false)
    expect(reconcileCall(c, callIdOf(c), escrow, { tokenOf: () => token }).ok).toBe(true)
  })
})

describe('reconcileEscrow', () => {
  it("balances: what came in minus what went out equals the open holds and the token's balance", () => {
    const events = [...registered(A), ...call(A, 'released'), ...call(A, 'failed'), ...call(A, 'timeout'), ...call(A, 'open'), ...call(A, 'open')]
    const r = reconcileEscrow(events, escrow, { [token]: 20_000n })
    expect(r.ok).toBe(true)
    expect(r.tokens[0]).toMatchObject({ token, into: 50_000n, out: 30_000n, balance: 20_000n, openHolds: 20_000n, onchain: 20_000n })
    expect(r.calls).toMatchObject({ held: 5, open: 2, released: 1, refunded: 1, timedOut: 1, failing: [] })
    expect(reconcileEscrow(events, escrow, { [token]: 19_999n }).ok).toBe(false)
  })
})
