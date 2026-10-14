// Ported from Fermata `packages/sdk/test/scores.test.ts` @ d7cc642 (MIT), on Stellar's events (a
// timeout is its own `timed_out` event; ledgers instead of blocks). Fermata's `fetchEscrowLogs` and
// `serviceLabelOf` tests have no counterpart: the indexer replaces the first (see
// indexer.live.test.ts) and a Stellar service id is a hash, with no label inside.
import { describe, expect, it } from 'vitest'
import { aggregateScores, wilsonLower } from '../src/index.ts'
import { A, B, agents, calls, h, payout, registered } from './fixtures.ts'

describe('wilsonLower', () => {
  it('matches the textbook values and ranks volume over luck', () => {
    expect(wilsonLower(0, 0)).toBe(0)
    expect(wilsonLower(3, 3)).toBeCloseTo(0.4385, 3)
    expect(wilsonLower(950, 1000)).toBeCloseTo(0.9346, 3)
    expect(wilsonLower(950, 1000)).toBeGreaterThan(wilsonLower(3, 3))
    expect(wilsonLower(5, 10)).toBeCloseTo(0.2366, 3)
  })
})

describe('aggregateScores', () => {
  it('counts releases, proven failures, timeouts, open holds and distinct agents per service', () => {
    const events = [
      ...registered(A),
      ...calls(A, ['released', 'released', 'released', 'failed', 'timeout', 'open']),
      ...calls(A, ['released'], agents[1]),
      ...calls(B, ['failed', 'failed']),
    ]
    const [a, b] = aggregateScores(events.reverse()) // any input order
    expect(a!.serviceId).toBe(A)
    expect(a).toMatchObject({ held: 7, released: 4, provenFailures: 1, timeouts: 1, open: 1, settled: 6, distinctAgents: 2, payout, verifier: h('verifier'), pricePerCall: 10_000n })
    // proven outcomes only: 4 released of 5 proven; the timeout is counted but not held against the vendor
    expect(a!.deliveryRate).toBeCloseTo(4 / 5)
    expect(a!.score).toBeCloseTo(wilsonLower(4, 5))
    expect(a!.releasedAmount).toBe(40_000n)
    expect(a!.refundedAmount).toBe(20_000n)
    expect(b).toMatchObject({ held: 2, released: 0, provenFailures: 2, deliveryRate: 0, score: 0 })
  })

  it('timeouts alone (e.g. a stranger holding calls and never presenting them) do not sink a vendor', () => {
    const [s] = aggregateScores([...calls(A, ['released', 'released']), ...calls(A, Array(10).fill('timeout'))])
    expect(s).toMatchObject({ released: 2, timeouts: 10, deliveryRate: 1 })
    expect(s!.score).toBeCloseTo(wilsonLower(2, 2))
  })

  it('ignores a settlement seen twice', () => {
    const events = calls(A, ['released'])
    const [s] = aggregateScores([...events, events[2]!])
    expect(s).toMatchObject({ released: 1, settled: 1, open: 0 })
  })

  it('a service with no settled calls has no rate and scores 0', () => {
    const [s] = aggregateScores(calls(A, ['open']))
    expect(s).toMatchObject({ deliveryRate: null, score: 0, open: 1 })
  })
})
