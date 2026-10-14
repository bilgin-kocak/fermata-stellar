// Vendor delivery scores, computed from the escrow's own events and nothing else, so anyone can
// recompute them from an index: service_registered, held, released, refunded, timed_out.
//
// Ported from Fermata `packages/sdk/src/scores.ts` @ d7cc642 (github.com/bilgin-kocak/fermata, MIT).
// Kept: the delivery rate over proven outcomes only, the Wilson score lower bound (95 %) as the
// ranking key, distinct agents, and the caveats. Changed: a timeout is its own `timed_out` event
// here (Fermata read it as `Refunded` with a zero presentation hash), so every `refunded` is a proven
// failure; ledgers instead of blocks; addresses are Stellar's.
//
// A `refunded` event is a proven failure (a verdict backed by a TLSNotary presentation); `timed_out`
// means no proof arrived inside the window. The delivery rate counts proven outcomes only (released
// vs proven failures): a timeout proves nothing about the vendor, since anyone can hold a call and
// never present it. Ranking uses the Wilson lower bound of that rate, so a vendor with 3/3 does not
// outrank one with 950/1000. A ranking should only include services whose verifier it trusts
// (service_registered carries it): a service that names itself as verifier can sign "deliveries"
// with no proof.
//
// Limits (shown wherever scores are shown): only calls paid through Fermata count, and a vendor can
// pay itself to inflate its score; distinct agents are reported for that reason.
import type { IndexedEvent } from './indexer.ts'
import type { Hex } from './hex.ts'

export type ServiceScore = {
  serviceId: Hex
  /** From service_registered (absent if the registration predates the index). */
  owner?: string
  payout?: string
  /** Who signs this service's verdicts. A ranking should only trust verifiers it knows. */
  verifier?: Hex
  token?: string
  pricePerCall?: bigint
  registeredLedger?: number
  held: number
  released: number
  /** Refunded on a verdict: the vendor's own answer failed the delivery check. */
  provenFailures: number
  /** Refunded by claim_timeout: no proof inside the settlement window. */
  timeouts: number
  /** Held, not yet settled. */
  open: number
  settled: number
  /** released / (released + provenFailures), or null before the first proven outcome. */
  deliveryRate: number | null
  /** Wilson 95 % lower bound of the delivery rate (0 with no proven outcome): the ranking key. */
  score: number
  distinctAgents: number
  releasedAmount: bigint
  refundedAmount: bigint
  firstCallLedger?: number
  lastCallLedger?: number
}

/** Wilson score interval lower bound for `successes` out of `n` (z = 1.96 → 95 %). */
export function wilsonLower(successes: number, n: number, z = 1.96): number {
  if (n <= 0) return 0
  const p = successes / n
  const z2 = z * z
  const centre = p + z2 / (2 * n)
  const margin = z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))
  return Math.max(0, (centre - margin) / (1 + z2 / n))
}

/** Aggregates indexed events (any order) into one score per service, best first. */
export function aggregateScores(events: readonly IndexedEvent[]): ServiceScore[] {
  const sorted = [...events].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  const by = new Map<string, ServiceScore & { agents: Set<string>; settledCalls: Set<string> }>()
  const get = (serviceId: Hex) => {
    const key = serviceId.toLowerCase()
    let s = by.get(key)
    if (!s) {
      s = {
        serviceId: key,
        held: 0,
        released: 0,
        provenFailures: 0,
        timeouts: 0,
        open: 0,
        settled: 0,
        deliveryRate: null,
        score: 0,
        distinctAgents: 0,
        releasedAmount: 0n,
        refundedAmount: 0n,
        agents: new Set(),
        settledCalls: new Set(),
      }
      by.set(key, s)
    }
    return s
  }
  for (const e of sorted) {
    switch (e.name) {
      case 'service_registered':
        Object.assign(get(e.serviceId), {
          owner: e.owner,
          payout: e.payout,
          verifier: e.verifier,
          token: e.token,
          pricePerCall: e.pricePerCall,
          registeredLedger: e.ledger,
        })
        break
      case 'held': {
        const s = get(e.serviceId)
        s.held++
        s.agents.add(e.agent)
        s.firstCallLedger ??= e.ledger
        s.lastCallLedger = e.ledger
        break
      }
      case 'released':
      case 'refunded':
      case 'timed_out': {
        const s = get(e.serviceId)
        const call = e.callId.toLowerCase()
        if (s.settledCalls.has(call)) break // a call settles once; ignore duplicates
        s.settledCalls.add(call)
        if (e.name === 'released') {
          s.released++
          s.releasedAmount += e.amount
        } else {
          if (e.name === 'timed_out') s.timeouts++
          else s.provenFailures++
          s.refundedAmount += e.amount
        }
        break
      }
    }
  }
  const out: ServiceScore[] = []
  for (const { agents, settledCalls, ...s } of by.values()) {
    void settledCalls
    s.settled = s.released + s.provenFailures + s.timeouts
    s.open = Math.max(0, s.held - s.settled)
    const proven = s.released + s.provenFailures
    s.deliveryRate = proven ? s.released / proven : null
    s.score = wilsonLower(s.released, proven)
    s.distinctAgents = agents.size
    out.push(s)
  }
  return out.sort((a, b) => b.score - a.score || b.settled - a.settled)
}
