// Reconciliation from events: every call's money movements checked against the escrow's own events.
//
// On Tempo, Fermata filtered TIP-20 `TransferWithMemo` logs by memo = call id (packages/sdk
// escrow.ts `reconcile` @ d7cc642). On Stellar the escrow's event names the call and the token's
// `transfer` events sit in the same transaction, so a call reconciles when:
// - it was held once, and the hold moved exactly the price from the agent into the escrow;
// - it was settled at most once, and the settlement moved exactly what its event says: on release,
//   price − fee to the service's payout and the fee to the treasury; on a refund or a timeout, the
//   price back to the agent; nothing else left the escrow in that transaction.
// For the whole escrow, per token: what came in minus what went out equals the open holds.
import type { IndexedEvent } from './indexer.ts'
import type { Held, Released, Refunded, ServiceRegistered, TimedOut, TransferEvent, TreasuryUpdated } from './events.ts'
import type { Hex } from './hex.ts'

export type Check = { name: string; ok: boolean; detail?: string }
type Final = (Released | Refunded | TimedOut) & { txHash: Hex; ledger: number; id: string; ledgerClosedAt?: string }

export type CallReconciliation = {
  callId: Hex
  serviceId?: Hex
  agent?: string
  token?: string
  amount?: bigint
  status: 'unknown' | 'held' | 'released' | 'refunded' | 'timed_out'
  hold?: { txHash: Hex; ledger: number; at?: string }
  final?: { event: Final['name']; txHash: Hex; ledger: number; at?: string; presentationHash?: Hex; fee?: bigint }
  movements: { txHash: Hex; token: string; from: string; to: string; amount: bigint }[]
  checks: Check[]
  ok: boolean
}

const isTransfer = (e: IndexedEvent): e is TransferEvent => e.name === 'transfer'
const sameHex = (a: string, b: string) => a.toLowerCase() === b.toLowerCase()

/**
 * Services' tokens when their registration is not in the index (it happened before the index's
 * start): the gateway knows them from `get_service`.
 */
export type ReconcileOptions = { tokenOf?: (serviceId: Hex) => string | undefined }

/** Reconciles one call against an index of the escrow's events (see {@link EscrowIndexer}). */
export function reconcileCall(events: readonly IndexedEvent[], callId: Hex, escrow: string, opts: ReconcileOptions = {}): CallReconciliation {
  const ofCall = events.filter((e) => 'callId' in e && sameHex(e.callId, callId))
  const helds = ofCall.filter((e): e is Held & IndexedEvent => e.name === 'held')
  const finals = ofCall.filter((e): e is Final => e.name === 'released' || e.name === 'refunded' || e.name === 'timed_out')
  const held = helds[0]
  const final = finals[0]
  const checks: Check[] = []
  const check = (name: string, ok: boolean, detail?: string) => checks.push({ name, ok, ...(detail && !ok ? { detail } : {}) })

  const registered = held
    ? events.find((e): e is ServiceRegistered & IndexedEvent => e.name === 'service_registered' && sameHex(e.serviceId, held.serviceId))
    : undefined
  const token = registered?.token ?? (held ? opts.tokenOf?.(held.serviceId) : undefined)
  const txs = new Set([held?.txHash, final?.txHash].filter((h): h is string => !!h))
  const movements = events
    .filter(isTransfer)
    .filter((t) => txs.has(t.txHash))
    .map((t) => ({ txHash: t.txHash, token: t.token, from: t.from, to: t.to, amount: t.amount }))

  check('held once', helds.length === 1, helds.length === 0 ? 'no held event in the index (before its start, or not read yet)' : `${helds.length} held events`)
  if (held) {
    const into = movements.filter((m) => m.txHash === held.txHash && m.to === escrow)
    const one = into.length === 1 ? into[0]! : undefined
    check(
      'the hold moved the price from the agent into the escrow',
      !!one && one.from === held.agent && one.amount === held.amount && (!token || one.token === token),
      `transfers into the escrow in the hold: ${JSON.stringify(into.map((m) => ({ ...m, amount: m.amount.toString() })))}`,
    )
    check("the service's token is known", token !== undefined, 'its registration is not in the index')
  }
  check('settled at most once', finals.length <= 1, `${finals.length} settlements`)
  if (held && final) {
    check('the settlement is for the held amount', final.amount === held.amount, `held ${held.amount}, settled ${final.amount}`)
    const out = movements.filter((m) => m.txHash === final.txHash && m.from === escrow)
    const wrongToken = out.some((m) => token !== undefined && m.token !== token)
    if (final.name === 'released') {
      const treasury = events
        .filter((e): e is TreasuryUpdated & IndexedEvent => e.name === 'treasury_updated' && e.id < final.id)
        .at(-1)?.treasury
      const toPayout = out.filter((m) => m.to === final.payout).reduce((n, m) => n + m.amount, 0n)
      const toTreasury = out.filter((m) => m.to === treasury).reduce((n, m) => n + m.amount, 0n)
      const total = out.reduce((n, m) => n + m.amount, 0n)
      check(
        'the release paid price − fee to the payout and the fee to the treasury, and nothing else',
        !wrongToken &&
          toPayout === final.amount - final.fee &&
          (treasury === undefined ? final.fee === 0n || total === final.amount : toTreasury === final.fee) &&
          total === final.amount,
        `payout ${toPayout}, treasury ${toTreasury}, total ${total}, fee ${final.fee}`,
      )
    } else {
      const toAgent = out.filter((m) => m.to === held.agent).reduce((n, m) => n + m.amount, 0n)
      check(
        `the ${final.name === 'refunded' ? 'refund' : 'timeout refund'} returned the price to the agent, and nothing else`,
        !wrongToken && out.length === 1 && toAgent === final.amount,
        `transfers out of the escrow: ${out.length}, to the agent: ${toAgent}`,
      )
    }
  }

  return {
    callId: callId.toLowerCase(),
    serviceId: held?.serviceId,
    agent: held?.agent,
    token,
    amount: held?.amount,
    status: final ? final.name : held ? 'held' : 'unknown',
    ...(held ? { hold: { txHash: held.txHash, ledger: held.ledger, at: held.ledgerClosedAt } } : {}),
    ...(final
      ? {
          final: {
            event: final.name,
            txHash: final.txHash,
            ledger: final.ledger,
            at: final.ledgerClosedAt,
            ...('presentationHash' in final ? { presentationHash: final.presentationHash } : {}),
            ...(final.name === 'released' ? { fee: final.fee } : {}),
          },
        }
      : {}),
    movements,
    checks,
    ok: checks.every((c) => c.ok),
  }
}

export type TokenBalance = { token: string; into: bigint; out: bigint; balance: bigint; openHolds: bigint; onchain?: bigint; ok: boolean }

export type EscrowReconciliation = {
  tokens: TokenBalance[]
  calls: { held: number; open: number; released: number; refunded: number; timedOut: number; failing: Hex[] }
  ok: boolean
}

/**
 * Reconciles the whole index: every call, and per token the escrow's balance (transfers in minus
 * transfers out) against the open holds and, when given, the token's own `balance(escrow)`. The
 * balance check holds only for an index that starts at the escrow's deployment with no gap.
 */
export function reconcileEscrow(
  events: readonly IndexedEvent[],
  escrow: string,
  onchain: Record<string, bigint> = {},
  opts: ReconcileOptions = {},
): EscrowReconciliation {
  const callIds = [...new Set(events.filter((e): e is Held & IndexedEvent => e.name === 'held').map((e) => e.callId))]
  const calls = callIds.map((id) => reconcileCall(events, id, escrow, opts))
  const byToken = new Map<string, TokenBalance>()
  const row = (token: string) => {
    let r = byToken.get(token)
    if (!r) byToken.set(token, (r = { token, into: 0n, out: 0n, balance: 0n, openHolds: 0n, ok: true }))
    return r
  }
  for (const t of events.filter(isTransfer)) {
    if (t.to === escrow) row(t.token).into += t.amount
    if (t.from === escrow) row(t.token).out += t.amount
  }
  for (const c of calls) if (c.status === 'held' && c.amount !== undefined && c.token) row(c.token).openHolds += c.amount
  for (const r of byToken.values()) {
    r.balance = r.into - r.out
    if (onchain[r.token] !== undefined) r.onchain = onchain[r.token]
    r.ok = r.balance === r.openHolds && (r.onchain === undefined || r.onchain === r.balance)
  }
  const tokens = [...byToken.values()]
  const count = (s: CallReconciliation['status']) => calls.filter((c) => c.status === s).length
  const failing = calls.filter((c) => !c.ok).map((c) => c.callId)
  return {
    tokens,
    calls: { held: calls.length, open: count('held'), released: count('released'), refunded: count('refunded'), timedOut: count('timed_out'), failing },
    ok: failing.length === 0 && tokens.every((t) => t.ok),
  }
}
