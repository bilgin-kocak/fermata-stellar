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

// ------------------------------------------------------------------------------------ sessions
//
// A session (contracts/session) reconciles when its index (an EscrowIndexer with kind 'session')
// shows: one opening that moved exactly the deposit (max_calls × price) from the agent into the
// session contract; batches that follow one another from call 0 and each moved exactly what its
// event says (the vendor's share to the payout, the fee to the treasury, the refund, plus what is
// left when the batch ends the session, to the agent, and nothing else); at most one closing; and,
// once closed, a deposit fully accounted for. While open, what is left is (max_calls − settled) × price.

type Opened = Extract<IndexedEvent, { name: 'session_opened' }>
type Settled = Extract<IndexedEvent, { name: 'batch_settled' }>
type Closed = Extract<IndexedEvent, { name: 'session_closed' }>

export type SessionReconcileOptions = ReconcileOptions & {
  /** The service's payout account (the session contract's events do not name it). */
  payoutOf?: (serviceId: Hex) => string | undefined
  /** The escrow's treasury, which receives the fees. */
  treasury?: string
}

export type SessionReconciliation = {
  sessionId: Hex
  serviceId?: Hex
  agent?: string
  token?: string
  deposit?: bigint
  price?: bigint
  maxCalls?: number
  status: 'unknown' | 'open' | 'closed'
  /** Calls settled by the indexed batches. */
  settled: number
  paidCalls: number
  paidOut: bigint
  fees: bigint
  refunded: bigint
  /** deposit − paid out − fees − refunded. */
  remaining: bigint
  opened?: { txHash: Hex; ledger: number; at?: string }
  batches: { from: number; to: number; paid: number; payoutAmount: bigint; fee: bigint; refund: bigint; txHash: Hex; ledger: number }[]
  closed?: { txHash: Hex; ledger: number; refund: bigint }
  movements: { txHash: Hex; token: string; from: string; to: string; amount: bigint }[]
  checks: Check[]
  ok: boolean
}

/** Reconciles one session against an index of the session contract's events. */
export function reconcileSession(
  events: readonly IndexedEvent[],
  sessionId: Hex,
  contract: string,
  opts: SessionReconcileOptions = {},
): SessionReconciliation {
  const ofSession = events.filter((e) => 'sessionId' in e && sameHex(e.sessionId, sessionId))
  const openings = ofSession.filter((e): e is Opened => e.name === 'session_opened')
  const batches = ofSession.filter((e): e is Settled => e.name === 'batch_settled')
  const closings = ofSession.filter((e): e is Closed => e.name === 'session_closed')
  const opened = openings[0]
  const closed = closings[0]
  const checks: Check[] = []
  const check = (name: string, ok: boolean, detail?: string) => checks.push({ name, ok, ...(detail && !ok ? { detail } : {}) })
  const payout = opened ? opts.payoutOf?.(opened.serviceId) : undefined
  const txs = new Set([opened?.txHash, ...batches.map((b) => b.txHash), closed?.txHash].filter((h): h is string => !!h))
  const movements = events
    .filter(isTransfer)
    .filter((t) => txs.has(t.txHash))
    .map((t) => ({ txHash: t.txHash, token: t.token, from: t.from, to: t.to, amount: t.amount }))
  const out = (txHash: Hex) => movements.filter((m) => m.txHash === txHash && m.from === contract)
  const into = opened ? movements.filter((m) => m.txHash === opened.txHash && m.to === contract) : []
  // The session contract's events do not name the token. For a service the caller does not know
  // (another gateway's, on the same contract), the deposit's own transfer does.
  const token = (opened ? opts.tokenOf?.(opened.serviceId) : undefined) ?? (into.length === 1 ? into[0]!.token : undefined)

  check('opened once', openings.length === 1, openings.length === 0 ? 'no session_opened event in the index' : `${openings.length} openings`)
  if (opened) {
    const one = into.length === 1 ? into[0]! : undefined
    check(
      'the opening moved the deposit from the agent into the session contract',
      !!one && one.from === opened.agent && one.amount === opened.deposit && (!token || one.token === token),
      `transfers into the session contract in the opening: ${into.length}`,
    )
    check('the deposit is max_calls × price', opened.deposit === opened.price * BigInt(opened.maxCalls), `${opened.deposit} ≠ ${opened.maxCalls} × ${opened.price}`)
  }

  let at = 0
  let paidCalls = 0
  let paidOut = 0n
  let fees = 0n
  let refunded = 0n
  for (const b of batches) {
    const label = `batch ${b.from + 1}-${b.to}`
    check(`${label} follows the previous one`, b.from === at && b.to > b.from && (!opened || b.to - b.from <= opened.batchSize), `from ${b.from}, expected ${at}`)
    at = b.to
    paidCalls += b.paid
    const count = b.to - b.from
    if (opened) {
      check(
        `${label} paid what its counts say`,
        b.paid <= count && b.payoutAmount + b.fee === BigInt(b.paid) * opened.price && b.refund === BigInt(count - b.paid) * opened.price,
        `paid ${b.paid} of ${count}, payout ${b.payoutAmount}, fee ${b.fee}, refund ${b.refund}`,
      )
    }
    const rest = closed && closed.txHash === b.txHash ? closed.refund : 0n
    const moved = out(b.txHash)
    const toPayout = moved.filter((m) => payout !== undefined && m.to === payout).reduce((n, m) => n + m.amount, 0n)
    const toTreasury = moved.filter((m) => opts.treasury !== undefined && m.to === opts.treasury).reduce((n, m) => n + m.amount, 0n)
    const toAgent = moved.filter((m) => opened && m.to === opened.agent).reduce((n, m) => n + m.amount, 0n)
    const total = moved.reduce((n, m) => n + m.amount, 0n)
    check(
      `${label} moved exactly its event's amounts`,
      total === b.payoutAmount + b.fee + b.refund + rest &&
        toAgent === b.refund + rest &&
        (payout === undefined || toPayout === b.payoutAmount) &&
        (opts.treasury === undefined || toTreasury === b.fee) &&
        moved.every((m) => !token || m.token === token),
      `out ${total}: payout ${toPayout}, treasury ${toTreasury}, agent ${toAgent}`,
    )
    paidOut += b.payoutAmount
    fees += b.fee
    refunded += b.refund + rest
  }
  check('closed at most once', closings.length <= 1, `${closings.length} closings`)
  if (closed && opened && !batches.some((b) => b.txHash === closed.txHash)) {
    const moved = out(closed.txHash)
    check(
      'the closing returned what was left to the agent, and nothing else',
      moved.length === (closed.refund === 0n ? 0 : 1) && moved.every((m) => m.to === opened.agent && m.amount === closed.refund),
      `transfers out in the closing: ${moved.length}`,
    )
    refunded += closed.refund
  }
  const deposit = opened?.deposit ?? 0n
  const remaining = deposit - paidOut - fees - refunded
  if (opened) {
    if (closed) check('the whole deposit is accounted for', remaining === 0n, `${remaining} left`)
    else check('what is left covers the calls not settled', remaining === BigInt(opened.maxCalls - at) * opened.price, `${remaining} left for ${opened.maxCalls - at} calls`)
  }

  return {
    sessionId: sessionId.toLowerCase(),
    serviceId: opened?.serviceId,
    agent: opened?.agent,
    token,
    deposit: opened?.deposit,
    price: opened?.price,
    maxCalls: opened?.maxCalls,
    status: closed ? 'closed' : opened ? 'open' : 'unknown',
    settled: at,
    paidCalls,
    paidOut,
    fees,
    refunded,
    remaining,
    ...(opened ? { opened: { txHash: opened.txHash, ledger: opened.ledger, at: opened.ledgerClosedAt } } : {}),
    batches: batches.map((b) => ({ from: b.from, to: b.to, paid: b.paid, payoutAmount: b.payoutAmount, fee: b.fee, refund: b.refund, txHash: b.txHash, ledger: b.ledger })),
    ...(closed ? { closed: { txHash: closed.txHash, ledger: closed.ledger, refund: closed.refund } } : {}),
    movements,
    checks,
    ok: checks.every((c) => c.ok),
  }
}

export type SessionsReconciliation = {
  tokens: { token: string; into: bigint; out: bigint; balance: bigint; openDeposits: bigint; onchain?: bigint; ok: boolean }[]
  /**
   * `untracked`: sessions of services the caller does not know whose deposit is not in the index
   * either, so in a token the index does not follow; they cannot be checked, and do not change the
   * balances of the tokens it follows.
   */
  sessions: { opened: number; open: number; closed: number; failing: Hex[]; untracked: Hex[] }
  ok: boolean
}

/**
 * Reconciles every session in the index and, per token, the session contract's balance (transfers
 * in minus out) against what is left of the open sessions' deposits and, when given, the token's
 * own `balance(contract)`. The balance check holds only for an index from the contract's deployment.
 */
export function reconcileSessions(
  events: readonly IndexedEvent[],
  contract: string,
  onchain: Record<string, bigint> = {},
  opts: SessionReconcileOptions = {},
): SessionsReconciliation {
  const ids = [...new Set(events.filter((e): e is Opened => e.name === 'session_opened').map((e) => e.sessionId))]
  const all = ids.map((id) => reconcileSession(events, id, contract, opts))
  const rows = new Map<string, SessionsReconciliation['tokens'][number]>()
  const row = (token: string) => {
    let r = rows.get(token)
    if (!r) rows.set(token, (r = { token, into: 0n, out: 0n, balance: 0n, openDeposits: 0n, ok: true }))
    return r
  }
  for (const t of events.filter(isTransfer)) {
    if (t.to === contract) row(t.token).into += t.amount
    if (t.from === contract) row(t.token).out += t.amount
  }
  for (const s of all) if (s.status === 'open' && s.token) row(s.token).openDeposits += s.remaining
  for (const r of rows.values()) {
    r.balance = r.into - r.out
    if (onchain[r.token] !== undefined) r.onchain = onchain[r.token]
    r.ok = r.balance === r.openDeposits && (r.onchain === undefined || r.onchain === r.balance)
  }
  const tokens = [...rows.values()]
  const untracked = all.filter((s) => s.token === undefined).map((s) => s.sessionId)
  const failing = all.filter((s) => !s.ok && s.token !== undefined).map((s) => s.sessionId)
  return {
    tokens,
    sessions: { opened: all.length, open: all.filter((s) => s.status === 'open').length, closed: all.filter((s) => s.status === 'closed').length, failing, untracked },
    ok: failing.length === 0 && tokens.every((t) => t.ok),
  }
}
