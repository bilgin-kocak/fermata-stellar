// The gateway's record of each session (docs/session-escrow.md, phase 1): one JSON file per
// session, written atomically, as CallStore does for holds.
//
// New in this repository. A session is opened by its first paid call (the gateway submits the
// agent's `open_session`), takes one call per ticket, and is settled in batches signed by the
// attestor; after its deadline the gateway closes it.
import { mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises'
import path from 'node:path'
import type { Hex } from 'fermata-stellar-sdk'

/** Life of a session at the gateway. */
export type SessionStatus =
  | 'opening' // open_session is being submitted
  | 'open' // taking calls, then settling them
  | 'closed' // every call settled (its last batch closed it) or closed after the deadline

/** Life of one call of a session at the gateway. */
export type SessionCallStatus =
  | 'proving' // the attestor is proving it
  | 'recorded' // the attestor recorded its result (DELIVERED, FAILED or UNANSWERED)
  | 'unrecorded' // the attestor could not be reached: the sweeper has it recorded UNANSWERED

export type SessionCall = {
  n: number
  method: string
  target: string
  requestHash: Hex
  /** chain(n). */
  chain: Hex
  /** The agent's ticket for call n. */
  ticket: Hex
  status: SessionCallStatus
  outcome?: 'DELIVERED' | 'FAILED' | 'UNANSWERED'
  presentationHash?: Hex
  failures?: string[]
  proveMs?: number
  error?: string
  createdAt: string
}

export type SessionBatch = { from: number; to: number; paid: number; txHash: Hex; at: string }

export type SessionRecord = {
  sessionId: Hex
  serviceId: Hex
  agent: string
  ticketKey: Hex
  maxCalls: number
  batchSize: number
  /** Base units, as decimal strings (JSON-safe bigints). */
  price: string
  deposit: string
  /** Unix seconds: calls are taken until `expiresAt`, batches settle until `deadline`. */
  expiresAt: string
  deadline: string
  status: SessionStatus
  openTx?: Hex
  /** Calls settled on chain. */
  settled: number
  calls: SessionCall[]
  batches: SessionBatch[]
  closeTx?: Hex
  error?: string
  createdAt: string
  updatedAt: string
}

/** The next call number and chain(next − 1) of a session, from its recorded calls. */
export function nextOf(s: SessionRecord): { next: number; chain: Hex } {
  const last = s.calls.at(-1)
  return last ? { next: last.n + 1, chain: last.chain } : { next: 1, chain: s.sessionId }
}

/** One JSON file per session under `dir`, written atomically (temp file + rename). */
export class SessionStore {
  constructor(readonly dir: string) {}

  private file(sessionId: string) {
    if (!/^[0-9a-f]{64}$/.test(sessionId)) throw new Error(`bad session id ${sessionId}`)
    return path.join(this.dir, `${sessionId}.json`)
  }

  async put(record: SessionRecord): Promise<SessionRecord> {
    await mkdir(this.dir, { recursive: true })
    const next = { ...record, updatedAt: new Date().toISOString() }
    const file = this.file(record.sessionId)
    const tmp = `${file}.${process.pid}.${Date.now()}.tmp`
    await writeFile(tmp, `${JSON.stringify(next, null, 2)}\n`)
    await rename(tmp, file)
    return next
  }

  async update(sessionId: Hex, patch: Partial<SessionRecord>): Promise<SessionRecord> {
    const current = await this.get(sessionId)
    if (!current) throw new Error(`no session ${sessionId}`)
    return this.put({ ...current, ...patch })
  }

  /** Changes one call of a session. */
  async updateCall(sessionId: Hex, n: number, patch: Partial<SessionCall>): Promise<SessionRecord> {
    const current = await this.get(sessionId)
    if (!current) throw new Error(`no session ${sessionId}`)
    return this.put({ ...current, calls: current.calls.map((c) => (c.n === n ? { ...c, ...patch } : c)) })
  }

  async get(sessionId: string): Promise<SessionRecord | undefined> {
    try {
      return JSON.parse(await readFile(this.file(sessionId.toLowerCase()), 'utf8'))
    } catch {
      return undefined
    }
  }

  async list(): Promise<SessionRecord[]> {
    let names: string[] = []
    try {
      names = (await readdir(this.dir)).filter((n) => /^[0-9a-f]{64}\.json$/.test(n))
    } catch {
      return []
    }
    const records = await Promise.all(names.map((n) => this.get(n.slice(0, -5))))
    return records.filter((r): r is SessionRecord => !!r).sort((a, b) => a.createdAt.localeCompare(b.createdAt))
  }
}

/** The method server's view of a session (fermata-stellar-sdk `SessionView`). */
export function viewOf(s: SessionRecord) {
  const { next, chain } = nextOf(s)
  return {
    serviceId: s.serviceId,
    agent: s.agent,
    ticketKey: s.ticketKey,
    maxCalls: s.maxCalls,
    expiresAt: BigInt(s.expiresAt),
    next,
    chain,
    // A call the attestor did not record blocks the next ones until the sweeper records it.
    open: s.status === 'open' && !s.calls.some((c) => c.status === 'unrecorded' || c.status === 'proving'),
  }
}

/** The record of a session the gateway is about to open (status `opening`). */
export function openingRecord(o: {
  sessionId: Hex
  serviceId: Hex
  agent: string
  ticketKey: Hex
  maxCalls: number
  batchSize: number
  expiresAt: bigint
  deposit: bigint
}): SessionRecord {
  const now = new Date().toISOString()
  return {
    sessionId: o.sessionId.toLowerCase(),
    serviceId: o.serviceId.toLowerCase(),
    agent: o.agent,
    ticketKey: o.ticketKey.toLowerCase(),
    maxCalls: o.maxCalls,
    batchSize: o.batchSize,
    price: (o.deposit / BigInt(o.maxCalls)).toString(),
    deposit: o.deposit.toString(),
    expiresAt: o.expiresAt.toString(),
    // Known once the opening lands (expiry plus the service's settlement window).
    deadline: '0',
    status: 'opening',
    settled: 0,
    calls: [],
    batches: [],
    createdAt: now,
    updatedAt: now,
  }
}
