// An indexer for one escrow: its events, and the token transfers into and out of it, read from
// Soroban RPC with `getEvents` and kept on disk.
//
// RPC keeps events for about 7 days (`history-retention-window`, 120,960 ledgers by default), and
// events are not ledger state, so reconciliation needs its own copy. The indexer pages forward with
// the RPC's cursor and appends what it reads to a JSON-lines file; after a restart it resumes from
// the saved cursor. Its history starts at `startLedger`, or at the oldest ledger the RPC still has;
// anything earlier is recorded as a gap, which only a data lake or a third-party indexer can fill.
//
// Tokens are learned from `service_registered` events. When a new one appears, its transfers are
// read again from that ledger, so none in the same page is missed.
import { mkdir, readFile, appendFile, writeFile, rename } from 'node:fs/promises'
import { join } from 'node:path'
import { Address, rpc, xdr } from '@stellar/stellar-sdk'
import { decodeEscrowEvent, decodeTransfer, type EscrowEvent, type EventPosition, type TransferEvent } from './events.ts'
import { rpcServer } from './soroban.ts'

export type IndexedEvent = EscrowEvent | TransferEvent

export type IndexerOptions = {
  rpcUrl: string
  escrow: string
  /** Tokens to follow from the start (more are learned from `service_registered`). */
  tokens?: readonly string[]
  /** First ledger to read (the escrow's deployment ledger). Default: the oldest the RPC has. */
  startLedger?: number
  /** Where to keep `events.jsonl` and `state.json`. Without it the index lives in memory only. */
  dir?: string
  /** Events per `getEvents` page (the RPC caps it, 10,000 by default). Default 1,000. */
  pageLimit?: number
}

type State = { escrow: string; tokens: string[]; cursor?: string; startLedger?: number; gaps: { from: number; to: number }[] }

const TRANSFER = xdr.ScVal.scvSymbol('transfer').toXDR('base64')

export class EscrowIndexer {
  private readonly server: rpc.Server
  private state: State
  private readonly byId = new Map<string, IndexedEvent>()
  private sorted: IndexedEvent[] = []
  private polling?: Promise<number>
  /** The latest ledger the RPC reported on the last poll. */
  latestLedger = 0

  constructor(private readonly opts: IndexerOptions) {
    this.server = rpcServer(opts.rpcUrl)
    this.state = { escrow: opts.escrow, tokens: [...new Set(opts.tokens ?? [])], startLedger: opts.startLedger, gaps: [] }
  }

  /** Reads a saved index from `dir`, if there is one for this escrow. */
  async load(): Promise<void> {
    if (!this.opts.dir) return
    await mkdir(this.opts.dir, { recursive: true })
    const state = await readFile(join(this.opts.dir, 'state.json'), 'utf8').then(JSON.parse, () => undefined)
    if (!state || state.escrow !== this.opts.escrow) return
    this.state = { ...state, tokens: [...new Set([...state.tokens, ...this.state.tokens])] }
    const lines = await readFile(join(this.opts.dir, 'events.jsonl'), 'utf8').catch(() => '')
    for (const line of lines.split('\n')) if (line.trim()) this.add(fromJson(JSON.parse(line)))
    this.resort()
  }

  get events(): readonly IndexedEvent[] {
    return this.sorted
  }

  get tokens(): readonly string[] {
    return this.state.tokens
  }

  /** Ledger ranges before the index's start that the RPC no longer had. */
  get gaps(): readonly { from: number; to: number }[] {
    return this.state.gaps
  }

  /** Reads everything new; concurrent calls share one read. Returns how many events were added. */
  poll(): Promise<number> {
    this.polling ??= this.pollNow().finally(() => {
      this.polling = undefined
    })
    return this.polling
  }

  private filters(tokens: readonly string[], withEscrow = true): rpc.Api.EventFilter[] {
    const escrow = new Address(this.opts.escrow).toScVal().toXDR('base64')
    const out: rpc.Api.EventFilter[] = withEscrow ? [{ type: 'contract', contractIds: [this.opts.escrow] }] : []
    for (let i = 0; i < tokens.length; i += 5) {
      out.push({
        type: 'contract',
        contractIds: tokens.slice(i, i + 5),
        topics: [
          [TRANSFER, '*', escrow, '**'],
          [TRANSFER, escrow, '*', '**'],
        ],
      })
    }
    if (out.length > 5) throw new Error('more tokens than one getEvents request can follow (20)')
    return out
  }

  private async pollNow(): Promise<number> {
    let added = 0
    for (;;) {
      const limit = this.opts.pageLimit ?? 1_000
      let res: rpc.Api.GetEventsResponse
      if (this.state.cursor) {
        try {
          res = await this.server.getEvents({ cursor: this.state.cursor, filters: this.filters(this.state.tokens), limit })
        } catch (e) {
          // A cursor older than the RPC's retention (the indexer was stopped for days): what the
          // RPC dropped meanwhile is a gap, and reading starts again from its oldest ledger.
          const { oldestLedger } = await this.server.getHealth()
          const at = ledgerOfCursor(this.state.cursor)
          if (at >= oldestLedger) throw e
          this.state.gaps.push({ from: at + 1, to: oldestLedger - 1 })
          this.state.cursor = undefined
          this.state.startLedger = oldestLedger
          continue
        }
      } else {
        const health = await this.server.getHealth()
        const start = Math.max(this.state.startLedger ?? health.oldestLedger, health.oldestLedger)
        if (this.state.startLedger !== undefined && this.state.startLedger < health.oldestLedger) {
          this.state.gaps.push({ from: this.state.startLedger, to: health.oldestLedger - 1 })
        }
        this.state.startLedger = start
        res = await this.server.getEvents({ startLedger: start, filters: this.filters(this.state.tokens), limit })
      }
      this.latestLedger = res.latestLedger
      const fresh: IndexedEvent[] = []
      const learned: { token: string; ledger: number }[] = []
      for (const e of res.events) {
        const ev = this.decode(e)
        if (!ev || this.byId.has(ev.id)) continue
        fresh.push(ev)
        if (ev.name === 'service_registered' && !this.state.tokens.includes(ev.token)) {
          this.state.tokens.push(ev.token)
          learned.push({ token: ev.token, ledger: ev.ledger })
        }
      }
      for (const { token, ledger } of learned) fresh.push(...(await this.backfill(token, ledger)))
      added += await this.commit(fresh, res.cursor)
      if (caughtUp(res, limit)) return added
    }
  }

  /** Transfers of a newly learned token, from the ledger it was registered in to the head. */
  private async backfill(token: string, from: number): Promise<IndexedEvent[]> {
    const out: IndexedEvent[] = []
    let res = await this.server.getEvents({ startLedger: from, filters: this.filters([token], false), limit: 1_000 })
    for (;;) {
      for (const e of res.events) {
        const ev = this.decode(e)
        if (ev && !this.byId.has(ev.id)) out.push(ev)
      }
      if (caughtUp(res, 1_000)) return out
      res = await this.server.getEvents({ cursor: res.cursor, filters: this.filters([token], false), limit: 1_000 })
    }
  }

  private decode(e: rpc.Api.EventResponse): IndexedEvent | undefined {
    const contract = e.contractId?.contractId()
    if (!contract || !e.inSuccessfulContractCall) return undefined
    const pos: EventPosition = { ledger: e.ledger, txHash: e.txHash, id: e.id, ledgerClosedAt: e.ledgerClosedAt }
    try {
      if (contract === this.opts.escrow) {
        const d = decodeEscrowEvent(e.topic, e.value)
        return d ? { ...d, ...pos } : undefined
      }
      const t = decodeTransfer(contract, e.topic, e.value)
      return t && (t.from === this.opts.escrow || t.to === this.opts.escrow) ? { ...t, ...pos } : undefined
    } catch {
      return undefined
    }
  }

  private add(ev: IndexedEvent) {
    this.byId.set(ev.id, ev)
  }

  private resort() {
    this.sorted = [...this.byId.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  }

  private async commit(fresh: IndexedEvent[], cursor: string): Promise<number> {
    const seen = new Set<string>()
    const unique = fresh.filter((e) => !this.byId.has(e.id) && !seen.has(e.id) && seen.add(e.id))
    for (const e of unique) this.add(e)
    if (unique.length) this.resort()
    this.state.cursor = cursor
    if (this.opts.dir) {
      if (unique.length) await appendFile(join(this.opts.dir, 'events.jsonl'), unique.map((e) => JSON.stringify(toJson(e)) + '\n').join(''))
      const tmp = join(this.opts.dir, 'state.json.tmp')
      await writeFile(tmp, JSON.stringify(this.state, null, 2))
      await rename(tmp, join(this.opts.dir, 'state.json'))
    }
    return unique.length
  }
}

/** The ledger a `getEvents` cursor points into (its TOID's upper 32 bits). */
export function ledgerOfCursor(cursor: string): number {
  return Number(BigInt(cursor.split('-')[0] ?? '0') >> 32n)
}

/**
 * Whether a `getEvents` page reached the RPC's latest ledger. A short page alone does not say so:
 * the RPC scans at most 10,000 ledgers per request (stellar-rpc `LedgerScanLimit`), and a page that
 * ends at its scan window has fewer events than asked for and a cursor at the window's last ledger.
 */
export function caughtUp(res: { events: readonly unknown[]; cursor: string; latestLedger: number }, limit: number): boolean {
  return res.events.length < limit && ledgerOfCursor(res.cursor) >= res.latestLedger
}

const BIGINT_FIELDS = new Set(['amount', 'fee', 'pricePerCall'])

function toJson(e: IndexedEvent): Record<string, unknown> {
  return Object.fromEntries(Object.entries(e).map(([k, v]) => [k, typeof v === 'bigint' ? v.toString() : v]))
}

function fromJson(o: Record<string, unknown>): IndexedEvent {
  return Object.fromEntries(Object.entries(o).map(([k, v]) => [k, BIGINT_FIELDS.has(k) && typeof v === 'string' ? BigInt(v) : v])) as IndexedEvent
}
