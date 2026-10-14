// The gateway's record of each paid call: one JSON file per call, written atomically.
//
// Ported from Fermata `apps/gateway/src/store.ts` @ d7cc642 (github.com/bilgin-kocak/fermata, MIT).
// Kept: the statuses and their meaning, one file per call, atomic writes. Changed: call ids are hex
// without `0x`; a record notes how the call was paid (MPP or x402, sponsored or not); `holding`
// marks a sponsored hold the gateway is about to submit, so the sweeper finds it even if the
// submission's outcome was lost.
import { mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises'
import path from 'node:path'
import type { Hex, Verdict } from 'fermata-stellar-sdk'

/** Life of one paid call at the gateway. Final: released, refunded, timed-out, closed. */
export type CallStatus =
  | 'holding' // a sponsored hold is being submitted
  | 'held' // hold verified, proving
  | 'released' // DELIVERED verdict settled: vendor paid
  | 'refunded' // FAILED verdict settled: agent refunded
  | 'settle-pending' // verdict signed, settle failed; retried while the window is open
  | 'awaiting-timeout' // no verdict (no transcript / binding check failed): only claim_timeout can end it
  | 'timed-out' // claim_timeout sent by the sweeper
  | 'closed' // finalised by someone else, or never held

export type CallRecord = {
  callId: Hex
  serviceId: Hex
  method: string
  target: string
  requestHash: Hex
  /** How the agent paid: the MPP method or the x402 scheme, and whether the gateway submitted the hold. */
  paidWith: 'mpp' | 'x402'
  sponsored: boolean
  holdTx?: Hex
  agent?: string
  deadline: string // unix seconds (string: JSON-safe bigint)
  status: CallStatus
  outcome?: 'DELIVERED' | 'FAILED'
  failures?: string[]
  verdict?: Verdict
  signature?: Hex
  presentationHash?: Hex
  settleTx?: Hex
  timeoutTx?: Hex
  proveMs?: number
  signer?: string
  error?: string
  createdAt: string
  updatedAt: string
}

export const FINAL: readonly CallStatus[] = ['released', 'refunded', 'timed-out', 'closed']

/** One JSON file per call under `dir`, written atomically (temp file + rename). */
export class CallStore {
  constructor(readonly dir: string) {}

  private file(callId: string) {
    if (!/^[0-9a-f]{64}$/.test(callId)) throw new Error(`bad callId ${callId}`)
    return path.join(this.dir, `${callId}.json`)
  }

  async put(record: CallRecord): Promise<CallRecord> {
    await mkdir(this.dir, { recursive: true })
    const next = { ...record, updatedAt: new Date().toISOString() }
    const file = this.file(record.callId)
    const tmp = `${file}.${process.pid}.${Date.now()}.tmp`
    await writeFile(tmp, `${JSON.stringify(next, null, 2)}\n`)
    await rename(tmp, file)
    return next
  }

  async update(callId: Hex, patch: Partial<CallRecord>): Promise<CallRecord> {
    const current = await this.get(callId)
    if (!current) throw new Error(`no call ${callId}`)
    return this.put({ ...current, ...patch })
  }

  async get(callId: string): Promise<CallRecord | undefined> {
    try {
      return JSON.parse(await readFile(this.file(callId.toLowerCase()), 'utf8'))
    } catch {
      return undefined
    }
  }

  async list(): Promise<CallRecord[]> {
    let names: string[] = []
    try {
      names = (await readdir(this.dir)).filter((n) => /^[0-9a-f]{64}\.json$/.test(n))
    } catch {
      return []
    }
    const records = await Promise.all(names.map((n) => this.get(n.slice(0, -5))))
    return records.filter((r): r is CallRecord => !!r).sort((a, b) => a.createdAt.localeCompare(b.createdAt))
  }
}
