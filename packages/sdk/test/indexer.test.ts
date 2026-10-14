// The indexer's paging against a fake RPC that scans at most 10,000 ledgers per `getEvents`
// request, as stellar-rpc does (`LedgerScanLimit` in cmd/stellar-rpc/internal/methods/get_events.go):
// a page that ends at its scan window is short, and its cursor sits at the window's last ledger.
import { Contract, xdr } from '@stellar/stellar-sdk'
import { describe, expect, it } from 'vitest'
import { EscrowIndexer, caughtUp, ledgerOfCursor } from '../src/index.ts'
import { escrow } from './fixtures.ts'

const SCAN = 10_000
const toid = (ledger: number) => BigInt(ledger) << 32n
/** The cursor stellar-rpc returns when a scan window ends at `ledger` with fewer events than asked for. */
const windowEnd = (ledger: number) => `${(toid(ledger) | 0xffffffffn).toString().padStart(19, '0')}-4294967295`
const eventId = (ledger: number) => `${toid(ledger).toString().padStart(19, '0')}-0000000000`

/** A `fee_bps_updated` event of the escrow, shaped as the RPC returns it. */
function feeEvent(ledger: number, feeBps: number) {
  return {
    type: 'contract',
    ledger,
    ledgerClosedAt: '2026-10-14T00:00:00Z',
    transactionIndex: 1,
    operationIndex: 0,
    inSuccessfulContractCall: true,
    txHash: 'ab'.repeat(32),
    id: eventId(ledger),
    contractId: new Contract(escrow),
    topic: [xdr.ScVal.scvSymbol('fee_bps_updated')],
    value: xdr.ScVal.scvMap([new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('fee_bps'), val: xdr.ScVal.scvU32(feeBps) })]),
  }
}

/** An RPC whose `getEvents` scans 10,000 ledgers at most, from `startLedger` or after a cursor. */
function windowedRpc(latest: number, events: ReturnType<typeof feeEvent>[]) {
  const starts: number[] = []
  return {
    starts,
    async getHealth() {
      return { status: 'healthy', latestLedger: latest, oldestLedger: 1, ledgerRetentionWindow: 120_960 }
    },
    async getEvents(req: { startLedger?: number; cursor?: string; limit?: number }) {
      const start = req.cursor ? ledgerOfCursor(req.cursor) + 1 : req.startLedger!
      const end = Math.min(latest + 1, start + SCAN)
      starts.push(start)
      const found = events.filter((e) => e.ledger >= start && e.ledger < end).slice(0, req.limit)
      const cursor = found.length === req.limit ? found.at(-1)!.id : windowEnd(end - 1)
      return { events: found, cursor, latestLedger: latest, oldestLedger: 1, latestLedgerCloseTime: '0', oldestLedgerCloseTime: '0' }
    },
  }
}

describe('the indexer and the RPC scan window', () => {
  it('reads on to the latest ledger when a page ends at the scan window, not at the head', async () => {
    const rpc = windowedRpc(25_000, [feeEvent(5, 40), feeEvent(24_000, 60)])
    const ix = new EscrowIndexer({ rpcUrl: 'http://localhost:1', escrow })
    ;(ix as unknown as { server: unknown }).server = rpc
    expect(await ix.poll()).toBe(2)
    expect(ix.events.map((e) => (e.name === 'fee_bps_updated' ? e.feeBps : undefined))).toEqual([40, 60])
    expect(rpc.starts).toEqual([1, 10_001, 20_001])
    expect(ix.latestLedger).toBe(25_000)
  })

  it('caughtUp: a short page ends the read only if its cursor reached the latest ledger', () => {
    expect(caughtUp({ events: [], cursor: windowEnd(10_000), latestLedger: 25_000 }, 1_000)).toBe(false)
    expect(caughtUp({ events: [], cursor: windowEnd(25_000), latestLedger: 25_000 }, 1_000)).toBe(true)
    expect(caughtUp({ events: new Array(1_000), cursor: eventId(25_000), latestLedger: 25_000 }, 1_000)).toBe(false)
  })
})
