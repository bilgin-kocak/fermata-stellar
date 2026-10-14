// The indexer on a deployed escrow: it reads every event since the start of the RPC's history,
// persists them, resumes, and every call it saw reconciles; so does the escrow's balance.
//
//   FERMATA_DEPLOYMENT=… pnpm sdk:test
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { EscrowIndexer, aggregateScores, reconcileCall, reconcileEscrow, tokenBalance } from '../src/index.ts'

const file = process.env.FERMATA_DEPLOYMENT
const root = new URL('../../../', import.meta.url)

describe.skipIf(!file)('the indexer on a deployed escrow (FERMATA_DEPLOYMENT)', () => {
  const d = file ? JSON.parse(readFileSync(new URL(file, root), 'utf8')) : undefined
  const rpcUrl =
    process.env.FERMATA_RPC_URL ?? (d?.network === 'local' ? 'http://localhost:8000/rpc' : 'https://soroban-testnet.stellar.org')
  const escrow: string = d?.escrow.contract_id
  const dir = mkdtempSync(join(tmpdir(), 'fermata-index-'))
  afterAll(() => rmSync(dir, { recursive: true, force: true }))

  it('indexes, persists and resumes', async () => {
    const a = new EscrowIndexer({ rpcUrl, escrow, dir, pageLimit: 7 })
    await a.load()
    const added = await a.poll()
    expect(added).toBeGreaterThan(0)
    expect(a.tokens).toContain(d.token.sac)
    expect(a.events.some((e) => e.name === 'service_registered' && e.serviceId === d.service.id)).toBe(true)

    const b = new EscrowIndexer({ rpcUrl, escrow, dir })
    await b.load()
    expect(b.events.length).toBe(a.events.length)
    expect(b.events.map((e) => e.id)).toEqual(a.events.map((e) => e.id))
    await b.poll()
    expect(new Set(b.events.map((e) => e.id)).size).toBe(b.events.length)
  })

  it('every indexed call reconciles, and so does the balance when the index covers the whole history', async () => {
    const ix = new EscrowIndexer({ rpcUrl, escrow })
    await ix.poll()
    const onchain = { [d.token.sac]: await tokenBalance(rpcUrl, d.network_passphrase, d.token.sac, escrow) }
    const r = reconcileEscrow(ix.events, escrow, onchain)
    // On failure, say which checks failed and on what (one intermittent failure, not reproduced).
    const why = (ids: readonly string[]) =>
      JSON.stringify(ids.map((id) => ({ id, failed: reconcileCall(ix.events, id, escrow).checks.filter((c) => !c.ok) })))
    expect(r.calls.failing, why(r.calls.failing)).toEqual([])
    expect(r.calls.held).toBeGreaterThan(0)
    if (ix.gaps.length === 0 && ix.events.some((e) => e.name === 'treasury_updated')) {
      // The index starts at the deployment: the balance check applies.
      const token = r.tokens.find((t) => t.token === d.token.sac)
      expect(token, JSON.stringify({ token, latestLedger: ix.latestLedger }, (_, v) => (typeof v === 'bigint' ? v.toString() : v))).toMatchObject({ ok: true })
    }
    const scores = aggregateScores(ix.events)
    expect(scores.find((s) => s.serviceId === d.service.id)?.held).toBeGreaterThan(0)
  })
})
