// The agent side of scripts/gateway-cases.sh: pays through a running gateway with every method it
// offers, waits for the timeout refunds, and checks every call against the gateway's records, the
// indexed events, an offline re-verification of its proof, and the token balances on chain.
// Prints a JSON report on stdout; progress goes to stderr.
//
// Ported in spirit from Fermata `scripts/demo/cases.ts` and `apps/gateway/test/e2e.test.ts` @ d7cc642
// (github.com/bilgin-kocak/fermata, MIT): the same three outcomes, here paid with MPP and with x402.
//
// Environment: GATEWAY_URL, FERMATA_DEPLOYMENT (deployment JSON), STELLAR_RPC_URL, STELLAR_NETWORK
// (CAIP-2), FERMATA_AGENT_SECRET, SERVICES ('{"ok":…,"e500":…,"hang":…}'), TARGET, WINDOW (seconds),
// UNPROTECTED (yes when the gateway offers Stellar's MPP Charge and x402 `exact`: they know only
// testnet's and mainnet's passphrases, so on other networks C1-C2 are left out).
import { readFileSync } from 'node:fs'
import { charge as stellarCharge } from '@stellar/mpp/charge/client'
import { Keypair } from '@stellar/stellar-sdk'
import { decodePaymentResponseHeader } from '@x402/core/http'
import type { Network } from '@x402/core/types'
import { wrapFetchWithPaymentFromConfig } from '@x402/fetch'
import { createEd25519Signer } from '@x402/stellar'
import { ExactStellarScheme } from '@x402/stellar/exact/client'
import { Receipt } from 'mppx'
import { Mppx } from 'mppx/client'
import { FermataX402Client, fermata, tokenBalance } from 'fermata-stellar-sdk'

const env = (k: string) => {
  const v = process.env[k]
  if (!v) throw new Error(`${k} is not set`)
  return v
}
const gateway = env('GATEWAY_URL')
const d = JSON.parse(readFileSync(env('FERMATA_DEPLOYMENT'), 'utf8'))
const rpcUrl = env('STELLAR_RPC_URL')
const network = env('STELLAR_NETWORK') as Network
const passphrase: string = d.network_passphrase
const escrow: string = d.escrow.contract_id
const keypair = Keypair.fromSecret(env('FERMATA_AGENT_SECRET'))
const services = JSON.parse(env('SERVICES')) as { ok: string; e500: string; hang: string }
const target = env('TARGET')
const window = Number(env('WINDOW'))
const verifier: string = d.service.verifier
const unprotectedOffered = env('UNPROTECTED') === 'yes'
const log = (m: string) => process.stderr.write(`${m}\n`)

const fermataMpp = (mode: 'sponsored' | 'direct') =>
  Mppx.create({
    methods: [fermata({ keypair, rpcUrl, network, networkPassphrase: passphrase, trustedVerifiers: [verifier], escrows: [escrow], mode })],
    polyfill: false,
  })
// Built only when used: both refuse a network they do not know.
const chargeMpp = () => Mppx.create({ methods: [stellarCharge({ keypair, rpcUrl })], polyfill: false })
const fermataX402 = wrapFetchWithPaymentFromConfig(fetch, {
  schemes: [{ network, client: new FermataX402Client({ keypair, rpcUrl, networkPassphrase: passphrase, trustedVerifiers: [verifier], escrows: [escrow] }) }],
  spendControls: { allowedAssets: true },
})
const exactX402 = () =>
  wrapFetchWithPaymentFromConfig(fetch, {
    schemes: [{ network, client: new ExactStellarScheme(createEd25519Signer(keypair.secret(), network), { url: rpcUrl }) }],
    spendControls: { allowedAssets: true },
  })

type Check = { name: string; ok: boolean; detail?: string }
type Case = {
  id: string
  pay: 'MPP fermata (sponsored)' | 'MPP fermata (direct)' | 'x402 fermata' | 'MPP stellar charge' | 'x402 exact'
  service: keyof typeof services
  expect: { http: number; outcome?: 'DELIVERED' | 'FAILED' | 'AWAITING_TIMEOUT'; final?: 'released' | 'refunded' | 'timed-out' }
  http?: number
  callId?: string
  holdTx?: string
  settleTx?: string
  outcome?: string
  checks: Check[]
}

const cases: Case[] = (
  [
    { id: 'A1', pay: 'MPP fermata (sponsored)', service: 'ok', expect: { http: 200, outcome: 'DELIVERED', final: 'released' }, checks: [] },
    { id: 'A2', pay: 'MPP fermata (direct)', service: 'e500', expect: { http: 500, outcome: 'FAILED', final: 'refunded' }, checks: [] },
    { id: 'A3', pay: 'MPP fermata (sponsored)', service: 'hang', expect: { http: 504, outcome: 'AWAITING_TIMEOUT', final: 'timed-out' }, checks: [] },
    { id: 'B1', pay: 'x402 fermata', service: 'ok', expect: { http: 200, outcome: 'DELIVERED', final: 'released' }, checks: [] },
    { id: 'B2', pay: 'x402 fermata', service: 'e500', expect: { http: 500, outcome: 'FAILED', final: 'refunded' }, checks: [] },
    { id: 'B3', pay: 'x402 fermata', service: 'hang', expect: { http: 504, outcome: 'AWAITING_TIMEOUT', final: 'timed-out' }, checks: [] },
    { id: 'C1', pay: 'MPP stellar charge', service: 'ok', expect: { http: 200 }, checks: [] },
    { id: 'C2', pay: 'x402 exact', service: 'ok', expect: { http: 200 }, checks: [] },
  ] satisfies Case[]
).filter((c) => unprotectedOffered || c.expect.final)

const check = (c: Case, name: string, ok: boolean, detail?: string) => {
  c.checks.push({ name, ok, ...(ok || !detail ? {} : { detail }) })
  log(`  ${ok ? 'ok  ' : 'FAIL'}  ${c.id} ${name}${ok || !detail ? '' : `: ${detail}`}`)
}
const api = async (path: string, init?: RequestInit) => {
  const res = await fetch(`${gateway}${path}`, init)
  return (await res.json()) as Record<string, any>
}

async function pay(c: Case) {
  const url = `${gateway}/s/${services[c.service]}${target}`
  const init = { headers: { accept: 'application/json' } }
  const res =
    c.pay === 'MPP fermata (sponsored)' ? await fermataMpp('sponsored').fetch(url, init)
    : c.pay === 'MPP fermata (direct)' ? await fermataMpp('direct').fetch(url, init)
    : c.pay === 'MPP stellar charge' ? await chargeMpp().fetch(url, init)
    : c.pay === 'x402 fermata' ? await fermataX402(url, init)
    : await exactX402()(url, init)
  c.http = res.status
  await res.arrayBuffer()
  check(c, `HTTP ${c.expect.http}`, res.status === c.expect.http, `got ${res.status}`)
  if (!c.expect.outcome) {
    check(c, 'unprotected: the vendor was paid directly', res.headers.get('x-fermata-unprotected') === 'true')
    if (c.pay === 'x402 exact') check(c, 'PAYMENT-RESPONSE: settled', decodePaymentResponseHeader(res.headers.get('payment-response') ?? '').success === true)
    return
  }
  c.callId = res.headers.get('x-fermata-call') ?? undefined
  c.holdTx = res.headers.get('x-fermata-hold-tx') ?? undefined
  if (c.pay.startsWith('MPP')) {
    const r = Receipt.fromResponse(res) as Receipt.Receipt & Record<string, any>
    c.outcome = r.outcome ?? undefined
    check(c, 'receipt names the call and its hold', r.callId === c.callId && r.holdTx === c.holdTx && !!c.holdTx, `receipt ${r.callId}/${r.holdTx}, headers ${c.callId}/${c.holdTx}`)
  } else {
    c.outcome = res.headers.get('x-fermata-outcome') ?? (res.status === 504 ? 'AWAITING_TIMEOUT' : undefined)
    const settled = decodePaymentResponseHeader(res.headers.get('payment-response') ?? '')
    check(c, 'PAYMENT-RESPONSE: the hold transaction', settled.success === true && settled.transaction === c.holdTx, `PAYMENT-RESPONSE ${settled.success}/${settled.transaction}, X-Fermata-Hold-Tx ${c.holdTx}`)
  }
  check(c, `outcome ${c.expect.outcome}`, c.outcome === c.expect.outcome, `got ${c.outcome}`)
}

const token: string = d.token.sac
const vendor: string = d.service.owner
const price = BigInt(d.service.price_per_call)
const fee = (price * BigInt(d.escrow.fee_bps)) / 10_000n
const balances = async () => ({ agent: await tokenBalance(rpcUrl, passphrase, token, keypair.publicKey()), vendor: await tokenBalance(rpcUrl, passphrase, token, vendor) })

const before = await balances()
log(`agent ${keypair.publicKey()}: ${before.agent} base units; paying through ${gateway}`)
for (const c of cases) {
  log(`${c.id} ${c.pay} → ${c.service}`)
  try {
    await pay(c)
  } catch (e) {
    check(c, 'paid', false, (e as Error).message)
  }
}

log(`waiting for the timeout refunds (window ${window} s, then the gateway's sweeper)`)
const until = Date.now() + (window + 180) * 1000
for (const c of cases.filter((x) => x.expect.final === 'timed-out' && x.callId)) {
  while (Date.now() < until && (await api(`/calls/${c.callId}`)).status !== 'timed-out') await new Promise((r) => setTimeout(r, 3000))
}

for (const c of cases.filter((x) => x.expect.final && x.callId)) {
  const record = await api(`/calls/${c.callId}`)
  c.settleTx = record.settleTx ?? record.timeoutTx
  check(c, `gateway record ${c.expect.final}`, record.status === c.expect.final, `got ${record.status}`)
  const rec = await api(`/reconcile/${c.callId}`)
  const chainStatus = { released: 'released', refunded: 'refunded', 'timed-out': 'timed_out' }[c.expect.final!]
  check(c, 'reconciles from events', rec.ok === true && rec.status === chainStatus, JSON.stringify(rec.checks?.filter((k: Check) => !k.ok) ?? rec))
  if (c.expect.outcome === 'DELIVERED' || c.expect.outcome === 'FAILED') {
    const v = await api(`/proofs/${c.callId}/verify`, { method: 'POST' })
    check(c, 'the proof re-verifies offline against the chain', v.ok === true, JSON.stringify(v.checks?.filter((k: { ok: boolean }) => !k.ok) ?? v))
  }
}

const after = await balances()
const paidEscrowed = BigInt(cases.filter((c) => c.expect.final === 'released').length) * price
const paidDirect = BigInt(cases.filter((c) => !c.expect.final).length) * price
const balanceChecks: Check[] = [
  { name: 'the agent paid exactly the released and the unprotected calls', ok: before.agent - after.agent === paidEscrowed + paidDirect, detail: `${before.agent} → ${after.agent}` },
  {
    name: 'the vendor received price − fee per release and the price per unprotected call',
    ok: after.vendor - before.vendor === paidEscrowed - fee * BigInt(cases.filter((c) => c.expect.final === 'released').length) + paidDirect,
    detail: `${before.vendor} → ${after.vendor}`,
  },
]
for (const b of balanceChecks) log(`  ${b.ok ? 'ok  ' : 'FAIL'}  ${b.name}${b.ok ? '' : `: ${b.detail}`}`)

const escrowWide = await api('/reconcile')
const escrowCheck: Check = {
  name: 'the escrow reconciles: every call, and per token its balance against the open holds and the chain',
  ok: escrowWide.ok === true && escrowWide.complete === true,
  detail: JSON.stringify({ tokens: escrowWide.tokens, failing: escrowWide.calls?.failing, complete: escrowWide.complete }),
}
log(`  ${escrowCheck.ok ? 'ok  ' : 'FAIL'}  ${escrowCheck.name}${escrowCheck.ok ? '' : `: ${escrowCheck.detail}`}`)

const failures = [...cases.flatMap((c) => c.checks), ...balanceChecks, escrowCheck].filter((k) => !k.ok).length
process.stdout.write(
  `${JSON.stringify({ gateway, escrow, network, agent: keypair.publicKey(), cases, balances: { before, after }, balanceChecks, escrowCheck, failures }, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2)}\n`,
)
process.exit(failures ? 1 : 0)
