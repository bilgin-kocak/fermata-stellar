// The gateway's read API, as the dashboard uses it.
//
// Ported from Fermata apps/dashboard/src/api.ts @ d7cc642 (github.com/bilgin-kocak/fermata, MIT).
// Changed for Stellar: the network and the indexer in /info; how a call was paid; escrow events
// read from the gateway's index (held, released, refunded, timed_out, by ledger); reconciliation
// as checks over the escrow's events and the token's transfers. The demo and onboarding calls are
// not ported (the gateway does not serve them).
export type Info = {
  network: string
  networkPassphrase: string
  escrow: string
  explorer: string | null
  services: number
  verifier: string
  indexer: { latestLedger: number; events: number; gaps: { from: number; to: number }[] } | null
}

export type CallStatus = 'holding' | 'held' | 'released' | 'refunded' | 'settle-pending' | 'awaiting-timeout' | 'timed-out' | 'closed'

export type Call = {
  callId: string
  serviceId: string
  method: string
  target: string
  requestHash: string
  paidWith: 'mpp' | 'x402'
  sponsored: boolean
  holdTx?: string
  agent?: string
  deadline: string
  status: CallStatus
  outcome?: 'DELIVERED' | 'FAILED'
  failures?: string[]
  verdict?: Record<string, unknown>
  signature?: string
  signer?: string
  presentationHash?: string
  settleTx?: string
  timeoutTx?: string
  proveMs?: number
  error?: string
  createdAt: string
  updatedAt: string
}

/** One indexed escrow event (amounts as decimal strings). */
export type EscrowEvent = {
  name: 'held' | 'released' | 'refunded' | 'timed_out'
  callId: string
  serviceId: string
  amount: string
  fee?: string
  presentationHash?: string
  agent?: string
  payout?: string
  ledger: number
  txHash: string
  id: string
  ledgerClosedAt?: string
}

export type Service = {
  serviceId: string
  endpoint: string
  examplePath: string | null
  summary: string | null
  upstream: string
  price: string
  token: string
  settlementWindow: number
  verifier: string
  escrow: string
  network: string
  pay: { mpp: string[]; x402: string[] }
  unprotected: { recipient: string; amount?: string } | null
}

export type VendorScore = {
  serviceId: string
  known: boolean
  upstream: string | null
  summary: string | null
  held: number
  released: number
  provenFailures: number
  timeouts: number
  open: number
  settled: number
  deliveryRate: number | null
  score: number
  distinctAgents: number
  fewCalls: boolean
}
export type Scores = { escrow: string; network: string; indexedTo: number | null; method: string; caveats: string[]; scores: VendorScore[] }

export type Movement = { txHash: string; token: string; from: string; to: string; amount: string }
export type Reconciliation = {
  callId: string
  status: 'unknown' | 'held' | 'released' | 'refunded' | 'timed_out'
  token?: string
  amount?: string
  movements: Movement[]
  checks: { name: string; ok: boolean; detail?: string }[]
  record: { status: CallStatus; holdTx: string | null; settleTx: string | null } | null
  recordMatches: boolean
  ok: boolean
}

export type Check = { name: string; recomputed: string | null; onchain: string | null; ok: boolean }
export type Reverify = {
  callId: string
  ok: boolean
  checks: Check[]
  transcript: { request: string; response: string }
  notaryKey: string
  sessionTime: number
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, init)
  const body = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error((body as { error?: string; detail?: string }).detail ?? (body as { error?: string }).error ?? `HTTP ${res.status}`)
  return body as T
}

export const api = {
  info: () => json<Info>('/info'),
  calls: () => json<Call[]>('/calls'),
  events: () => json<EscrowEvent[]>('/events?since=0'),
  services: () => json<Service[]>('/services'),
  scores: () => json<Scores>('/scores'),
  reconcile: (callId: string) => json<Reconciliation>(`/reconcile/${callId}`),
  reverify: (callId: string) => json<Reverify>(`/proofs/${callId}/verify`, { method: 'POST' }),
  proofUrl: (callId: string) => `/proofs/${callId}`,
}
