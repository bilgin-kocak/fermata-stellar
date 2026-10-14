// Client for `fermata-attest serve` (apps/attestor).
//
// Ported from Fermata `apps/gateway/src/attestor.ts` @ d7cc642 (github.com/bilgin-kocak/fermata,
// MIT). Kept: the three results of an attestation (a verdict, no transcript, a failed binding
// check), offline re-verification and the stored presentation. Changed: the Stellar attestor's JSON
// (src/serve.rs): an Ed25519 verdict with its message and the signer's `G…` key, hex without `0x`;
// `/healthz` names the network passphrase, the escrow `C…` and the signer. New: the session routes
// (docs/session-escrow.md, phase 1).
import type { Hex, Verdict } from 'fermata-stellar-sdk'

export type AttestInput = { callId: Hex; url: string; method: string; headers: Record<string, string>; body: string }

export type ProvedResponse = {
  status: number | null
  headers?: [string, string][]
  bodyBase64?: string
  rawBase64?: string
  error?: string
}

/** The attestor's signed verdict (verify.rs `SignedVerdict`). */
export type SignedVerdict = {
  verdict: Verdict
  outcome: 'DELIVERED' | 'FAILED'
  failures: string[]
  /** The 294-byte message, hex. */
  message: Hex
  /** Ed25519 signature, hex. */
  signature: Hex
  /** The verifier's account form (`G…`) and its 32-byte key (hex). */
  signer: string
  signerKey: Hex
}

export type AttestResult =
  | { kind: 'verdict'; signed: SignedVerdict; presentationHash: Hex; response: ProvedResponse; proveMs?: number }
  | { kind: 'no-transcript'; detail: string }
  | { kind: 'rejected'; check: string; detail: string }

export type Reverified = Record<string, unknown> & {
  presentationHash: Hex
  responseHash: Hex
  requestHash: Hex | null
  originHash: Hex
  notaryKeyHash: Hex
  predicateHash: Hex | null
  outcome: 'DELIVERED' | 'FAILED' | null
  callHeader: string | null
  callHeaderMatches: boolean
}

export type AttestorHealth = { network: string; escrow: string; signer: string; signerKey: Hex; sessionContract?: string | null }

/** Call n of a session, for the attestor's session routes (src/session.rs). */
export type SessionCallInput = { sessionId: Hex; n: number; ticket: Hex; url: string; method: string; headers: Record<string, string>; body: string }

/** One call's entry in a batch, as `fermata-verdict` writes it. */
export type SessionEntry = { result: number; presentation_hash: Hex; response_hash: Hex }

export type SessionCallResult =
  /** Proved: DELIVERED or FAILED. */
  | { kind: 'entry'; n: number; chain: Hex; entry: SessionEntry; outcome: 'DELIVERED' | 'FAILED'; failures: string[]; presentationHash: Hex; response: ProvedResponse; proveMs?: number }
  /** Recorded UNANSWERED: no transcript, or a proof that did not bind. */
  | { kind: 'unanswered'; n: number; chain: Hex; detail: string; check?: string }
  /** Not recorded: out of order, a ticket that does not cover the request, a session it does not take. */
  | { kind: 'refused'; status: number; detail: string; check?: string }
  | { kind: 'unreachable'; detail: string }

/** The attestor's signed batch statement and what `settle_batch` takes with it. */
export type SignedSessionStatement = {
  statement: Record<string, unknown>
  message: Hex
  signature: Hex
  from: number
  to: number
  requestHashes: Hex[]
  entries: SessionEntry[]
  ticket: Hex
  signer: string
}

export interface Attestor {
  attest(input: AttestInput): Promise<AttestResult>
  /** Offline re-verification of the stored presentation (no key, no chain). */
  reverify(input: { callId: Hex; serviceId: Hex; predicateHash: Hex }): Promise<Reverified | { error: string; check?: string; detail?: string }>
  health(): Promise<AttestorHealth>
  presentation(callId: Hex): Promise<Uint8Array | undefined>
  /** Proves call n of a session (the attestor checks the ticket first) and records its entry. */
  sessionAttest(input: SessionCallInput): Promise<SessionCallResult>
  /** Records call n of a session UNANSWERED (its ticket checked), for a call the attestor never proved. */
  sessionUnanswered(input: SessionCallInput): Promise<SessionCallResult>
  /** The signed statement over calls `settled + 1` through `to`. */
  sessionStatement(input: { sessionId: Hex; to: number }): Promise<{ ok: true; signed: SignedSessionStatement } | { ok: false; status: number; detail: string }>
}

export class HttpAttestor implements Attestor {
  constructor(
    readonly baseUrl: string,
    readonly timeoutMs = Number(process.env.ATTEST_TIMEOUT_MS ?? 90_000),
  ) {}

  async attest(input: AttestInput): Promise<AttestResult> {
    let res: Response
    try {
      res = await fetch(`${this.baseUrl}/v1/attest`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(input),
        // Proving is serialised in the attestor; past this the call is left to its timeout refund.
        signal: AbortSignal.timeout(this.timeoutMs),
      })
    } catch (e) {
      return { kind: 'no-transcript', detail: `attestor unreachable: ${(e as Error).message}` }
    }
    const json = (await res.json().catch(() => ({}))) as Record<string, any>
    if (res.status === 200 && json.verdict) {
      return { kind: 'verdict', signed: json.verdict, presentationHash: json.presentationHash, response: json.response ?? { status: null }, proveMs: json.prove?.proveMs }
    }
    if (res.status === 422) return { kind: 'rejected', check: String(json.check), detail: String(json.detail) }
    return { kind: 'no-transcript', detail: String(json.detail ?? json.error ?? `attestor HTTP ${res.status}`) }
  }

  async reverify(input: { callId: Hex; serviceId: Hex; predicateHash: Hex }) {
    const res = await fetch(`${this.baseUrl}/v1/reverify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(input),
    })
    return (await res.json()) as Reverified | { error: string }
  }

  async health(): Promise<AttestorHealth> {
    const res = await fetch(`${this.baseUrl}/healthz`)
    if (!res.ok) throw new Error(`attestor /healthz HTTP ${res.status}`)
    return (await res.json()) as AttestorHealth
  }

  async presentation(callId: Hex) {
    const res = await fetch(`${this.baseUrl}/v1/presentations/${callId}`)
    return res.ok ? new Uint8Array(await res.arrayBuffer()) : undefined
  }

  private async sessionCall(route: 'attest' | 'unanswered', input: SessionCallInput): Promise<SessionCallResult> {
    let res: Response
    try {
      res = await fetch(`${this.baseUrl}/v1/session/${route}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(input),
        signal: AbortSignal.timeout(this.timeoutMs),
      })
    } catch (e) {
      return { kind: 'unreachable', detail: `attestor unreachable: ${(e as Error).message}` }
    }
    const json = (await res.json().catch(() => ({}))) as Record<string, any>
    const detail = String(json.detail ?? json.error ?? `attestor HTTP ${res.status}`)
    if (json.recorded) {
      return { kind: 'unanswered', n: json.recorded.n, chain: json.recorded.chain, detail, ...(json.check ? { check: String(json.check) } : {}) }
    }
    if (res.status === 200 && json.entry) {
      if (json.entry.result === 4) return { kind: 'unanswered', n: json.n, chain: json.chain, detail: 'recorded unanswered' }
      return {
        kind: 'entry',
        n: json.n,
        chain: json.chain,
        entry: json.entry,
        outcome: json.outcome,
        failures: json.failures ?? [],
        presentationHash: json.presentationHash,
        response: json.response ?? { status: null },
        proveMs: json.prove?.proveMs,
      }
    }
    return { kind: 'refused', status: res.status, detail, ...(json.check ? { check: String(json.check) } : {}) }
  }

  sessionAttest(input: SessionCallInput) {
    return this.sessionCall('attest', input)
  }

  sessionUnanswered(input: SessionCallInput) {
    return this.sessionCall('unanswered', input)
  }

  async sessionStatement(input: { sessionId: Hex; to: number }) {
    const res = await fetch(`${this.baseUrl}/v1/session/statement`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(input),
    })
    const json = (await res.json().catch(() => ({}))) as Record<string, any>
    if (res.ok) return { ok: true as const, signed: json as SignedSessionStatement }
    return { ok: false as const, status: res.status, detail: String(json.detail ?? json.error ?? `attestor HTTP ${res.status}`) }
  }
}
