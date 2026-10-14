// Client for `fermata-attest serve` (apps/attestor).
//
// Ported from Fermata `apps/gateway/src/attestor.ts` @ d7cc642 (github.com/bilgin-kocak/fermata,
// MIT). Kept: the three results of an attestation (a verdict, no transcript, a failed binding
// check), offline re-verification and the stored presentation. Changed: the Stellar attestor's JSON
// (src/serve.rs): an Ed25519 verdict with its message and the signer's `G…` key, hex without `0x`;
// `/healthz` names the network passphrase, the escrow `C…` and the signer.
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

export type AttestorHealth = { network: string; escrow: string; signer: string; signerKey: Hex }

export interface Attestor {
  attest(input: AttestInput): Promise<AttestResult>
  /** Offline re-verification of the stored presentation (no key, no chain). */
  reverify(input: { callId: Hex; serviceId: Hex; predicateHash: Hex }): Promise<Reverified | { error: string; check?: string; detail?: string }>
  health(): Promise<AttestorHealth>
  presentation(callId: Hex): Promise<Uint8Array | undefined>
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
}
