// What the gateway reads from and writes to the chain (a fake in unit tests).
//
// Ported from Fermata `apps/gateway/src/chain.ts` @ d7cc642 (github.com/bilgin-kocak/fermata, MIT).
// Kept: the interface's shape and the writes serialised through one relayer. Changed for Stellar:
// views by simulation (EscrowReader), `settle` and `claim_timeout` sent by the SDK's Relayer with
// their arguments encoded from the contract's own spec, and contract errors reported by name. Event
// reads moved to the indexer (fermata-stellar-sdk `EscrowIndexer`). New: the session contract's view,
// `settle_batch` and `close_session` (docs/session-escrow.md, phase 1).
import { Contract } from '@stellar/stellar-sdk'
import { Buffer } from 'buffer'
import {
  EscrowErrors,
  SessionErrors,
  closeSessionOperation,
  fromHex,
  settleBatchOperation,
  toContractVerdict,
  tokenBalance,
  type EscrowReader,
  type Hex,
  type HoldInfo,
  type Relayer,
  type ServiceInfo,
  type SessionBatch,
  type SessionInfo,
  type SessionReader,
  type Verdict,
} from 'fermata-stellar-sdk'

export type TxResult = { ok: true; txHash: Hex } | { ok: false; error: string; txHash?: Hex }

export interface GatewayChain {
  readonly network: string
  readonly networkPassphrase: string
  readonly escrow: string
  /** The session contract, when sessions are enabled. */
  readonly sessionContract?: string
  service(serviceId: Hex): Promise<ServiceInfo | undefined>
  hold(callId: Hex): Promise<HoldInfo | undefined>
  /** The latest ledger's close time: the clock `settle` and `claim_timeout` check. */
  now(): Promise<bigint>
  settle(callId: Hex, verdict: Verdict, signature: Hex): Promise<TxResult>
  claimTimeout(callId: Hex): Promise<TxResult>
  /** A token's balance of `id` (the escrow's, for reconciliation). */
  balance(token: string, id: string): Promise<bigint>
  session(sessionId: Hex): Promise<SessionInfo | undefined>
  settleBatch(batch: SessionBatch): Promise<TxResult>
  closeSession(sessionId: Hex): Promise<TxResult>
  /** The escrow's treasury (it receives the fees of sessions too). */
  treasury(): Promise<string>
}

/** A contract error by name (`WindowClosed (#107)`, `InvalidBatch (#207)`), or the message as it is. */
export function errorName(e: unknown): string {
  const message = e instanceof Error ? e.message : String(e)
  const code = /Error\(Contract, #(\d+)\)/.exec(message)?.[1]
  const errors = { ...(EscrowErrors as Record<number, { message: string }>), ...(SessionErrors as Record<number, { message: string }>) }
  const name = code ? errors[Number(code)]?.message : undefined
  return name ? `${name} (#${code})` : message.split('\n')[0]!.slice(0, 300)
}

export class SorobanGatewayChain implements GatewayChain {
  constructor(
    readonly reader: EscrowReader,
    readonly relayer: Relayer,
    readonly network: string,
    readonly sessions?: SessionReader,
  ) {}

  get sessionContract() {
    return this.sessions?.contract
  }

  async session(sessionId: Hex) {
    if (!this.sessions) throw new Error('sessions are not enabled')
    return this.sessions.session(sessionId)
  }

  private async invoke(op: Parameters<Relayer['invoke']>[0]): Promise<TxResult> {
    try {
      const res = await this.relayer.invoke(op)
      return { ok: true, txHash: res.txHash }
    } catch (e) {
      return { ok: false, error: errorName(e) }
    }
  }

  settleBatch(batch: SessionBatch) {
    if (!this.sessions) throw new Error('sessions are not enabled')
    return this.invoke(settleBatchOperation(this.sessions.contract, batch))
  }

  closeSession(sessionId: Hex) {
    if (!this.sessions) throw new Error('sessions are not enabled')
    return this.invoke(closeSessionOperation(this.sessions.contract, sessionId))
  }

  async treasury() {
    return (await this.reader.client.treasury()).result
  }

  get escrow() {
    return this.reader.escrow
  }

  get networkPassphrase() {
    return this.reader.networkPassphrase
  }

  service(serviceId: Hex) {
    return this.reader.service(serviceId)
  }

  hold(callId: Hex) {
    return this.reader.hold(callId)
  }

  now() {
    return this.reader.now()
  }

  balance(token: string, id: string) {
    return tokenBalance(this.reader.rpcUrl, this.networkPassphrase, token, id)
  }

  private async send(fn: 'settle' | 'claim_timeout', args: Record<string, unknown>): Promise<TxResult> {
    try {
      const scArgs = this.reader.client.spec.funcArgsToScVals(fn, args)
      const res = await this.relayer.invoke(new Contract(this.escrow).call(fn, ...scArgs))
      return { ok: true, txHash: res.txHash }
    } catch (e) {
      return { ok: false, error: errorName(e) }
    }
  }

  settle(callId: Hex, verdict: Verdict, signature: Hex) {
    return this.send('settle', {
      call_id: Buffer.from(fromHex(callId, 32)),
      verdict: toContractVerdict(verdict),
      signature: Buffer.from(fromHex(signature, 64)),
    })
  }

  claimTimeout(callId: Hex) {
    return this.send('claim_timeout', { call_id: Buffer.from(fromHex(callId, 32)) })
  }
}
