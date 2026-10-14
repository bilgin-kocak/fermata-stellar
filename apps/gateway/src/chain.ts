// What the gateway reads from and writes to the chain (a fake in unit tests).
//
// Ported from Fermata `apps/gateway/src/chain.ts` @ d7cc642 (github.com/bilgin-kocak/fermata, MIT).
// Kept: the interface's shape and the writes serialised through one relayer. Changed for Stellar:
// views by simulation (EscrowReader), `settle` and `claim_timeout` sent by the SDK's Relayer with
// their arguments encoded from the contract's own spec, and contract errors reported by name. Event
// reads moved to the indexer (fermata-stellar-sdk `EscrowIndexer`).
import { Contract } from '@stellar/stellar-sdk'
import { Buffer } from 'buffer'
import {
  EscrowErrors,
  fromHex,
  toContractVerdict,
  tokenBalance,
  type EscrowReader,
  type Hex,
  type HoldInfo,
  type Relayer,
  type ServiceInfo,
  type Verdict,
} from 'fermata-stellar-sdk'

export type TxResult = { ok: true; txHash: Hex } | { ok: false; error: string; txHash?: Hex }

export interface GatewayChain {
  readonly network: string
  readonly networkPassphrase: string
  readonly escrow: string
  service(serviceId: Hex): Promise<ServiceInfo | undefined>
  hold(callId: Hex): Promise<HoldInfo | undefined>
  /** The latest ledger's close time: the clock `settle` and `claim_timeout` check. */
  now(): Promise<bigint>
  settle(callId: Hex, verdict: Verdict, signature: Hex): Promise<TxResult>
  claimTimeout(callId: Hex): Promise<TxResult>
  /** A token's balance of `id` (the escrow's, for reconciliation). */
  balance(token: string, id: string): Promise<bigint>
}

/** A contract error by name (`WindowClosed (#107)`), or the message as it is. */
export function errorName(e: unknown): string {
  const message = e instanceof Error ? e.message : String(e)
  const code = /Error\(Contract, #(\d+)\)/.exec(message)?.[1]
  const name = code ? (EscrowErrors as Record<number, { message: string }>)[Number(code)]?.message : undefined
  return name ? `${name} (#${code})` : message.split('\n')[0]!.slice(0, 300)
}

export class SorobanGatewayChain implements GatewayChain {
  constructor(
    readonly reader: EscrowReader,
    readonly relayer: Relayer,
    readonly network: string,
  ) {}

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
