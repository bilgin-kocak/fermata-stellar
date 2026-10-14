// A Stellar account that submits invocations and pays their fees: the gateway's relayer. It sends
// `settle` and `claim_timeout`, which anyone may call, and the agents' sponsored holds. Like
// Fermata's serialized wallet writes (apps/gateway/src/chain.ts @ d7cc642), one invocation at a time,
// because each spends the account's next sequence number.
import { Keypair, Operation, TransactionBuilder, rpc, xdr } from '@stellar/stellar-sdk'
import { simulate, submitWithRetries } from './soroban.ts'

export type Invocation = { func: xdr.HostFunction; auth: xdr.SorobanAuthorizationEntry[] }

export type RelayerOptions = {
  /** Highest total fee (inclusion plus resources) the relayer pays for one transaction, in stroops. Default 10,000,000 (1 XLM). */
  maxFeeStroops?: number
  /** Inclusion fee bid, in stroops. Default 100. */
  inclusionFeeStroops?: number
  timeoutMs?: number
}

export class Relayer {
  private queue: Promise<unknown> = Promise.resolve()

  constructor(
    readonly keypair: Keypair,
    readonly server: rpc.Server,
    readonly networkPassphrase: string,
    readonly opts: RelayerOptions = {},
  ) {}

  get address(): string {
    return this.keypair.publicKey()
  }

  /**
   * Submits one invocation from the relayer's account and waits for it. The invocation is simulated
   * first, in enforce mode when it carries someone's signed authorization, so the relayer does not
   * pay for a transaction the network would reject; `check` can inspect the simulation (its events)
   * before anything is signed.
   */
  invoke(
    invocation: Invocation | xdr.Operation,
    check?: (sim: rpc.Api.SimulateTransactionSuccessResponse) => void,
  ): Promise<rpc.Api.GetSuccessfulTransactionResponse> {
    const run = () => this.invokeNow(invocation, check)
    const result = this.queue.then(run, run)
    this.queue = result.catch(() => undefined)
    return result
  }

  private async invokeNow(
    invocation: Invocation | xdr.Operation,
    check?: (sim: rpc.Api.SimulateTransactionSuccessResponse) => void,
  ): Promise<rpc.Api.GetSuccessfulTransactionResponse> {
    const op =
      invocation instanceof xdr.Operation ? invocation : Operation.invokeHostFunction({ func: invocation.func, auth: invocation.auth })
    const hasAuth = !(invocation instanceof xdr.Operation) && invocation.auth.length > 0
    const fee = String(this.opts.inclusionFeeStroops ?? 100)
    const max = this.opts.maxFeeStroops ?? 10_000_000
    const build = async () => {
      const account = await this.server.getAccount(this.address)
      const tx = new TransactionBuilder(account, { fee, networkPassphrase: this.networkPassphrase })
        .addOperation(op)
        .setTimeout(60)
        .build()
      const sim = await simulate(this.server, tx, hasAuth ? 'enforce' : undefined)
      check?.(sim)
      const prepared = rpc.assembleTransaction(tx, sim).build()
      if (Number(prepared.fee) > max) throw new Error(`fee ${prepared.fee} stroops is above the relayer's limit of ${max}`)
      prepared.sign(this.keypair)
      return prepared
    }
    // Another process may use the same account: rebuild on a sequence clash.
    return submitWithRetries(this.server, build, { timeoutMs: this.opts.timeoutMs })
  }
}
