// Soroban RPC plumbing shared by the payment methods, the indexer and the gateway.
import { Address, FeeBumpTransaction, Transaction, rpc, scValToNative, xdr } from '@stellar/stellar-sdk'
import { toHex, type Hex } from './hex.ts'

/**
 * The all-zero account (`G` + 55 × `A`, checksum `WHF`). Read-only simulations use it as their source,
 * and a client whose transaction a sponsor rebuilds uses it as a placeholder (Stellar's MPP Charge
 * and x402 `exact` do the same).
 */
export const NULL_ACCOUNT = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF'

/** An RPC client; plain HTTP is allowed only for a local URL. */
export function rpcServer(url: string): rpc.Server {
  const local = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/.test(url)
  return new rpc.Server(url, { allowHttp: local })
}

export class SimulationError extends Error {
  constructor(readonly detail: string) {
    super(`simulation failed: ${detail}`)
    this.name = 'SimulationError'
  }
}

/** Simulates `tx`; a failed simulation throws {@link SimulationError} with the RPC's error text. */
export async function simulate(
  server: rpc.Server,
  tx: Transaction | FeeBumpTransaction,
  authMode?: rpc.Api.SimulationAuthMode,
): Promise<rpc.Api.SimulateTransactionSuccessResponse> {
  const sim = await server.simulateTransaction(tx, undefined, authMode)
  if (rpc.Api.isSimulationError(sim)) throw new SimulationError(sim.error)
  if (rpc.Api.isSimulationRestore(sim)) throw new SimulationError('archived entries must be restored first')
  return sim
}

/**
 * Waits for a submitted transaction: resolves with its successful result, throws when it failed or
 * was not seen within `timeoutMs`.
 */
export async function waitForTransaction(
  server: rpc.Server,
  hash: string,
  { timeoutMs = 60_000, intervalMs = 1_000 }: { timeoutMs?: number; intervalMs?: number } = {},
): Promise<rpc.Api.GetSuccessfulTransactionResponse> {
  const until = Date.now() + timeoutMs
  for (;;) {
    const res = await server.getTransaction(hash)
    if (res.status === rpc.Api.GetTransactionStatus.SUCCESS) return res
    if (res.status === rpc.Api.GetTransactionStatus.FAILED) {
      throw new Error(`transaction ${hash} failed: ${res.resultXdr.result().switch().name}`)
    }
    if (Date.now() >= until) throw new Error(`transaction ${hash} not seen after ${timeoutMs} ms`)
    await new Promise((r) => setTimeout(r, intervalMs))
  }
}

/** A transaction the network did not accept; `retryable` when rebuilding it with a fresh sequence number may succeed. */
export class SubmitError extends Error {
  constructor(
    message: string,
    readonly retryable: boolean,
  ) {
    super(message)
    this.name = 'SubmitError'
  }
}

/** Sends a signed transaction and waits for it. */
export async function sendAndWait(
  server: rpc.Server,
  tx: Transaction | FeeBumpTransaction,
  opts?: { timeoutMs?: number },
): Promise<rpc.Api.GetSuccessfulTransactionResponse> {
  const sent = await server.sendTransaction(tx)
  if (sent.status === 'ERROR') {
    const code = sent.errorResult?.result().switch().name ?? 'unknown error'
    throw new SubmitError(`transaction rejected: ${code}`, code === 'txBadSeq')
  }
  // One pending transaction per source account: another one from this account is in the queue.
  if (sent.status === 'TRY_AGAIN_LATER') throw new SubmitError('transaction not accepted (TRY_AGAIN_LATER)', true)
  return waitForTransaction(server, sent.hash, opts)
}

/**
 * Builds, signs and sends a transaction from an account, rebuilding it with the account's current
 * sequence number when the network answers TRY_AGAIN_LATER or a bad sequence (another transaction
 * from the same account got in first), up to `attempts` times.
 */
export async function submitWithRetries(
  server: rpc.Server,
  build: () => Promise<Transaction>,
  opts: { attempts?: number; timeoutMs?: number } = {},
): Promise<rpc.Api.GetSuccessfulTransactionResponse> {
  const attempts = opts.attempts ?? 5
  for (let i = 1; ; i++) {
    try {
      return await sendAndWait(server, await build(), opts)
    } catch (e) {
      if (!(e instanceof SubmitError) || !e.retryable || i >= attempts) throw e
      await new Promise((r) => setTimeout(r, 1_000 * i))
    }
  }
}

// ----------------------------------------------------------------------------------- ScVal reading

export function scAddress(v: xdr.ScVal): string {
  return Address.fromScVal(v).toString()
}

export function scBytes(v: xdr.ScVal): Uint8Array {
  if (v.switch().value !== xdr.ScValType.scvBytes().value) throw new Error(`expected bytes, got ${v.switch().name}`)
  return new Uint8Array(v.bytes())
}

export function scHex32(v: xdr.ScVal): Hex {
  const b = scBytes(v)
  if (b.length !== 32) throw new Error(`expected 32 bytes, got ${b.length}`)
  return toHex(b)
}

export function scBigint(v: xdr.ScVal): bigint {
  const n = scValToNative(v) as unknown
  if (typeof n === 'bigint') return n
  if (typeof n === 'number' && Number.isInteger(n)) return BigInt(n)
  throw new Error(`expected an integer, got ${v.switch().name}`)
}

export function scSymbol(v: xdr.ScVal): string | undefined {
  return v.switch().value === xdr.ScValType.scvSymbol().value ? v.sym().toString() : undefined
}

/** The fields of an ScMap keyed by symbol, as `#[contracttype]` structs and event data are encoded. */
export function scFields(v: xdr.ScVal): Map<string, xdr.ScVal> {
  if (v.switch().value !== xdr.ScValType.scvMap().value) throw new Error(`expected a map, got ${v.switch().name}`)
  const out = new Map<string, xdr.ScVal>()
  for (const e of v.map() ?? []) {
    const k = scSymbol(e.key())
    if (k === undefined) throw new Error('map key is not a symbol')
    out.set(k, e.val())
  }
  return out
}

export function field(fields: Map<string, xdr.ScVal>, name: string): xdr.ScVal {
  const v = fields.get(name)
  if (!v) throw new Error(`missing field ${name}`)
  return v
}

/** A contract id (`C…`) from a contract event's `contractId` hash. */
export function contractOf(event: xdr.ContractEvent): string | undefined {
  const id = event.contractId()
  return id ? Address.contract(id as unknown as Buffer).toString() : undefined
}
