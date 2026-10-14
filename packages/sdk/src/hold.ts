// Holding a call's price in the escrow: the agent's side and the sponsor's side.
//
// `hold(agent, call_id, service_id, request_hash)` needs the agent's authorization, and that
// authorization covers the token transfer inside it with its exact amount. So an agent can sign
// only the authorization and let someone else submit the transaction and pay its fee ("pull" in
// Stellar's MPP Charge, the sponsored flow of x402 `exact`), or submit the transaction itself
// ("push"). The sponsored flow follows Stellar's MPP Charge (stellar/stellar-mpp-sdk @ 90394ec, MIT:
// `charge/client/Charge.ts`, `charge/server/Charge.ts`, `shared/verify-auth.ts`): the client builds
// the call with the all-zero account as source and signs only its authorization entry; the sponsor
// checks the entry, rebuilds the transaction from its own account, simulates it in enforce mode and
// checks its events before it pays for it.
import {
  Account,
  Address,
  Contract,
  Keypair,
  Operation,
  StrKey,
  Transaction,
  TransactionBuilder,
  authorizeEntry,
  buildAuthorizationEntryPreimage,
  hash,
  rpc,
  scValToNative,
  xdr,
} from '@stellar/stellar-sdk'
import { Buffer } from 'buffer'
import { submitThroughChannels, type ChannelsConfig } from './channels.ts'
import { decodeEscrowEvent, decodeTransfer, escrowEventsOf, type Held } from './events.ts'
import { fromHex, type Hex } from './hex.ts'
import type { Relayer } from './relayer.ts'
import { NULL_ACCOUNT, contractOf, scAddress, scBigint, scHex32, sendAndWait, simulate, waitForTransaction } from './soroban.ts'

/** A call to hold: which escrow, which call id, for which service and request. */
export type HoldCall = { escrow: string; callId: Hex; serviceId: Hex; requestHash: Hex }
/** A call and what holding it moves: the service's token and price. */
export type HoldTerms = HoldCall & { token: string; amount: bigint }

/** Seconds per ledger assumed when an expiry in seconds becomes a ledger number (as Stellar's MPP Charge does). */
export const LEDGER_SECONDS = 5
/** Ledgers of tolerance on the sponsor's upper bound for an authorization's expiry. */
export const EXPIRY_SKEW_LEDGERS = 10

const scvBytes32 = (h: Hex) => xdr.ScVal.scvBytes(Buffer.from(fromHex(h, 32)))
const same = (a: string, b: string) => a.toLowerCase().replace(/^0x/, '') === b.toLowerCase().replace(/^0x/, '')

/** The `hold` invocation of `agent` for `call`. */
export function holdOperation(agent: string, call: HoldCall): xdr.Operation {
  return new Contract(call.escrow).call(
    'hold',
    new Address(agent).toScVal(),
    scvBytes32(call.callId),
    scvBytes32(call.serviceId),
    scvBytes32(call.requestHash),
  )
}

function contractCall(inv: xdr.SorobanAuthorizedInvocation): xdr.InvokeContractArgs | undefined {
  const fn = inv.function()
  if (fn.switch().value !== xdr.SorobanAuthorizedFunctionType.sorobanAuthorizedFunctionTypeContractFn().value) {
    return undefined
  }
  return fn.contractFn()
}

/**
 * Why an authorized invocation tree is not exactly `escrow.hold(agent, terms)` with one child, the
 * token transfer of the price from the agent to the escrow, and nothing else; undefined when it is.
 * Signing anything more would let a hostile token or escrow move other funds.
 */
export function holdAuthorizationProblem(inv: xdr.SorobanAuthorizedInvocation, agent: string, t: HoldTerms): string | undefined {
  try {
    const root = contractCall(inv)
    if (!root) return 'the authorization is not a contract call'
    if (Address.fromScAddress(root.contractAddress()).toString() !== t.escrow) return 'the authorization calls another contract'
    if (root.functionName().toString() !== 'hold') return 'the authorization is not a hold'
    const a = root.args()
    if (a.length !== 4) return 'the hold has the wrong number of arguments'
    if (scAddress(a[0]!) !== agent) return 'the hold is for another agent'
    if (!same(scHex32(a[1]!), t.callId)) return 'the hold is for another call id'
    if (!same(scHex32(a[2]!), t.serviceId)) return 'the hold is for another service'
    if (!same(scHex32(a[3]!), t.requestHash)) return 'the hold is for another request'
    const subs = inv.subInvocations()
    if (subs.length !== 1) return `the hold authorizes ${subs.length} inner calls, not one token transfer`
    const sub = subs[0]!
    if (sub.subInvocations().length > 0) return 'the token transfer authorizes further calls'
    const tr = contractCall(sub)
    if (!tr || Address.fromScAddress(tr.contractAddress()).toString() !== t.token || tr.functionName().toString() !== 'transfer') {
      return "the inner authorization is not a transfer of the service's token"
    }
    const ta = tr.args()
    if (ta.length !== 3 || scAddress(ta[0]!) !== agent || scAddress(ta[1]!) !== t.escrow || scBigint(ta[2]!) !== t.amount) {
      return 'the transfer is not the price, from the agent to the escrow'
    }
    return undefined
  } catch (e) {
    return `the authorization cannot be read: ${(e as Error).message}`
  }
}

/** The address credentials of an entry: the legacy arm or CAP-71's V2 arm; undefined for any other. */
export function addressCredentials(c: xdr.SorobanCredentials): xdr.SorobanAddressCredentials | undefined {
  switch (c.switch().value) {
    case xdr.SorobanCredentialsType.sorobanCredentialsAddress().value:
      return c.address()
    case xdr.SorobanCredentialsType.sorobanCredentialsAddressV2().value:
      return c.addressV2()
    default:
      return undefined
  }
}

/**
 * Checks the signature of an account's authorization entry against the payload the network checks
 * (the preimage `authorizeEntry` signs), with exactly one signature by that account. Throws if not.
 */
export function verifyEntrySignature(entry: xdr.SorobanAuthorizationEntry, networkPassphrase: string): void {
  const cred = addressCredentials(entry.credentials())
  if (!cred) throw new Error('the authorization does not use address credentials')
  if (cred.address().switch().value !== xdr.ScAddressType.scAddressTypeAccount().value) {
    throw new Error('the authorizer is not an account')
  }
  const signer = Address.fromScAddress(cred.address()).toString()
  const payload = hash(buildAuthorizationEntryPreimage(entry, cred.signatureExpirationLedger(), networkPassphrase).toXDR())
  const sig = cred.signature()
  if (sig.switch().value !== xdr.ScValType.scvVec().value || (sig.vec() ?? []).length !== 1) {
    throw new Error('the authorization must carry exactly one signature')
  }
  const [one] = scValToNative(sig) as { public_key?: Uint8Array; signature?: Uint8Array }[]
  if (!(one?.public_key instanceof Uint8Array) || one.public_key.length !== 32 || !(one.signature instanceof Uint8Array) || one.signature.length !== 64) {
    throw new Error('the signature is malformed')
  }
  if (StrKey.encodeEd25519PublicKey(Buffer.from(one.public_key)) !== signer) throw new Error('the authorization is signed by another key')
  if (!Keypair.fromPublicKey(signer).verify(payload, Buffer.from(one.signature))) throw new Error('the authorization signature is invalid')
}

// ------------------------------------------------------------------------------------ agent side

/**
 * Agent side, sponsored ("pull"): builds the hold with the all-zero account as source, simulates it
 * to record the authorization it needs, checks that the authorization is exactly this hold and its
 * transfer, and signs it so that it expires after about `validForSeconds`. Returns the transaction
 * (base64 XDR) for the sponsor, who rebuilds it from its own account; the agent pays no fee.
 */
export async function signSponsoredHold(opts: {
  server: rpc.Server
  networkPassphrase: string
  keypair: Keypair
  terms: HoldTerms
  validForSeconds: number
}): Promise<{ transaction: string; validUntilLedger: number }> {
  const { server, networkPassphrase, keypair, terms } = opts
  const agent = keypair.publicKey()
  const tx = new TransactionBuilder(new Account(NULL_ACCOUNT, '0'), { fee: '100', networkPassphrase })
    .addOperation(holdOperation(agent, terms))
    .setTimeout(opts.validForSeconds)
    .build()
  const prepared = rpc.assembleTransaction(tx, await simulate(server, tx)).build()
  const envelope = prepared.toEnvelope()
  const entries = envelope.v1().tx().operations()[0]!.body().invokeHostFunctionOp().auth()
  if (entries.length !== 1) throw new Error(`the hold needs ${entries.length} authorizations; expected only the agent's`)
  const cred = addressCredentials(entries[0]!.credentials())
  if (!cred || Address.fromScAddress(cred.address()).toString() !== agent) throw new Error("the hold's authorization is not the agent's")
  const problem = holdAuthorizationProblem(entries[0]!.rootInvocation(), agent, terms)
  if (problem) throw new Error(`refusing to sign: ${problem}`)
  const validUntilLedger = (await server.getLatestLedger()).sequence + Math.ceil(opts.validForSeconds / LEDGER_SECONDS)
  entries[0] = await authorizeEntry(entries[0]!, keypair, validUntilLedger, networkPassphrase)
  return { transaction: envelope.toXDR('base64'), validUntilLedger }
}

/**
 * Agent side, unsponsored ("push"): builds, checks, signs and submits the hold from the agent's own
 * account (the agent pays the fee) and waits for it. Returns the transaction hash.
 */
export async function submitOwnHold(opts: {
  server: rpc.Server
  networkPassphrase: string
  keypair: Keypair
  terms: HoldTerms
  timeoutMs?: number
}): Promise<{ hash: Hex; ledger: number }> {
  const { server, networkPassphrase, keypair, terms } = opts
  const agent = keypair.publicKey()
  const account = await server.getAccount(agent)
  const tx = new TransactionBuilder(account, { fee: '100', networkPassphrase })
    .addOperation(holdOperation(agent, terms))
    .setTimeout(60)
    .build()
  const prepared = rpc.assembleTransaction(tx, await simulate(server, tx)).build()
  // The envelope signature authorizes every source-account entry, so check the tree first.
  for (const entry of prepared.toEnvelope().v1().tx().operations()[0]!.body().invokeHostFunctionOp().auth()) {
    const problem = holdAuthorizationProblem(entry.rootInvocation(), agent, terms)
    if (problem) throw new Error(`refusing to sign: ${problem}`)
  }
  prepared.sign(keypair)
  const res = await sendAndWait(server, prepared, { timeoutMs: opts.timeoutMs })
  return { hash: res.txHash, ledger: res.ledger }
}

// ---------------------------------------------------------------------------------- sponsor side

export type SponsoredHold = {
  agent: string
  func: xdr.HostFunction
  auth: xdr.SorobanAuthorizationEntry[]
  validUntilLedger: number
}

/**
 * Sponsor side: parses an agent's sponsored hold and checks it before anything is simulated or paid.
 * - One `invokeHostFunction` operation calling `hold` on this escrow for exactly these terms, with
 *   the all-zero account as source and no operation source.
 * - One authorization entry, the agent's, with address credentials and exactly one valid signature;
 *   its tree is the hold and its token transfer, nothing else.
 * - Its expiry lies after `latestLedger` and no later than `maxLedger`.
 * - None of `sponsors` (the accounts that would pay) is the agent.
 */
export function checkSponsoredHold(opts: {
  transaction: string
  networkPassphrase: string
  terms: HoldTerms
  latestLedger: number
  maxLedger: number
  sponsors: readonly string[]
}): SponsoredHold {
  const { networkPassphrase, terms } = opts
  let tx: Transaction
  try {
    const parsed = TransactionBuilder.fromXDR(opts.transaction, networkPassphrase)
    if (!(parsed instanceof Transaction)) throw new Error('a fee-bump transaction')
    tx = parsed
  } catch (e) {
    throw new Error(`the hold transaction cannot be read: ${(e as Error).message}`)
  }
  if (tx.source !== NULL_ACCOUNT) throw new Error('a sponsored hold must use the all-zero account as its source')
  if (tx.operations.length !== 1) throw new Error('the hold transaction must have exactly one operation')
  const op = tx.toEnvelope().v1().tx().operations()[0]!
  if (op.sourceAccount()) throw new Error('the hold operation must not name a source account')
  if (op.body().switch().value !== xdr.OperationType.invokeHostFunction().value) throw new Error('the operation is not a contract call')
  const invoke = op.body().invokeHostFunctionOp()
  const func = invoke.hostFunction()
  if (func.switch().value !== xdr.HostFunctionType.hostFunctionTypeInvokeContract().value) {
    throw new Error('the operation is not a contract call')
  }
  const call = func.invokeContract()
  if (Address.fromScAddress(call.contractAddress()).toString() !== terms.escrow) throw new Error('the hold calls another contract')
  if (call.functionName().toString() !== 'hold' || call.args().length !== 4) throw new Error('the operation is not a hold')
  const agent = scAddress(call.args()[0]!)
  if (!StrKey.isValidEd25519PublicKey(agent)) throw new Error('a sponsored hold must be from an account (G…)')
  if (opts.sponsors.includes(agent)) throw new Error("the sponsor's own account cannot be the agent")

  const auth = invoke.auth()
  if (auth.length !== 1) throw new Error('the hold must carry exactly one authorization, the agent’s')
  const entry = auth[0]!
  const cred = addressCredentials(entry.credentials())
  if (!cred) throw new Error('the authorization must use address credentials')
  if (Address.fromScAddress(cred.address()).toString() !== agent) throw new Error('the authorization is not the agent’s')
  const problem = holdAuthorizationProblem(entry.rootInvocation(), agent, terms)
  if (problem) throw new Error(problem)
  // The function the transaction invokes must be the one the agent authorized.
  const authorized = contractCall(entry.rootInvocation())!
  if (!authorized.toXDR().equals(call.toXDR())) throw new Error('the transaction invokes something other than what the agent authorized')
  const expiry = cred.signatureExpirationLedger()
  if (expiry <= opts.latestLedger) throw new Error('the authorization has expired')
  if (expiry > opts.maxLedger) throw new Error(`the authorization stays valid until ledger ${expiry}, beyond ${opts.maxLedger}`)
  verifyEntrySignature(entry, networkPassphrase)
  return { agent, func, auth: [entry], validUntilLedger: expiry }
}

/**
 * Why a simulation (or a transaction's events) of a hold does not show exactly the expected money
 * movement: one `held` event for this call and one transfer of the price from the agent to the
 * escrow, and no other transfer of any token. Undefined when it does.
 */
export function holdEventsProblem(
  events: readonly { contract: string; topics: xdr.ScVal[]; value: xdr.ScVal }[],
  agent: string,
  t: HoldTerms,
): string | undefined {
  let held: Held | undefined
  const transfers: { token: string; from: string; to: string; amount: bigint }[] = []
  for (const e of events) {
    try {
      if (e.contract === t.escrow) {
        const d = decodeEscrowEvent(e.topics, e.value)
        if (d?.name === 'held') {
          if (held) return 'more than one held event'
          held = d
        }
        continue
      }
      const tr = decodeTransfer(e.contract, e.topics, e.value)
      if (tr) transfers.push(tr)
    } catch (err) {
      return `an event cannot be read: ${(err as Error).message}`
    }
  }
  if (!held) return 'no held event'
  if (!same(held.callId, t.callId) || !same(held.serviceId, t.serviceId) || !same(held.requestHash, t.requestHash)) {
    return 'the held event is for other terms'
  }
  if (held.agent !== agent || held.amount !== t.amount) return 'the held event is for another agent or amount'
  if (transfers.length !== 1) return `${transfers.length} token transfers instead of one`
  const [tr] = transfers
  if (tr!.token !== t.token || tr!.from !== agent || tr!.to !== t.escrow || tr!.amount !== t.amount) {
    return 'the transfer is not the price, from the agent to the escrow'
  }
  return undefined
}

/** The contract events of a simulation, as {@link holdEventsProblem} reads them. */
export function simulationEvents(sim: rpc.Api.SimulateTransactionSuccessResponse) {
  const out: { contract: string; topics: xdr.ScVal[]; value: xdr.ScVal }[] = []
  for (const d of sim.events ?? []) {
    const e = d.event()
    const contract = contractOf(e)
    if (!contract || e.type().name !== 'contract' || !d.inSuccessfulContractCall()) continue
    out.push({ contract, topics: e.body().v0().topics(), value: e.body().v0().data() })
  }
  return out
}

/**
 * Sponsor side: simulates a checked hold in enforce mode (the agent's signature and nonce are
 * checked against the ledger) from the all-zero account, and checks its events.
 */
export async function simulateSponsoredHold(opts: {
  server: rpc.Server
  networkPassphrase: string
  hold: SponsoredHold
  terms: HoldTerms
}): Promise<rpc.Api.SimulateTransactionSuccessResponse> {
  const { server, networkPassphrase, hold, terms } = opts
  const tx = new TransactionBuilder(new Account(NULL_ACCOUNT, '0'), { fee: '100', networkPassphrase })
    .addOperation(Operation.invokeHostFunction({ func: hold.func, auth: hold.auth }))
    .setTimeout(60)
    .build()
  const sim = await simulate(server, tx, 'enforce')
  const problem = holdEventsProblem(simulationEvents(sim), hold.agent, terms)
  if (problem) throw new Error(`the hold would not do what it says: ${problem}`)
  return sim
}

/**
 * Checks a submitted hold transaction: it succeeded and holds exactly these terms (push mode, or
 * after a sponsor submitted it). Returns the `held` event.
 */
export function checkHoldTransaction(tx: rpc.Api.GetSuccessfulTransactionResponse, t: HoldCall & { amount: bigint }): Held {
  const held = escrowEventsOf(tx, t.escrow).find((e): e is Held => e.name === 'held' && same(e.callId, t.callId))
  if (!held) throw new Error('the transaction holds no money for this call')
  if (!same(held.serviceId, t.serviceId)) throw new Error('the hold is for another service')
  if (!same(held.requestHash, t.requestHash)) throw new Error('the hold is for another request')
  if (held.amount !== t.amount) throw new Error('the held amount differs from the price')
  return held
}

/**
 * Sponsor side: submits a checked hold and waits for it. Through OpenZeppelin's Channels service
 * when `channels` is set (it pays the fee), else from the `relayer` account. Either way the hold is
 * first simulated in enforce mode and its events checked, and the landed transaction is checked
 * again. Returns the transaction hash and the `held` event.
 */
export async function submitSponsoredHold(opts: {
  server: rpc.Server
  networkPassphrase: string
  hold: SponsoredHold
  terms: HoldTerms
  relayer?: Relayer
  channels?: ChannelsConfig
  timeoutMs?: number
}): Promise<{ hash: Hex; ledger: number; held: Held; via: 'channels' | 'relayer' }> {
  const { server, hold, terms } = opts
  let tx: rpc.Api.GetSuccessfulTransactionResponse
  let via: 'channels' | 'relayer'
  if (opts.channels) {
    await simulateSponsoredHold(opts)
    const res = await submitThroughChannels(
      opts.channels,
      hold.func.toXDR('base64'),
      hold.auth.map((a) => a.toXDR('base64')),
    )
    if (!res.hash) throw new Error(`Channels accepted the hold but returned no transaction hash (status ${res.status})`)
    tx = await waitForTransaction(server, res.hash, { timeoutMs: opts.timeoutMs })
    via = 'channels'
  } else if (opts.relayer) {
    tx = await opts.relayer.invoke({ func: hold.func, auth: hold.auth }, (sim) => {
      const problem = holdEventsProblem(simulationEvents(sim), hold.agent, terms)
      if (problem) throw new Error(`the hold would not do what it says: ${problem}`)
    })
    via = 'relayer'
  } else {
    throw new Error('no way to submit a sponsored hold: set a relayer or Channels')
  }
  const held = checkHoldTransaction(tx, terms)
  if (held.agent !== hold.agent) throw new Error('the hold is from another agent')
  return { hash: tx.txHash, ledger: tx.ledger, held, via }
}
