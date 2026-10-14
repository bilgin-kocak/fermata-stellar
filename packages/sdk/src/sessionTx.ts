// Sessions on chain: opening one (the agent's side and the sponsor's side), settling batches,
// closing, the contract's events and its views. The encodings the agent and the verifier sign are
// in session.ts.
//
// `open_session` needs the agent's authorization, and that authorization covers the deposit's
// transfer with its exact amount (`max_calls × price`). So, as for a hold (hold.ts), an agent can
// sign only the authorization and let a sponsor (the gateway, through its relayer or OpenZeppelin
// Channels) submit the transaction and pay its fee. The sponsor's checks are the same as for a
// sponsored hold: one operation, one authorization entry (the agent's) whose tree is exactly this
// `open_session` and its one transfer, an expiry in range, a valid signature, and a simulation in
// enforce mode whose events show exactly this deposit.
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
  rpc,
  xdr,
} from '@stellar/stellar-sdk'
import { Buffer } from 'buffer'
import { submitThroughChannels, type ChannelsConfig } from './channels.ts'
import { contractEventsOf, decodeTransfer } from './events.ts'
import { fromHex, toHex, type Hex } from './hex.ts'
import { LEDGER_SECONDS, addressCredentials, simulationEvents, verifyEntrySignature } from './hold.ts'
import type { Relayer } from './relayer.ts'
import { entriesBytes, type SessionEntry } from './session.ts'
import { Client as SessionClient, SessionStatus } from './session/bindings.ts'
import {
  NULL_ACCOUNT,
  field,
  scAddress,
  scBigint,
  scFields,
  scHex32,
  scSymbol,
  simulate,
  submitWithRetries,
  waitForTransaction,
} from './soroban.ts'

/** What opening a session commits the agent to. `deposit` is `maxCalls × price` of the service. */
export type OpenTerms = {
  /** The session contract (`C…`). */
  contract: string
  /** The service's token (`C…`). */
  token: string
  sessionId: Hex
  serviceId: Hex
  maxCalls: number
  /** The agent's ticket key (32 bytes, hex): not its account key. */
  ticketKey: Hex
  sampleK: number
  batchSize: number
  /** The verifier's seed commitment when k > 1; 32 zero bytes when k = 1. */
  seed: Hex
  /** Unix seconds: when calls stop. */
  expiresAt: bigint
  deposit: bigint
}

const scvBytes = (h: Hex, length?: number) => xdr.ScVal.scvBytes(Buffer.from(fromHex(h, length)))
const scvU32 = (n: number) => xdr.ScVal.scvU32(n)
const same = (a: string, b: string) => a.toLowerCase().replace(/^0x/, '') === b.toLowerCase().replace(/^0x/, '')

function openArgs(agent: string, t: OpenTerms): xdr.ScVal[] {
  return [
    new Address(agent).toScVal(),
    scvBytes(t.sessionId, 32),
    scvBytes(t.serviceId, 32),
    scvU32(t.maxCalls),
    scvBytes(t.ticketKey, 32),
    scvU32(t.sampleK),
    scvU32(t.batchSize),
    scvBytes(t.seed, 32),
    xdr.ScVal.scvU64(xdr.Uint64.fromString(t.expiresAt.toString())),
  ]
}

/** The `open_session` invocation of `agent` for `t`. */
export function openSessionOperation(agent: string, t: OpenTerms): xdr.Operation {
  return new Contract(t.contract).call('open_session', ...openArgs(agent, t))
}

function contractCall(inv: xdr.SorobanAuthorizedInvocation): xdr.InvokeContractArgs | undefined {
  const fn = inv.function()
  if (fn.switch().value !== xdr.SorobanAuthorizedFunctionType.sorobanAuthorizedFunctionTypeContractFn().value) {
    return undefined
  }
  return fn.contractFn()
}

/**
 * Why an authorized invocation tree is not exactly `open_session(agent, terms)` with one child,
 * the token transfer of the deposit from the agent to the session contract, and nothing else;
 * undefined when it is. Signing anything more would let a hostile token or contract move other
 * funds.
 */
export function openAuthorizationProblem(inv: xdr.SorobanAuthorizedInvocation, agent: string, t: OpenTerms): string | undefined {
  try {
    const root = contractCall(inv)
    if (!root) return 'the authorization is not a contract call'
    if (Address.fromScAddress(root.contractAddress()).toString() !== t.contract) return 'the authorization calls another contract'
    if (root.functionName().toString() !== 'open_session') return 'the authorization is not an open_session'
    const expected = openArgs(agent, t)
    const a = root.args()
    if (a.length !== expected.length) return 'open_session has the wrong number of arguments'
    if (scAddress(a[0]!) !== agent) return 'the session is for another agent'
    const names = ['agent', 'session id', 'service', 'max_calls', 'ticket key', 'sample_k', 'batch size', 'seed', 'expiry']
    for (let i = 1; i < expected.length; i++) {
      if (!a[i]!.toXDR().equals(expected[i]!.toXDR())) return `the session's ${names[i]} differs`
    }
    const subs = inv.subInvocations()
    if (subs.length !== 1) return `open_session authorizes ${subs.length} inner calls, not one token transfer`
    const sub = subs[0]!
    if (sub.subInvocations().length > 0) return 'the token transfer authorizes further calls'
    const tr = contractCall(sub)
    if (!tr || Address.fromScAddress(tr.contractAddress()).toString() !== t.token || tr.functionName().toString() !== 'transfer') {
      return "the inner authorization is not a transfer of the service's token"
    }
    const ta = tr.args()
    if (ta.length !== 3 || scAddress(ta[0]!) !== agent || scAddress(ta[1]!) !== t.contract || scBigint(ta[2]!) !== t.deposit) {
      return 'the transfer is not the deposit, from the agent to the session contract'
    }
    return undefined
  } catch (e) {
    return `the authorization cannot be read: ${(e as Error).message}`
  }
}

// ------------------------------------------------------------------------------------ agent side

/**
 * Agent side, sponsored: builds `open_session` with the all-zero account as source, simulates it
 * to record the authorization it needs, checks that the authorization is exactly this opening and
 * its deposit, and signs it so that it expires after about `validForSeconds`. Returns the
 * transaction (base64 XDR) for the sponsor, who rebuilds it from its own account.
 */
export async function signSponsoredOpen(opts: {
  server: rpc.Server
  networkPassphrase: string
  keypair: Keypair
  terms: OpenTerms
  validForSeconds: number
}): Promise<{ transaction: string; validUntilLedger: number }> {
  const { server, networkPassphrase, keypair, terms } = opts
  const agent = keypair.publicKey()
  const tx = new TransactionBuilder(new Account(NULL_ACCOUNT, '0'), { fee: '100', networkPassphrase })
    .addOperation(openSessionOperation(agent, terms))
    .setTimeout(opts.validForSeconds)
    .build()
  const prepared = rpc.assembleTransaction(tx, await simulate(server, tx)).build()
  const envelope = prepared.toEnvelope()
  const entries = envelope.v1().tx().operations()[0]!.body().invokeHostFunctionOp().auth()
  if (entries.length !== 1) throw new Error(`open_session needs ${entries.length} authorizations; expected only the agent's`)
  const cred = addressCredentials(entries[0]!.credentials())
  if (!cred || Address.fromScAddress(cred.address()).toString() !== agent) {
    throw new Error("open_session's authorization is not the agent's")
  }
  const problem = openAuthorizationProblem(entries[0]!.rootInvocation(), agent, terms)
  if (problem) throw new Error(`refusing to sign: ${problem}`)
  const validUntilLedger = (await server.getLatestLedger()).sequence + Math.ceil(opts.validForSeconds / LEDGER_SECONDS)
  entries[0] = await authorizeEntry(entries[0]!, keypair, validUntilLedger, networkPassphrase)
  return { transaction: envelope.toXDR('base64'), validUntilLedger }
}

/** Agent side, unsponsored: builds, checks, signs and submits `open_session` from the agent's account. */
export async function submitOwnOpen(opts: {
  server: rpc.Server
  networkPassphrase: string
  keypair: Keypair
  terms: OpenTerms
  timeoutMs?: number
}): Promise<{ hash: Hex; ledger: number; opened: SessionOpened }> {
  const { server, networkPassphrase, keypair, terms } = opts
  const agent = keypair.publicKey()
  const build = async () => {
    const account = await server.getAccount(agent)
    const tx = new TransactionBuilder(account, { fee: '100', networkPassphrase })
      .addOperation(openSessionOperation(agent, terms))
      .setTimeout(60)
      .build()
    const prepared = rpc.assembleTransaction(tx, await simulate(server, tx)).build()
    // The envelope signature authorizes every source-account entry, so check the tree first.
    for (const entry of prepared.toEnvelope().v1().tx().operations()[0]!.body().invokeHostFunctionOp().auth()) {
      const problem = openAuthorizationProblem(entry.rootInvocation(), agent, terms)
      if (problem) throw new Error(`refusing to sign: ${problem}`)
    }
    prepared.sign(keypair)
    return prepared
  }
  const res = await submitWithRetries(server, build, { timeoutMs: opts.timeoutMs })
  return { hash: res.txHash, ledger: res.ledger, opened: checkOpenTransaction(res, terms) }
}

// ---------------------------------------------------------------------------------- sponsor side

export type SponsoredOpen = {
  agent: string
  func: xdr.HostFunction
  auth: xdr.SorobanAuthorizationEntry[]
  validUntilLedger: number
}

/**
 * Sponsor side: parses an agent's sponsored `open_session` and checks it before anything is
 * simulated or paid, as `checkSponsoredHold` does for a hold: one `invokeHostFunction` operation
 * on this contract for exactly these terms, from the all-zero account; one authorization entry,
 * the agent's, with one valid signature over exactly this opening and its deposit; an expiry
 * after `latestLedger` and no later than `maxLedger`; and an agent that is none of `sponsors`.
 */
export function checkSponsoredOpen(opts: {
  transaction: string
  networkPassphrase: string
  terms: OpenTerms
  latestLedger: number
  maxLedger: number
  sponsors: readonly string[]
}): SponsoredOpen {
  const { networkPassphrase, terms } = opts
  let tx: Transaction
  try {
    const parsed = TransactionBuilder.fromXDR(opts.transaction, networkPassphrase)
    if (!(parsed instanceof Transaction)) throw new Error('a fee-bump transaction')
    tx = parsed
  } catch (e) {
    throw new Error(`the open_session transaction cannot be read: ${(e as Error).message}`)
  }
  if (tx.source !== NULL_ACCOUNT) throw new Error('a sponsored open_session must use the all-zero account as its source')
  if (tx.operations.length !== 1) throw new Error('the transaction must have exactly one operation')
  const op = tx.toEnvelope().v1().tx().operations()[0]!
  if (op.sourceAccount()) throw new Error('the operation must not name a source account')
  if (op.body().switch().value !== xdr.OperationType.invokeHostFunction().value) throw new Error('the operation is not a contract call')
  const invoke = op.body().invokeHostFunctionOp()
  const func = invoke.hostFunction()
  if (func.switch().value !== xdr.HostFunctionType.hostFunctionTypeInvokeContract().value) {
    throw new Error('the operation is not a contract call')
  }
  const call = func.invokeContract()
  if (Address.fromScAddress(call.contractAddress()).toString() !== terms.contract) throw new Error('the operation calls another contract')
  if (call.functionName().toString() !== 'open_session') throw new Error('the operation is not an open_session')
  const agent = scAddress(call.args()[0]!)
  if (!StrKey.isValidEd25519PublicKey(agent)) throw new Error('a sponsored session must be opened by an account (G…)')
  if (opts.sponsors.includes(agent)) throw new Error("the sponsor's own account cannot be the agent")

  const auth = invoke.auth()
  if (auth.length !== 1) throw new Error('open_session must carry exactly one authorization, the agent’s')
  const entry = auth[0]!
  const cred = addressCredentials(entry.credentials())
  if (!cred) throw new Error('the authorization must use address credentials')
  if (Address.fromScAddress(cred.address()).toString() !== agent) throw new Error('the authorization is not the agent’s')
  const problem = openAuthorizationProblem(entry.rootInvocation(), agent, terms)
  if (problem) throw new Error(problem)
  const authorized = contractCall(entry.rootInvocation())!
  if (!authorized.toXDR().equals(call.toXDR())) throw new Error('the transaction invokes something other than what the agent authorized')
  const expiry = cred.signatureExpirationLedger()
  if (expiry <= opts.latestLedger) throw new Error('the authorization has expired')
  if (expiry > opts.maxLedger) throw new Error(`the authorization stays valid until ledger ${expiry}, beyond ${opts.maxLedger}`)
  verifyEntrySignature(entry, networkPassphrase)
  return { agent, func, auth: [entry], validUntilLedger: expiry }
}

/**
 * Why a simulation (or a transaction's events) of `open_session` does not show exactly the
 * expected deposit: one `session_opened` event for these terms and one transfer of the deposit
 * from the agent to the session contract, and no other transfer. Undefined when it does.
 */
export function openEventsProblem(
  events: readonly { contract: string; topics: xdr.ScVal[]; value: xdr.ScVal }[],
  agent: string,
  t: OpenTerms,
): string | undefined {
  let opened: SessionOpened | undefined
  const transfers: { token: string; from: string; to: string; amount: bigint }[] = []
  for (const e of events) {
    try {
      if (e.contract === t.contract) {
        const d = decodeSessionEvent(e.topics, e.value)
        if (d?.name === 'session_opened') {
          if (opened) return 'more than one session_opened event'
          opened = d
        }
        continue
      }
      const tr = decodeTransfer(e.contract, e.topics, e.value)
      if (tr) transfers.push(tr)
    } catch (err) {
      return `an event cannot be read: ${(err as Error).message}`
    }
  }
  if (!opened) return 'no session_opened event'
  const problem = openedProblem(opened, agent, t)
  if (problem) return problem
  if (transfers.length !== 1) return `${transfers.length} token transfers instead of one`
  const [tr] = transfers
  if (tr!.token !== t.token || tr!.from !== agent || tr!.to !== t.contract || tr!.amount !== t.deposit) {
    return 'the transfer is not the deposit, from the agent to the session contract'
  }
  return undefined
}

function openedProblem(e: SessionOpened, agent: string, t: OpenTerms): string | undefined {
  if (!same(e.sessionId, t.sessionId) || !same(e.serviceId, t.serviceId)) return 'the session_opened event is for other ids'
  if (e.agent !== agent || e.deposit !== t.deposit || e.maxCalls !== t.maxCalls) {
    return 'the session_opened event is for another agent, deposit or number of calls'
  }
  if (e.sampleK !== t.sampleK || e.batchSize !== t.batchSize) return 'the session_opened event has other sampling terms'
  return undefined
}

/** Sponsor side: simulates a checked opening in enforce mode from the all-zero account and checks its events. */
export async function simulateSponsoredOpen(opts: {
  server: rpc.Server
  networkPassphrase: string
  open: SponsoredOpen
  terms: OpenTerms
}): Promise<rpc.Api.SimulateTransactionSuccessResponse> {
  const { server, networkPassphrase, open, terms } = opts
  const tx = new TransactionBuilder(new Account(NULL_ACCOUNT, '0'), { fee: '100', networkPassphrase })
    .addOperation(Operation.invokeHostFunction({ func: open.func, auth: open.auth }))
    .setTimeout(60)
    .build()
  const sim = await simulate(server, tx, 'enforce')
  const problem = openEventsProblem(simulationEvents(sim), open.agent, terms)
  if (problem) throw new Error(`open_session would not do what it says: ${problem}`)
  return sim
}

/** Checks a landed `open_session`: it opened exactly these terms. Returns the `session_opened` event. */
export function checkOpenTransaction(tx: rpc.Api.GetSuccessfulTransactionResponse, t: OpenTerms): SessionOpened {
  const opened = sessionEventsOf(tx, t.contract).find(
    (e): e is SessionOpened => e.name === 'session_opened' && same(e.sessionId, t.sessionId),
  )
  if (!opened) throw new Error('the transaction opened no session with this id')
  const problem = openedProblem(opened, opened.agent, t)
  if (problem) throw new Error(problem)
  return opened
}

/**
 * Sponsor side: submits a checked opening and waits for it, through OpenZeppelin's Channels service
 * when `channels` is set, else from the `relayer` account; simulated first in enforce mode with its
 * events checked, and checked again once landed.
 */
export async function submitSponsoredOpen(opts: {
  server: rpc.Server
  networkPassphrase: string
  open: SponsoredOpen
  terms: OpenTerms
  relayer?: Relayer
  channels?: ChannelsConfig
  timeoutMs?: number
}): Promise<{ hash: Hex; ledger: number; opened: SessionOpened; via: 'channels' | 'relayer' }> {
  const { server, open, terms } = opts
  let tx: rpc.Api.GetSuccessfulTransactionResponse
  let via: 'channels' | 'relayer'
  if (opts.channels) {
    await simulateSponsoredOpen(opts)
    const res = await submitThroughChannels(
      opts.channels,
      open.func.toXDR('base64'),
      open.auth.map((a) => a.toXDR('base64')),
    )
    if (!res.hash) throw new Error(`Channels accepted open_session but returned no transaction hash (status ${res.status})`)
    tx = await waitForTransaction(server, res.hash, { timeoutMs: opts.timeoutMs })
    via = 'channels'
  } else if (opts.relayer) {
    tx = await opts.relayer.invoke({ func: open.func, auth: open.auth }, (sim) => {
      const problem = openEventsProblem(simulationEvents(sim), open.agent, terms)
      if (problem) throw new Error(`open_session would not do what it says: ${problem}`)
    })
    via = 'relayer'
  } else {
    throw new Error('no way to submit a sponsored open_session: set a relayer or Channels')
  }
  const opened = checkOpenTransaction(tx, terms)
  if (opened.agent !== open.agent) throw new Error('the session is from another agent')
  return { hash: tx.txHash, ledger: tx.ledger, opened, via }
}

// ------------------------------------------------------------------------- settling and closing

/** A batch as `settle_batch` takes it: calls `from + 1` through `to`. */
export type SessionBatch = {
  sessionId: Hex
  to: number
  /** The calls' request hashes, in call order. */
  requestHashes: readonly Hex[]
  /** The agent's ticket for call `to`. */
  ticket: Hex
  /** The batch's revealed seed; 32 zero bytes when k = 1. */
  seed: Hex
  entries: readonly SessionEntry[]
  /** The verifier's signature over the batch statement. */
  statement: Hex
}

/** The `settle_batch` invocation for a batch. Anyone may send it. */
export function settleBatchOperation(contract: string, b: SessionBatch): xdr.Operation {
  if (b.requestHashes.length !== b.entries.length) throw new Error('one request hash per entry')
  return new Contract(contract).call(
    'settle_batch',
    scvBytes(b.sessionId, 32),
    scvU32(b.to),
    xdr.ScVal.scvBytes(Buffer.from(b.requestHashes.map((h) => toHex(fromHex(h, 32))).join(''), 'hex')),
    scvBytes(b.ticket, 64),
    scvBytes(b.seed, 32),
    xdr.ScVal.scvBytes(Buffer.from(entriesBytes(b.entries))),
    scvBytes(b.statement, 64),
  )
}

/** The `close_session` invocation. Anyone may send it after the session's deadline. */
export function closeSessionOperation(contract: string, sessionId: Hex): xdr.Operation {
  return new Contract(contract).call('close_session', scvBytes(sessionId, 32))
}

// ------------------------------------------------------------------------------------- events

export type SessionOpened = {
  name: 'session_opened'
  sessionId: Hex
  serviceId: Hex
  agent: string
  deposit: bigint
  maxCalls: number
  price: bigint
  sampleK: number
  batchSize: number
  deadline: bigint
}
export type BatchSettled = {
  name: 'batch_settled'
  sessionId: Hex
  serviceId: Hex
  from: number
  to: number
  delivered: number
  failed: number
  answered: number
  unanswered: number
  paid: number
  payoutAmount: bigint
  fee: bigint
  refund: bigint
  chain: Hex
  entriesHash: Hex
}
export type SessionClosed = { name: 'session_closed'; sessionId: Hex; serviceId: Hex; agent: string; refund: bigint }
export type SessionEventData = SessionOpened | BatchSettled | SessionClosed

const u32 = (v: xdr.ScVal): number => {
  const n = scBigint(v)
  if (n < 0n || n > 0xffffffffn) throw new Error(`not a u32: ${n}`)
  return Number(n)
}

/**
 * Decodes one session-contract event (topics: its name, then its `#[topic]` fields; value: a map of
 * the others, `contracts/session/src/events.rs`); undefined for an event this version does not know.
 */
export function decodeSessionEvent(topics: readonly xdr.ScVal[], value: xdr.ScVal): SessionEventData | undefined {
  const name = topics[0] ? scSymbol(topics[0]) : undefined
  const t = (i: number) => {
    const v = topics[i]
    if (!v) throw new Error(`${name}: missing topic ${i}`)
    return v
  }
  switch (name) {
    case 'session_opened': {
      const f = scFields(value)
      return {
        name,
        sessionId: scHex32(t(1)),
        serviceId: scHex32(t(2)),
        agent: scAddress(t(3)),
        deposit: scBigint(field(f, 'deposit')),
        maxCalls: u32(field(f, 'max_calls')),
        price: scBigint(field(f, 'price')),
        sampleK: u32(field(f, 'sample_k')),
        batchSize: u32(field(f, 'batch_size')),
        deadline: scBigint(field(f, 'deadline')),
      }
    }
    case 'batch_settled': {
      const f = scFields(value)
      return {
        name,
        sessionId: scHex32(t(1)),
        serviceId: scHex32(t(2)),
        from: u32(field(f, 'from')),
        to: u32(field(f, 'to')),
        delivered: u32(field(f, 'delivered')),
        failed: u32(field(f, 'failed')),
        answered: u32(field(f, 'answered')),
        unanswered: u32(field(f, 'unanswered')),
        paid: u32(field(f, 'paid')),
        payoutAmount: scBigint(field(f, 'payout_amount')),
        fee: scBigint(field(f, 'fee')),
        refund: scBigint(field(f, 'refund')),
        chain: scHex32(field(f, 'chain')),
        entriesHash: scHex32(field(f, 'entries_hash')),
      }
    }
    case 'session_closed': {
      const f = scFields(value)
      return { name, sessionId: scHex32(t(1)), serviceId: scHex32(t(2)), agent: scAddress(t(3)), refund: scBigint(field(f, 'refund')) }
    }
    default:
      return undefined
  }
}

/** The session-contract events in a successful transaction. */
export function sessionEventsOf(tx: rpc.Api.GetSuccessfulTransactionResponse, contract: string): SessionEventData[] {
  return contractEventsOf(tx)
    .filter((e) => e.contract === contract)
    .map((e) => decodeSessionEvent(e.topics, e.value))
    .filter((e): e is SessionEventData => e !== undefined)
}

// -------------------------------------------------------------------------------------- views

export type SessionInfo = {
  sessionId: Hex
  agent: string
  serviceId: Hex
  token: string
  payout: string
  price: bigint
  feeBps: number
  verifier: Hex
  predicateHash: Hex
  ticketKey: Hex
  maxCalls: number
  sampleK: number
  batchSize: number
  openedAt: bigint
  deadline: bigint
  settled: number
  chain: Hex
  seed: Hex
  status: SessionStatus
}


/** Read-only views of the session contract, by simulation: no account and no key needed. */
export class SessionReader {
  readonly client: SessionClient

  constructor(
    readonly contract: string,
    readonly rpcUrl: string,
    readonly networkPassphrase: string,
  ) {
    this.client = new SessionClient({
      contractId: contract,
      networkPassphrase,
      rpcUrl,
      allowHttp: rpcUrl.startsWith('http://'),
    })
  }

  /** The session, or undefined for an id that was never opened. */
  async session(sessionId: Hex): Promise<SessionInfo | undefined> {
    const s = (await this.client.get_session({ session_id: Buffer.from(fromHex(sessionId, 32)) })).result
    if (!s) return undefined
    return {
      sessionId: toHex(fromHex(sessionId, 32)),
      agent: s.agent,
      serviceId: toHex(s.service_id),
      token: s.token,
      payout: s.payout,
      price: BigInt(s.price),
      feeBps: Number(s.fee_bps),
      verifier: toHex(s.verifier),
      predicateHash: toHex(s.predicate_hash),
      ticketKey: toHex(s.ticket_key),
      maxCalls: Number(s.max_calls),
      sampleK: Number(s.sample_k),
      batchSize: Number(s.batch_size),
      openedAt: BigInt(s.opened_at),
      deadline: BigInt(s.deadline),
      settled: Number(s.settled),
      chain: toHex(s.chain),
      seed: toHex(s.seed),
      status: s.status,
    }
  }

  /** The escrow whose services, fee and treasury the session contract uses. */
  async escrow(): Promise<string> {
    return (await this.client.escrow()).result
  }
}
