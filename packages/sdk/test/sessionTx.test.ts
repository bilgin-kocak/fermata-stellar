// The sponsor's checks on an agent's signed `open_session`, the events a session moves money
// with, and the encoding of `settle_batch`, offline: every transaction here is built and signed
// locally, the way `signSponsoredOpen` would after simulation.
import { Account, Address, Keypair, Operation, TransactionBuilder, authorizeEntry, nativeToScVal, xdr } from '@stellar/stellar-sdk'
import { Buffer } from 'buffer'
import { describe, expect, it } from 'vitest'
import {
  NETWORK_PASSPHRASES,
  NULL_ACCOUNT,
  checkSponsoredOpen,
  closeSessionOperation,
  contractAddress,
  decodeSessionEvent,
  entriesBytes,
  openAuthorizationProblem,
  openEventsProblem,
  openSessionOperation,
  provedEntry,
  settleBatchOperation,
  unprovedEntry,
  verifyEntrySignature,
  type OpenTerms,
} from '../src/index.ts'

const passphrase = NETWORK_PASSPHRASES.testnet
const agentKey = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 7))
const agent = agentKey.publicKey()
const relayer = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 9)).publicKey()
const contract = contractAddress(new Uint8Array(32).fill(0x5e))
const token = contractAddress(new Uint8Array(32).fill(0x70))
const terms: OpenTerms = {
  contract,
  token,
  sessionId: '5a'.repeat(32),
  serviceId: '5e'.repeat(32),
  maxCalls: 6,
  ticketKey: '7c'.repeat(32),
  sampleK: 1,
  batchSize: 4,
  seed: '00'.repeat(32),
  expiresAt: 1_700_000_060n,
  deposit: 600_000n,
}
const LATEST = 1000

const call = (c: string, fn: string, args: xdr.ScVal[]) =>
  new xdr.InvokeContractArgs({ contractAddress: new Address(c).toScAddress(), functionName: fn, args })
const invocation = (args: xdr.InvokeContractArgs, subs: xdr.SorobanAuthorizedInvocation[] = []) =>
  new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(args),
    subInvocations: subs,
  })
const openArgs = (t: OpenTerms, who = agent) =>
  openSessionOperation(who, t).body().invokeHostFunctionOp().hostFunction().invokeContract()
const transferArgs = (t: OpenTerms, who = agent, amount = t.deposit) =>
  call(t.token, 'transfer', [new Address(who).toScVal(), new Address(t.contract).toScVal(), nativeToScVal(amount, { type: 'i128' })])
const tree = (t: OpenTerms = terms) => invocation(openArgs(t), [invocation(transferArgs(t))])

async function signedEntry(root: xdr.SorobanAuthorizedInvocation, key = agentKey, expiry = LATEST + 20) {
  const entry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: new Address(agent).toScAddress(),
        nonce: xdr.Int64.fromString('42'),
        signatureExpirationLedger: 0,
        signature: xdr.ScVal.scvVoid(),
      }),
    ),
    rootInvocation: root,
  })
  return authorizeEntry(entry, key, expiry, passphrase)
}

function transaction(func: xdr.InvokeContractArgs, auth: xdr.SorobanAuthorizationEntry[], source = NULL_ACCOUNT) {
  return new TransactionBuilder(new Account(source, '0'), { fee: '100', networkPassphrase: passphrase })
    .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(func), auth }))
    .setTimeout(60)
    .build()
    .toEnvelope()
    .toXDR('base64')
}

const check = (transaction: string, overrides: Partial<Parameters<typeof checkSponsoredOpen>[0]> = {}) =>
  checkSponsoredOpen({
    transaction,
    networkPassphrase: passphrase,
    terms,
    latestLedger: LATEST,
    maxLedger: LATEST + 60,
    sponsors: [relayer],
    ...overrides,
  })

describe('the authorization tree an agent signs to open a session', () => {
  it('accepts exactly open_session and its transfer of the deposit', () => {
    expect(openAuthorizationProblem(tree(), agent, terms)).toBeUndefined()
  })

  it('refuses any other term', () => {
    const cases: [Partial<OpenTerms>, RegExp][] = [
      [{ sessionId: '5b'.repeat(32) }, /session id/],
      [{ serviceId: '5f'.repeat(32) }, /service/],
      [{ maxCalls: 7, deposit: 700_000n }, /max_calls/],
      [{ ticketKey: '7d'.repeat(32) }, /ticket key/],
      [{ sampleK: 4, seed: '5c'.repeat(32) }, /sample_k/],
      [{ batchSize: 8 }, /batch size/],
      [{ seed: '5c'.repeat(32) }, /seed/],
      [{ expiresAt: terms.expiresAt + 1n }, /expiry/],
    ]
    for (const [change, why] of cases) {
      const signed = { ...terms, ...change }
      expect(openAuthorizationProblem(invocation(openArgs(signed), [invocation(transferArgs(terms))]), agent, terms)).toMatch(why)
    }
    expect(openAuthorizationProblem(tree(), relayer, terms)).toMatch(/another agent/)
  })

  it('refuses another contract, token or amount', () => {
    const other = contractAddress(new Uint8Array(32).fill(1))
    expect(openAuthorizationProblem(invocation(openArgs({ ...terms, contract: other }), [invocation(transferArgs(terms))]), agent, terms)).toMatch(
      /another contract/,
    )
    expect(openAuthorizationProblem(invocation(openArgs(terms), [invocation(transferArgs({ ...terms, token: other }))]), agent, terms)).toMatch(
      /token/,
    )
    expect(openAuthorizationProblem(invocation(openArgs(terms), [invocation(transferArgs(terms, agent, 600_001n))]), agent, terms)).toMatch(
      /deposit/,
    )
  })

  it('refuses a tree that authorizes anything more', () => {
    const extra = invocation(transferArgs({ ...terms, token: contractAddress(new Uint8Array(32).fill(2)) }))
    expect(openAuthorizationProblem(invocation(openArgs(terms), [invocation(transferArgs(terms)), extra]), agent, terms)).toMatch(/2 inner calls/)
    expect(openAuthorizationProblem(invocation(openArgs(terms), [invocation(transferArgs(terms), [extra])]), agent, terms)).toMatch(/further calls/)
    expect(openAuthorizationProblem(invocation(openArgs(terms)), agent, terms)).toMatch(/0 inner calls/)
  })
})

describe("the sponsor's check of a signed open_session", () => {
  it('accepts a correctly signed opening and returns the agent', async () => {
    const opening = check(transaction(openArgs(terms), [await signedEntry(tree())]))
    expect(opening.agent).toBe(agent)
    expect(opening.validUntilLedger).toBe(LATEST + 20)
    expect(() => verifyEntrySignature(opening.auth[0]!, passphrase)).not.toThrow()
  })

  it('refuses a signature by another key, or for another network', async () => {
    const other = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 8))
    await expect(async () => check(transaction(openArgs(terms), [await signedEntry(tree(), other)]))).rejects.toThrow(/another key/)
    const tx = transaction(openArgs(terms), [await signedEntry(tree())])
    expect(() => check(tx, { networkPassphrase: NETWORK_PASSPHRASES.mainnet })).toThrow()
  })

  it('refuses no authorization, an expired one, or one valid for too long', async () => {
    expect(() => check(transaction(openArgs(terms), []))).toThrow(/exactly one authorization/)
    const expired = transaction(openArgs(terms), [await signedEntry(tree(), agentKey, LATEST)])
    expect(() => check(expired)).toThrow(/expired/)
    const long = transaction(openArgs(terms), [await signedEntry(tree(), agentKey, LATEST + 61)])
    expect(() => check(long)).toThrow(/beyond/)
  })

  it('refuses a transaction that invokes something other than what was authorized', async () => {
    const entry = await signedEntry(tree())
    // The tree the agent signed is checked against the terms first, so change only what the
    // terms do not pin: here the call names the same terms but another agent's address.
    expect(() => check(transaction(openArgs(terms, relayer), [entry]))).toThrow()
    const longer = openArgs({ ...terms, expiresAt: terms.expiresAt + 1n })
    expect(() => check(transaction(longer, [entry]), { terms: { ...terms, expiresAt: terms.expiresAt + 1n } })).toThrow(/expiry/)
  })

  it('refuses another source than the all-zero account, or an agent that is the sponsor', async () => {
    const entry = await signedEntry(tree())
    expect(() => check(transaction(openArgs(terms), [entry], relayer))).toThrow(/all-zero account/)
    expect(() => check(transaction(openArgs(terms), [entry]), { sponsors: [agent] })).toThrow(/sponsor/)
  })

  it('refuses a call to another contract or function', async () => {
    const entry = await signedEntry(tree())
    const other = contractAddress(new Uint8Array(32).fill(4))
    expect(() => check(transaction(openArgs({ ...terms, contract: other }), [entry]))).toThrow(/another contract/)
    expect(() => check(transaction(call(contract, 'close_session', [xdr.ScVal.scvBytes(Buffer.alloc(32, 0x5a))]), [entry]))).toThrow(
      /not an open_session/,
    )
  })
})

const sym = (s: string) => xdr.ScVal.scvSymbol(s)
const b32 = (hex: string) => xdr.ScVal.scvBytes(Buffer.from(hex, 'hex'))
const map = (fields: Record<string, xdr.ScVal>) =>
  xdr.ScVal.scvMap(Object.entries(fields).map(([k, v]) => new xdr.ScMapEntry({ key: sym(k), val: v })))
const i128 = (n: bigint) => nativeToScVal(n, { type: 'i128' })
const u32 = (n: number) => xdr.ScVal.scvU32(n)
const event = (c: string, topics: xdr.ScVal[], value: xdr.ScVal) => ({ contract: c, topics, value })

const openedEvent = (t: OpenTerms = terms, deposit = t.deposit) =>
  event(
    contract,
    [sym('session_opened'), b32(t.sessionId), b32(t.serviceId), new Address(agent).toScVal()],
    map({
      batch_size: u32(t.batchSize),
      deadline: xdr.ScVal.scvU64(xdr.Uint64.fromString('1700000180')),
      deposit: i128(deposit),
      max_calls: u32(t.maxCalls),
      price: i128(100_000n),
      sample_k: u32(t.sampleK),
    }),
  )
const transfer = (from: string, to: string, amount: bigint, c = token) =>
  event(c, [sym('transfer'), new Address(from).toScVal(), new Address(to).toScVal(), xdr.ScVal.scvString('USDC:G')], i128(amount))

describe('the money opening a session moves', () => {
  it('accepts one session_opened event and one transfer of the deposit', () => {
    expect(openEventsProblem([openedEvent(), transfer(agent, contract, terms.deposit)], agent, terms)).toBeUndefined()
  })

  it('refuses any other transfer, a missing event, or other terms', () => {
    expect(openEventsProblem([openedEvent(), transfer(agent, contract, terms.deposit), transfer(agent, relayer, 1n)], agent, terms)).toMatch(
      /2 token transfers/,
    )
    expect(openEventsProblem([transfer(agent, contract, terms.deposit)], agent, terms)).toMatch(/no session_opened/)
    expect(openEventsProblem([openedEvent(terms, 1n), transfer(agent, contract, terms.deposit)], agent, terms)).toMatch(/deposit/)
    expect(openEventsProblem([openedEvent({ ...terms, batchSize: 8 }), transfer(agent, contract, terms.deposit)], agent, terms)).toMatch(
      /sampling/,
    )
    expect(openEventsProblem([openedEvent(), transfer(agent, contract, terms.deposit, contractAddress(new Uint8Array(32).fill(3)))], agent, terms)).toMatch(
      /deposit/,
    )
  })
})

describe('session events', () => {
  it('decodes session_opened, batch_settled and session_closed', () => {
    const opened = decodeSessionEvent(openedEvent().topics, openedEvent().value)
    expect(opened).toMatchObject({ name: 'session_opened', agent, deposit: 600_000n, maxCalls: 6, sampleK: 1, batchSize: 4, deadline: 1_700_000_180n })
    const settled = decodeSessionEvent(
      [sym('batch_settled'), b32(terms.sessionId), b32(terms.serviceId)],
      map({
        answered: u32(0),
        chain: b32('aa'.repeat(32)),
        delivered: u32(1),
        entries_hash: b32('bb'.repeat(32)),
        failed: u32(1),
        fee: i128(500n),
        from: u32(0),
        paid: u32(1),
        payout_amount: i128(99_500n),
        refund: i128(200_000n),
        to: u32(3),
        unanswered: u32(1),
      }),
    )
    expect(settled).toEqual({
      name: 'batch_settled',
      sessionId: terms.sessionId,
      serviceId: terms.serviceId,
      from: 0,
      to: 3,
      delivered: 1,
      failed: 1,
      answered: 0,
      unanswered: 1,
      paid: 1,
      payoutAmount: 99_500n,
      fee: 500n,
      refund: 200_000n,
      chain: 'aa'.repeat(32),
      entriesHash: 'bb'.repeat(32),
    })
    const closed = decodeSessionEvent(
      [sym('session_closed'), b32(terms.sessionId), b32(terms.serviceId), new Address(agent).toScVal()],
      map({ refund: i128(200_000n) }),
    )
    expect(closed).toEqual({ name: 'session_closed', sessionId: terms.sessionId, serviceId: terms.serviceId, agent, refund: 200_000n })
    expect(decodeSessionEvent([sym('something_else')], map({}))).toBeUndefined()
  })
})

describe('settle_batch and close_session invocations', () => {
  it('concatenates the request hashes and the entries in call order', () => {
    const entries = [provedEntry(true, '11'.repeat(32), '22'.repeat(32)), unprovedEntry(false)]
    const op = settleBatchOperation(contract, {
      sessionId: terms.sessionId,
      to: 2,
      requestHashes: ['0x' + 'a1'.repeat(32), 'a2'.repeat(32)],
      ticket: 'cc'.repeat(64),
      seed: '00'.repeat(32),
      entries,
      statement: 'dd'.repeat(64),
    })
    const args = op.body().invokeHostFunctionOp().hostFunction().invokeContract().args()
    expect(args.map((a) => a.switch().name)).toEqual(['scvBytes', 'scvU32', 'scvBytes', 'scvBytes', 'scvBytes', 'scvBytes', 'scvBytes'])
    expect(Buffer.from(args[2]!.bytes()).toString('hex')).toBe('a1'.repeat(32) + 'a2'.repeat(32))
    expect(Buffer.from(args[5]!.bytes()).equals(Buffer.from(entriesBytes(entries)))).toBe(true)
    expect(args[1]!.u32()).toBe(2)
    expect(() =>
      settleBatchOperation(contract, {
        sessionId: terms.sessionId,
        to: 2,
        requestHashes: ['a1'.repeat(32)],
        ticket: 'cc'.repeat(64),
        seed: '00'.repeat(32),
        entries,
        statement: 'dd'.repeat(64),
      }),
    ).toThrow(/one request hash per entry/)
    const close = closeSessionOperation(contract, terms.sessionId).body().invokeHostFunctionOp().hostFunction().invokeContract()
    expect(close.functionName().toString()).toBe('close_session')
  })
})
