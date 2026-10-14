// The sponsor's checks on an agent's signed hold, offline: every transaction here is built and signed
// locally, the way `signSponsoredHold` would after simulation.
import { Account, Address, Keypair, Operation, TransactionBuilder, authorizeEntry, nativeToScVal, xdr } from '@stellar/stellar-sdk'
import { Buffer } from 'buffer'
import { describe, expect, it } from 'vitest'
import {
  NETWORK_PASSPHRASES,
  NULL_ACCOUNT,
  checkSponsoredHold,
  contractAddress,
  holdAuthorizationProblem,
  holdEventsProblem,
  verifyEntrySignature,
  type HoldTerms,
} from '../src/index.ts'

const passphrase = NETWORK_PASSPHRASES.testnet
const agentKey = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 7))
const agent = agentKey.publicKey()
const relayer = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 9)).publicKey()
const escrow = contractAddress(new Uint8Array(32).fill(0xe5))
const token = contractAddress(new Uint8Array(32).fill(0x70))
const terms: HoldTerms = {
  escrow,
  token,
  amount: 100_000n,
  callId: 'c1'.repeat(32),
  serviceId: '5e'.repeat(32),
  requestHash: 'ab'.repeat(32),
}
const LATEST = 1000

const b32 = (hex: string) => xdr.ScVal.scvBytes(Buffer.from(hex, 'hex'))
const call = (contract: string, fn: string, args: xdr.ScVal[]) =>
  new xdr.InvokeContractArgs({ contractAddress: new Address(contract).toScAddress(), functionName: fn, args })
const invocation = (args: xdr.InvokeContractArgs, subs: xdr.SorobanAuthorizedInvocation[] = []) =>
  new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(args),
    subInvocations: subs,
  })
const holdArgs = (t: HoldTerms, who = agent) =>
  call(t.escrow, 'hold', [new Address(who).toScVal(), b32(t.callId), b32(t.serviceId), b32(t.requestHash)])
const transferArgs = (t: HoldTerms, who = agent, amount = t.amount) =>
  call(t.token, 'transfer', [new Address(who).toScVal(), new Address(t.escrow).toScVal(), nativeToScVal(amount, { type: 'i128' })])
const tree = (t: HoldTerms = terms) => invocation(holdArgs(t), [invocation(transferArgs(t))])

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

const check = (transaction: string, overrides: Partial<Parameters<typeof checkSponsoredHold>[0]> = {}) =>
  checkSponsoredHold({
    transaction,
    networkPassphrase: passphrase,
    terms,
    latestLedger: LATEST,
    maxLedger: LATEST + 60,
    sponsors: [relayer],
    ...overrides,
  })

describe('the authorization tree an agent signs', () => {
  it('accepts exactly the hold and its transfer of the price', () => {
    expect(holdAuthorizationProblem(tree(), agent, terms)).toBeUndefined()
  })

  it('refuses another call id, service, request, contract, token, amount or agent', () => {
    expect(holdAuthorizationProblem(tree({ ...terms, callId: 'c2'.repeat(32) }), agent, terms)).toMatch(/call id/)
    expect(holdAuthorizationProblem(tree({ ...terms, serviceId: '5f'.repeat(32) }), agent, terms)).toMatch(/service/)
    expect(holdAuthorizationProblem(tree({ ...terms, requestHash: 'ac'.repeat(32) }), agent, terms)).toMatch(/request/)
    const other = contractAddress(new Uint8Array(32).fill(1))
    expect(holdAuthorizationProblem(invocation(holdArgs({ ...terms, escrow: other }), [invocation(transferArgs(terms))]), agent, terms)).toMatch(
      /another contract/,
    )
    expect(holdAuthorizationProblem(invocation(holdArgs(terms), [invocation(transferArgs({ ...terms, token: other }))]), agent, terms)).toMatch(
      /token/,
    )
    expect(holdAuthorizationProblem(invocation(holdArgs(terms), [invocation(transferArgs(terms, agent, 100_001n))]), agent, terms)).toMatch(
      /price/,
    )
    expect(holdAuthorizationProblem(tree(), relayer, terms)).toMatch(/another agent/)
  })

  it('refuses a tree that authorizes anything more', () => {
    const extra = invocation(transferArgs({ ...terms, token: contractAddress(new Uint8Array(32).fill(2)) }))
    expect(holdAuthorizationProblem(invocation(holdArgs(terms), [invocation(transferArgs(terms)), extra]), agent, terms)).toMatch(/2 inner calls/)
    expect(holdAuthorizationProblem(invocation(holdArgs(terms), [invocation(transferArgs(terms), [extra])]), agent, terms)).toMatch(/further calls/)
    expect(holdAuthorizationProblem(invocation(holdArgs(terms)), agent, terms)).toMatch(/0 inner calls/)
  })
})

describe("the sponsor's check of a signed hold", () => {
  it('accepts a correctly signed hold and returns the agent', async () => {
    const tx = transaction(holdArgs(terms), [await signedEntry(tree())])
    const hold = check(tx)
    expect(hold.agent).toBe(agent)
    expect(hold.validUntilLedger).toBe(LATEST + 20)
    expect(() => verifyEntrySignature(hold.auth[0]!, passphrase)).not.toThrow()
  })

  it('refuses a signature by another key, or for another network', async () => {
    const other = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 8))
    await expect(async () => check(transaction(holdArgs(terms), [await signedEntry(tree(), other)]))).rejects.toThrow(/another key/)
    const tx = transaction(holdArgs(terms), [await signedEntry(tree())])
    expect(() => check(tx, { networkPassphrase: NETWORK_PASSPHRASES.mainnet })).toThrow()
  })

  it('refuses an expired authorization, or one valid for too long', async () => {
    expect(() => check(transaction(holdArgs(terms), [])).toString()).toThrow(/exactly one authorization/)
    const expired = transaction(holdArgs(terms), [await signedEntry(tree(), agentKey, LATEST)])
    expect(() => check(expired)).toThrow(/expired/)
    const long = transaction(holdArgs(terms), [await signedEntry(tree(), agentKey, LATEST + 61)])
    expect(() => check(long)).toThrow(/beyond/)
  })

  it('refuses a transaction that invokes something other than what was authorized', async () => {
    const entry = await signedEntry(tree())
    const otherCall = holdArgs({ ...terms, requestHash: 'cd'.repeat(32) })
    expect(() => check(transaction(otherCall, [entry]))).toThrow(/other than what the agent authorized/)
  })

  it('refuses a hold whose source is not the all-zero account, or whose agent is the sponsor', async () => {
    const entry = await signedEntry(tree())
    expect(() => check(transaction(holdArgs(terms), [entry], relayer))).toThrow(/all-zero account/)
    expect(() => check(transaction(holdArgs(terms), [entry]), { sponsors: [agent] })).toThrow(/sponsor/)
  })

  it('refuses a tampered signature', async () => {
    const entry = await signedEntry(tree())
    const sig = entry.credentials().address().signature()
    const map = sig.vec()![0]!.map()!
    const field = map.find((e) => e.key().sym().toString() === 'signature')!
    const bytes = Buffer.from(field.val().bytes())
    bytes[0] = bytes[0]! ^ 1
    field.val(xdr.ScVal.scvBytes(bytes))
    expect(() => check(transaction(holdArgs(terms), [entry]))).toThrow(/signature is invalid/)
  })
})

describe('the money a hold moves', () => {
  const event = (contract: string, topics: xdr.ScVal[], value: xdr.ScVal) => ({ contract, topics, value })
  const sym = (s: string) => xdr.ScVal.scvSymbol(s)
  const map = (fields: Record<string, xdr.ScVal>) =>
    xdr.ScVal.scvMap(Object.entries(fields).map(([k, v]) => new xdr.ScMapEntry({ key: sym(k), val: v })))
  const held = (amount = terms.amount) =>
    event(escrow, [sym('held'), b32(terms.callId), b32(terms.serviceId), new Address(agent).toScVal()], map({ amount: nativeToScVal(amount, { type: 'i128' }), request_hash: b32(terms.requestHash) }))
  const transfer = (from: string, to: string, amount: bigint, contract = token) =>
    event(contract, [sym('transfer'), new Address(from).toScVal(), new Address(to).toScVal(), xdr.ScVal.scvString('USDC:G')], nativeToScVal(amount, { type: 'i128' }))

  it('accepts one held event and one transfer of the price into the escrow', () => {
    expect(holdEventsProblem([held(), transfer(agent, escrow, terms.amount)], agent, terms)).toBeUndefined()
  })

  it('refuses any other transfer, a missing event or another amount', () => {
    expect(holdEventsProblem([held(), transfer(agent, escrow, terms.amount), transfer(agent, relayer, 1n)], agent, terms)).toMatch(/2 token transfers/)
    expect(holdEventsProblem([transfer(agent, escrow, terms.amount)], agent, terms)).toMatch(/no held event/)
    expect(holdEventsProblem([held(1n), transfer(agent, escrow, terms.amount)], agent, terms)).toMatch(/amount/)
    expect(holdEventsProblem([held(), transfer(agent, escrow, terms.amount, contractAddress(new Uint8Array(32).fill(3)))], agent, terms)).toMatch(
      /price/,
    )
  })
})
