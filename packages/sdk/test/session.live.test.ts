// The session contract on a deployment written by scripts/deploy-testnet.sh, through the generated
// client and the SDK's helpers. Opt in as for the escrow's live tests:
//
//   FERMATA_DEPLOYMENT=deployments/local.json pnpm sdk:test
//
// - Views (no secrets): the contract's ticket and statement messages, call ids and sample agree
//   with the SDK's.
// - With the agent's, the relayer's and the verifier's secrets (scripts and CI pass them from the
//   keystore for one command): a session opened through the relayer and one the agent opens
//   itself, each settled with a batch the SDK builds and signs, until it closes.
import { readFileSync } from 'node:fs'
import * as ed from '@noble/ed25519'
import { Keypair } from '@stellar/stellar-sdk'
import { Buffer } from 'buffer'
import { describe, expect, it } from 'vitest'
import {
  EXPIRY_SKEW_LEDGERS,
  LEDGER_SECONDS,
  Relayer,
  SessionClient,
  SessionReader,
  SessionStatus,
  checkSponsoredOpen,
  entriesBytes,
  entriesHash,
  extendChain,
  isSampled,
  provedEntry,
  rpcServer,
  sessionCallId,
  sessionEventsOf,
  settleBatchOperation,
  signSponsoredOpen,
  signStatement,
  signTicket,
  statementMessage,
  submitOwnOpen,
  submitSponsoredOpen,
  ticketMessage,
  toHex,
  tokenBalance,
  unprovedEntry,
  type BatchSettled,
  type Domain,
  type OpenTerms,
  type SessionEntry,
} from '../src/index.ts'

const file = process.env.FERMATA_DEPLOYMENT
const root = new URL('../../../', import.meta.url)
const d = file ? JSON.parse(readFileSync(new URL(file, root), 'utf8')) : undefined
const rpcUrl =
  process.env.FERMATA_RPC_URL ?? (d?.network === 'local' ? 'http://localhost:8000/rpc' : 'https://soroban-testnet.stellar.org')
const fresh = () => toHex(crypto.getRandomValues(new Uint8Array(32)))
const ZERO = '00'.repeat(32)

describe.skipIf(!d?.session)('a deployed session contract (FERMATA_DEPLOYMENT)', () => {
  const contract: string = d?.session?.contract_id
  const domain: Domain = { networkPassphrase: d?.network_passphrase, contract }
  const client = () =>
    new SessionClient({ contractId: contract, networkPassphrase: d.network_passphrase, rpcUrl, allowHttp: rpcUrl.startsWith('http://') })

  it('reads the deployment escrow', async () => {
    expect(await new SessionReader(contract, rpcUrl, d.network_passphrase).escrow()).toBe(d.escrow.contract_id)
  })

  it('builds tickets, statements, call ids and the sample exactly as the contract does', async () => {
    const sessionId = fresh()
    const chain = fresh()
    const onchainTicket = (await client().ticket_message({ session_id: Buffer.from(sessionId, 'hex'), n: 7, chain: Buffer.from(chain, 'hex') })).result
    expect(onchainTicket.toString('hex')).toBe(toHex(ticketMessage(domain, sessionId, 7, chain)))

    const entries: SessionEntry[] = [provedEntry(true, fresh(), fresh()), unprovedEntry(false)]
    const statement = {
      session_id: sessionId,
      service_id: d.service.id,
      predicate_hash: d.service.predicate_hash,
      from: 3,
      to: 5,
      chain,
      seed: ZERO,
      entries_hash: entriesHash(entries),
    }
    const onchainStatement = (
      await client().statement_message({
        session_id: Buffer.from(sessionId, 'hex'),
        service_id: Buffer.from(d.service.id, 'hex'),
        predicate_hash: Buffer.from(d.service.predicate_hash, 'hex'),
        from: 3,
        to: 5,
        chain: Buffer.from(chain, 'hex'),
        seed: Buffer.from(ZERO, 'hex'),
        entries: Buffer.from(entriesBytes(entries)),
      })
    ).result
    expect(onchainStatement.toString('hex')).toBe(toHex(statementMessage(domain, statement)))

    const callId = (await client().call_id({ session_id: Buffer.from(sessionId, 'hex'), n: 7 })).result
    expect(callId.toString('hex')).toBe(sessionCallId(contract, sessionId, 7))
    const seed = fresh()
    for (const n of [1, 2, 3, 4, 5]) {
      const onchain = (await client().sampled({ seed: Buffer.from(seed, 'hex'), n, k: 4 })).result
      expect(onchain, `call ${n}`).toBe(isSampled(seed, n, 4))
    }
  })
})

const agentSecret = process.env.FERMATA_AGENT_SECRET
const relayerSecret = process.env.FERMATA_RELAYER_SECRET
const verifierSecret = process.env.FERMATA_VERIFIER_SECRET

describe.skipIf(!d?.session || !agentSecret || !relayerSecret || !verifierSecret)(
  'sessions on a deployment (agent, relayer and verifier secrets)',
  () => {
    const contract: string = d?.session?.contract_id
    const passphrase: string = d?.network_passphrase
    const domain: Domain = { networkPassphrase: passphrase, contract }
    const server = rpcServer(rpcUrl)
    const reader = new SessionReader(contract, rpcUrl, passphrase)
    const agent = agentSecret ? Keypair.fromSecret(agentSecret) : undefined
    const relayer = relayerSecret ? new Relayer(Keypair.fromSecret(relayerSecret), server, passphrase) : undefined
    const balance = (token: string, id: string) => tokenBalance(rpcUrl, passphrase, token, id)

    /** Terms for a new session of `maxCalls` calls (every call proved), with a fresh ticket key. */
    async function newSession(maxCalls: number) {
      const ticketSeed = crypto.getRandomValues(new Uint8Array(32))
      const price = BigInt(d.service.price_per_call)
      const now = BigInt((await server.getLatestLedger()).closeTime)
      const terms: OpenTerms = {
        contract,
        token: d.token.sac,
        sessionId: fresh(),
        serviceId: d.service.id,
        maxCalls,
        ticketKey: toHex(await ed.getPublicKeyAsync(ticketSeed)),
        sampleK: 1,
        batchSize: maxCalls,
        seed: ZERO,
        expiresAt: now + 300n,
        deposit: price * BigInt(maxCalls),
      }
      return { terms, ticketSeed }
    }

    /** Settles all of a session's calls in one batch with these entries, built and signed by the SDK. */
    async function settleAll(terms: OpenTerms, ticketSeed: Uint8Array, entries: SessionEntry[]) {
      const requestHashes = entries.map(() => fresh())
      const chain = extendChain(terms.sessionId, requestHashes)
      const to = entries.length
      const ticket = await signTicket(ticketSeed, domain, terms.sessionId, to, chain)
      const statement = await signStatement(verifierSecret!, domain, {
        session_id: terms.sessionId,
        service_id: terms.serviceId,
        predicate_hash: d.service.predicate_hash,
        from: 0,
        to,
        chain,
        seed: ZERO,
        entries_hash: entriesHash(entries),
      })
      const tx = await relayer!.invoke(
        settleBatchOperation(contract, { sessionId: terms.sessionId, to, requestHashes, ticket, seed: ZERO, entries, statement }),
      )
      return { tx, chain }
    }

    it('a sponsored session: opened through the relayer, then a DELIVERED and a FAILED call settled', async () => {
      const { terms, ticketSeed } = await newSession(2)
      const { transaction } = await signSponsoredOpen({ server, networkPassphrase: passphrase, keypair: agent!, terms, validForSeconds: 60 })
      const latest = (await server.getLatestLedger()).sequence
      const opening = checkSponsoredOpen({
        transaction,
        networkPassphrase: passphrase,
        terms,
        latestLedger: latest,
        maxLedger: latest + Math.ceil(60 / LEDGER_SECONDS) + EXPIRY_SKEW_LEDGERS,
        sponsors: [relayer!.address],
      })
      const landed = await submitSponsoredOpen({ server, networkPassphrase: passphrase, open: opening, terms, relayer })
      expect(landed.via).toBe('relayer')
      expect(landed.opened).toMatchObject({ agent: agent!.publicKey(), deposit: terms.deposit, maxCalls: 2 })
      const opened = await reader.session(terms.sessionId)
      expect(opened).toMatchObject({ status: SessionStatus.Open, settled: 0, chain: terms.sessionId, ticketKey: terms.ticketKey })

      const payoutBefore = await balance(terms.token, d.service.payout)
      const agentBefore = await balance(terms.token, agent!.publicKey())
      const { tx, chain } = await settleAll(terms, ticketSeed, [provedEntry(true, fresh(), fresh()), provedEntry(false, fresh(), fresh())])
      const price = BigInt(d.service.price_per_call)
      const fee = (price * BigInt(opened!.feeBps)) / 10_000n
      const events = sessionEventsOf(tx, contract)
      const settled = events.find((e): e is BatchSettled => e.name === 'batch_settled')
      expect(settled).toMatchObject({ from: 0, to: 2, delivered: 1, failed: 1, paid: 1, payoutAmount: price - fee, fee, refund: price, chain })
      expect(events.at(-1)).toMatchObject({ name: 'session_closed', refund: 0n })
      expect(await balance(terms.token, d.service.payout)).toBe(payoutBefore + price - fee)
      expect(await balance(terms.token, agent!.publicKey())).toBe(agentBefore + price)
      expect(await reader.session(terms.sessionId)).toMatchObject({ status: SessionStatus.Closed, settled: 2, chain })
    })

    it('a session the agent opens itself; an unanswered call is refunded and the session closes', async () => {
      const { terms, ticketSeed } = await newSession(1)
      const agentBefore = await balance(terms.token, agent!.publicKey())
      const { opened } = await submitOwnOpen({ server, networkPassphrase: passphrase, keypair: agent!, terms })
      expect(opened.deposit).toBe(terms.deposit)
      expect(await balance(terms.token, agent!.publicKey())).toBe(agentBefore - terms.deposit)
      const { tx } = await settleAll(terms, ticketSeed, [unprovedEntry(false)])
      expect(sessionEventsOf(tx, contract).map((e) => e.name)).toEqual(['batch_settled', 'session_closed'])
      expect(await balance(terms.token, agent!.publicKey())).toBe(agentBefore)
      expect((await reader.session(terms.sessionId))?.status).toBe(SessionStatus.Closed)
    })
  },
)
