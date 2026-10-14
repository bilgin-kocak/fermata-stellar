// Fermata gateway entry point.
//
//   GATEWAY_CONFIG=gateway.config.json FERMATA_RELAYER_SECRET=S… GATEWAY_SECRET_KEY=… pnpm -F @fermata-stellar/gateway start
//
// Secrets come only from the environment (the scripts pass them from the Stellar CLI keystore):
//   FERMATA_RELAYER_SECRET   the relayer account: settle, claim_timeout and sponsored holds (required)
//   GATEWAY_SECRET_KEY       the mppx HMAC secret, at least 32 bytes; it also keys x402 call ids (required)
//   FEE_PAYER_SECRET         the account that pays Stellar MPP Charge and in-process x402 `exact` fees
//                            (default: the relayer; a separate account avoids sequence clashes)
//   OZ_CHANNELS_API_KEY      with config `channels` (OZ_CHANNELS_URL): OpenZeppelin Channels submits holds
//   X402_FACILITATOR_API_KEY with config `exactFacilitatorUrl` (X402_FACILITATOR_URL), if it needs one
// Other overrides: see config.ts; GATEWAY_UPSTREAM_CA (vendor CA PEM) and GATEWAY_RESOLVE
// ("host:port=ip:port,…") are used only by the unprotected fallback, which calls the vendor directly.
import { mkdirSync, readFileSync } from 'node:fs'
import { serve } from '@hono/node-server'
import * as stellarMpp from '@stellar/mpp/charge/server'
import { Keypair } from '@stellar/stellar-sdk'
import { x402Facilitator } from '@x402/core/facilitator'
import { HTTPFacilitatorClient } from '@x402/core/server'
import type { Network } from '@x402/core/types'
import { createEd25519Signer } from '@x402/stellar'
import { ExactStellarScheme } from '@x402/stellar/exact/facilitator'
import { Store } from 'mppx/server'
import { fetch as undiciFetch } from 'undici'
import {
  EscrowIndexer,
  EscrowReader,
  FermataX402Facilitator,
  Relayer,
  SessionReader,
  fermataServer,
  fermataSessionServer,
  rpcServer,
} from 'fermata-stellar-sdk'
import { createGateway, type GatewayDeps, type X402Facilitator } from './app.ts'
import { HttpAttestor } from './attestor.ts'
import { SorobanGatewayChain } from './chain.ts'
import { loadConfig } from './config.ts'
import { SessionStore, openingRecord, viewOf } from './sessions.ts'
import { CallStore } from './store.ts'
import { parseResolve, upstreamDispatcher } from './upstream.ts'

function required(name: string): string {
  const v = process.env[name]
  if (!v) throw new Error(`${name} is not set`)
  return v
}

const config = loadConfig()
const secretKey = required('GATEWAY_SECRET_KEY')
if (new TextEncoder().encode(secretKey).length < 32) throw new Error('GATEWAY_SECRET_KEY must be at least 32 bytes')
const server = rpcServer(config.rpcUrl)
const network = await server.getNetwork()
if (network.passphrase !== config.networkPassphrase) {
  throw new Error(`the RPC serves "${network.passphrase}", the config names "${config.networkPassphrase}"`)
}
const relayerKey = Keypair.fromSecret(required('FERMATA_RELAYER_SECRET'))
const feePayerSecret = process.env.FEE_PAYER_SECRET ?? relayerKey.secret()
const relayer = new Relayer(relayerKey, server, config.networkPassphrase)
const reader = new EscrowReader(config.escrow, config.rpcUrl, config.networkPassphrase)
const store = new CallStore(config.storageDir)
const channels = config.channels ? { ...config.channels, apiKey: required('OZ_CHANNELS_API_KEY') } : undefined

const fermataHandler = fermataServer({
  rpcUrl: config.rpcUrl,
  network: config.network,
  networkPassphrase: config.networkPassphrase,
  escrow: config.escrow,
  secretKey,
  relayer,
  channels,
  // Recorded before submission, so the sweeper finds the hold even if the submission's outcome is lost.
  onSponsoredHold: async (call) => {
    const now = new Date().toISOString()
    await store.put({
      callId: call.callId, serviceId: call.serviceId, method: '', target: '', requestHash: call.requestHash, paidWith: 'mpp', sponsored: true,
      agent: call.agent, deadline: '0', status: 'holding', createdAt: now, updatedAt: now,
    })
  },
})

// Stellar's MPP Charge, the unprotected MPP fallback (only for services that configure one).
const fallback = config.services.find((s) => s.unprotected)
const chargeHandler = fallback
  ? stellarMpp.charge({
      recipient: fallback.unprotected!.recipient,
      currency: (await reader.service(fallback.serviceId))?.token ?? '',
      network: config.network as never,
      rpcUrl: config.rpcUrl,
      store: Store.memory(),
      feePayer: { envelopeSigner: Keypair.fromSecret(feePayerSecret) },
    })
  : undefined

// x402: the escrowed scheme's facilitator in process; `exact` through a hosted facilitator
// (OpenZeppelin's) when configured, otherwise in process from the fee payer's account.
const x402Network = config.network as Network
const fermataFacilitator = new FermataX402Facilitator({
  rpcUrl: config.rpcUrl,
  network: x402Network,
  networkPassphrase: config.networkPassphrase,
  escrows: [config.escrow],
  relayer,
  channels,
})
let exactFacilitator: X402Facilitator | undefined
if (fallback && config.exactFacilitatorUrl) {
  const apiKey = process.env.X402_FACILITATOR_API_KEY
  const headers = apiKey ? { Authorization: `Bearer ${apiKey}` } : undefined
  exactFacilitator = new HTTPFacilitatorClient({
    url: config.exactFacilitatorUrl,
    ...(headers ? { createAuthHeaders: async () => ({ verify: headers, settle: headers, supported: headers }) } : {}),
  })
} else if (fallback) {
  exactFacilitator = new x402Facilitator().register(
    x402Network,
    new ExactStellarScheme([createEd25519Signer(feePayerSecret, x402Network)], { rpcConfig: { url: config.rpcUrl } }),
  )
}

mkdirSync(config.indexDir, { recursive: true })
const indexer = new EscrowIndexer({ rpcUrl: config.rpcUrl, escrow: config.escrow, startLedger: config.startLedger, dir: config.indexDir })
await indexer.load()

// Sessions (docs/session-escrow.md, phase 1), when a session contract is configured.
let sessions: GatewayDeps['sessions']
let sessionReader: SessionReader | undefined
let sessionIndexer: EscrowIndexer | undefined
if (config.sessionContract) {
  sessionReader = new SessionReader(config.sessionContract, config.rpcUrl, config.networkPassphrase)
  const reads = await sessionReader.escrow()
  if (reads !== config.escrow) throw new Error(`session contract ${config.sessionContract} reads escrow ${reads}, not ${config.escrow}`)
  const sessionStore = new SessionStore(config.sessions.storageDir)
  const handler = fermataSessionServer({
    rpcUrl: config.rpcUrl,
    network: config.network,
    networkPassphrase: config.networkPassphrase,
    escrow: config.escrow,
    sessionContract: config.sessionContract,
    secretKey,
    relayer,
    channels,
    lookup: async (id) => {
      const r = await sessionStore.get(id)
      return r ? viewOf(r) : undefined
    },
    // Recorded before submission, so the sweeper finds the session even if the outcome is lost.
    onOpen: async (opened) => {
      await sessionStore.put(openingRecord(opened))
    },
  })
  const tokens = (await Promise.all(config.services.map((s) => reader.service(s.serviceId)))).map((s) => s?.token).filter((t): t is string => !!t)
  mkdirSync(config.sessions.indexDir, { recursive: true })
  sessionIndexer = new EscrowIndexer({
    rpcUrl: config.rpcUrl,
    escrow: config.sessionContract,
    kind: 'session',
    tokens: [...new Set(tokens)],
    startLedger: config.sessions.startLedger,
    dir: config.sessions.indexDir,
  })
  await sessionIndexer.load()
  sessions = {
    handler,
    store: sessionStore,
    batchSize: config.sessions.batchSize,
    maxCalls: config.sessions.maxCalls,
    maxDurationSeconds: config.sessions.maxDurationSeconds,
    indexer: sessionIndexer,
  }
}

const dispatcher = upstreamDispatcher(
  parseResolve(process.env.GATEWAY_RESOLVE),
  process.env.GATEWAY_UPSTREAM_CA ? readFileSync(process.env.GATEWAY_UPSTREAM_CA) : undefined,
)

const gateway = await createGateway({
  config,
  chain: new SorobanGatewayChain(reader, relayer, config.network, sessionReader),
  attestor: new HttpAttestor(config.attestorUrl),
  store,
  secretKey,
  fermataHandler,
  chargeHandler,
  x402: { fermata: fermataFacilitator, exact: exactFacilitator },
  indexer,
  sessions,
  fetchUpstream: async (url, init) => (await undiciFetch(url, { ...(init as object), dispatcher })) as unknown as Response,
  dashboardDir: process.env.GATEWAY_DASHBOARD_DIR ?? new URL('../../dashboard/dist', import.meta.url).pathname,
  verifierFiles: { caPath: process.env.GATEWAY_UPSTREAM_CA, predicateDirs: [new URL('../../../predicates', import.meta.url).pathname] },
})

const loop = (name: string, everyMs: number, run: () => Promise<unknown>) =>
  setInterval(() => {
    run().catch((e) => console.error(`[gateway] ${name} failed: ${(e as Error).message}`))
  }, everyMs).unref()
loop('sweep', config.sweepIntervalMs, gateway.sweep)
loop('indexer', config.indexIntervalMs, () => indexer.poll())
indexer.poll().catch((e) => console.error(`[gateway] indexer: ${(e as Error).message}`))
if (sessionIndexer) {
  loop('session indexer', config.indexIntervalMs, () => sessionIndexer.poll())
  sessionIndexer.poll().catch((e) => console.error(`[gateway] session indexer: ${(e as Error).message}`))
}

serve({ fetch: gateway.app.fetch, port: config.port, hostname: config.host }, () => {
  console.log(
    `[gateway] listening on http://${config.host}:${config.port}: escrow ${config.escrow} (${config.network}), relayer ${relayer.address}, ` +
      `${gateway.services.size} service(s), attestor ${config.attestorUrl}, holds via ${channels ? 'OpenZeppelin Channels' : 'the relayer'}, ` +
      `x402 exact via ${config.exactFacilitatorUrl ?? (exactFacilitator ? 'this process' : 'none')}, ` +
      `sessions ${config.sessionContract ? `on ${config.sessionContract} (B = ${config.sessions.batchSize})` : 'off'}`,
  )
})
