// Gateway configuration: a JSON file (GATEWAY_CONFIG) with environment overrides.
//
// Ported from Fermata `apps/gateway/src/config.ts` @ d7cc642 (github.com/bilgin-kocak/fermata, MIT).
// Kept: services with their upstream, forwarded headers and upstream credential (only the three
// headers whose values the prover hides), the storage directory and the sweep interval. Changed for
// Stellar: the network (CAIP-2 and passphrase), the RPC URL and the escrow `C…` instead of a chain
// and an address; the unprotected fallback pays the vendor's account (`G…`) through Stellar's MPP
// Charge or x402 `exact` instead of `tempo`; where events are indexed; and OpenZeppelin's services.
// Secrets never live in the file: they come from the environment (see main.ts).
import { readFileSync } from 'node:fs'
import { NETWORK_PASSPHRASES, networkPassphrase, type Hex } from 'fermata-stellar-sdk'

export type ServiceConfig = {
  serviceId: Hex
  /** Upstream origin, e.g. https://vendor.fermata.test:8443 (must match the on-chain origin hash). */
  upstream: string
  /** Agent request headers forwarded upstream (lower-case). Default: content-type, accept. */
  forwardHeaders?: string[]
  /** Upstream credential held by the gateway, sent as `header: value of env var` (hidden in proofs). */
  upstreamAuth?: { header: string; env: string }
  /** Example path for discovery. */
  examplePath?: string
  summary?: string
  /**
   * Unprotected fallback: Stellar's MPP Charge and x402 `exact`, paid straight to `recipient` (the
   * vendor's account, which needs a trustline to the token), with no escrow and no proof.
   * `amount` in base units; default: the service's price.
   */
  unprotected?: { recipient: string; amount?: string }
}

export type GatewayConfig = {
  port: number
  host: string
  realm: string
  /** CAIP-2 network id; `stellar:testnet` also names a local network run with testnet's passphrase. */
  network: string
  networkPassphrase: string
  rpcUrl: string
  /** The escrow contract (`C…`). */
  escrow: string
  attestorUrl: string
  storageDir: string
  /** Where the event indexer keeps its files. */
  indexDir: string
  /** First ledger the indexer reads (the escrow's deployment ledger); default: the oldest the RPC has. */
  startLedger?: number
  sweepIntervalMs: number
  indexIntervalMs: number
  /** OpenZeppelin's Channels service, used to submit sponsored holds (its API key: OZ_CHANNELS_API_KEY). */
  channels?: { baseUrl: string; pluginId?: string }
  /**
   * The x402 facilitator for `exact` (its API key, if it needs one: X402_FACILITATOR_API_KEY), e.g.
   * OpenZeppelin's https://channels.openzeppelin.com/x402/testnet. Without it `exact` is facilitated
   * in this process from the fee payer's account, which is how a local network runs.
   */
  exactFacilitatorUrl?: string
  /** Block explorer for links (stellar.expert on testnet; none on a local network). */
  explorer?: string | null
  services: ServiceConfig[]
}

const RPC_DEFAULTS: Record<string, string> = {
  'stellar:testnet': 'https://soroban-testnet.stellar.org',
  'stellar:local': 'http://localhost:8000/rpc',
}

/** `gateway.config.json` (path from GATEWAY_CONFIG) with environment overrides. */
export function loadConfig(path = process.env.GATEWAY_CONFIG ?? 'gateway.config.json', env = process.env): GatewayConfig {
  const file = JSON.parse(readFileSync(path, 'utf8')) as Partial<GatewayConfig>
  const network = env.STELLAR_NETWORK ?? file.network ?? 'stellar:testnet'
  const cfg: GatewayConfig = {
    port: Number(env.GATEWAY_PORT ?? file.port ?? 4300),
    host: env.GATEWAY_HOST ?? file.host ?? '127.0.0.1',
    realm: env.GATEWAY_REALM ?? file.realm ?? 'localhost',
    network,
    networkPassphrase: env.STELLAR_NETWORK_PASSPHRASE ?? file.networkPassphrase ?? networkPassphrase(network),
    rpcUrl: env.STELLAR_RPC_URL ?? file.rpcUrl ?? RPC_DEFAULTS[network] ?? '',
    escrow: env.FERMATA_ESCROW ?? file.escrow ?? '',
    attestorUrl: env.ATTESTOR_URL ?? file.attestorUrl ?? 'http://127.0.0.1:7048',
    storageDir: env.GATEWAY_STORAGE ?? file.storageDir ?? 'storage/calls',
    indexDir: env.GATEWAY_INDEX ?? file.indexDir ?? 'storage/index',
    startLedger: env.GATEWAY_START_LEDGER ? Number(env.GATEWAY_START_LEDGER) : file.startLedger,
    sweepIntervalMs: Number(env.GATEWAY_SWEEP_MS ?? file.sweepIntervalMs ?? 10_000),
    indexIntervalMs: Number(env.GATEWAY_INDEX_MS ?? file.indexIntervalMs ?? 5_000),
    channels: env.OZ_CHANNELS_URL ? { baseUrl: env.OZ_CHANNELS_URL, pluginId: env.OZ_CHANNELS_PLUGIN_ID } : file.channels,
    exactFacilitatorUrl: env.X402_FACILITATOR_URL ?? file.exactFacilitatorUrl,
    explorer: null,
    services: file.services ?? [],
  }
  // stellar.expert only for the real testnet: a local network with testnet's passphrase has no explorer.
  const realTestnet = cfg.networkPassphrase === NETWORK_PASSPHRASES.testnet && !/\/\/(localhost|127\.0\.0\.1)[:/]/.test(cfg.rpcUrl)
  cfg.explorer = env.GATEWAY_EXPLORER !== undefined ? env.GATEWAY_EXPLORER || null : (file.explorer ?? (realTestnet ? 'https://stellar.expert/explorer/testnet' : null))
  if (!/^C[A-Z2-7]{55}$/.test(cfg.escrow)) throw new Error('escrow contract missing or malformed (FERMATA_ESCROW or config.escrow)')
  if (!cfg.rpcUrl) throw new Error('no RPC URL for this network (STELLAR_RPC_URL or config.rpcUrl)')
  if (cfg.services.length === 0) throw new Error('no services configured')
  for (const s of cfg.services) {
    // The prover hides only these headers' values from the presentation (prove.rs).
    if (s.upstreamAuth && !['authorization', 'cookie', 'proxy-authorization'].includes(s.upstreamAuth.header.toLowerCase())) {
      throw new Error(`service ${s.serviceId}: upstreamAuth.header ${s.upstreamAuth.header} would appear in every proof; use Authorization, Cookie or Proxy-Authorization`)
    }
    if (s.unprotected && !/^G[A-Z2-7]{55}$/.test(s.unprotected.recipient)) {
      throw new Error(`service ${s.serviceId}: unprotected.recipient must be an account (G…)`)
    }
  }
  return cfg
}
