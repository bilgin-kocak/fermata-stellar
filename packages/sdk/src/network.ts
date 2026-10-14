// Stellar networks as payment protocols name them (CAIP-2), and their passphrases.
//
// MPP and x402 name a network `stellar:testnet` or `stellar:pubnet`. The SDK also accepts
// `stellar:futurenet` and `stellar:local`; neither is a registered CAIP-2 id, and both are meant for
// development only. A local quickstart network can also run with testnet's passphrase (CI does), in
// which case it is `stellar:testnet` to every library.
import { NETWORK_PASSPHRASES } from './verdict.ts'

export const STELLAR_TESTNET = 'stellar:testnet'
export const STELLAR_PUBNET = 'stellar:pubnet'

const BY_CAIP2: Record<string, string> = {
  [STELLAR_TESTNET]: NETWORK_PASSPHRASES.testnet,
  [STELLAR_PUBNET]: NETWORK_PASSPHRASES.mainnet,
  'stellar:futurenet': NETWORK_PASSPHRASES.futurenet,
  'stellar:local': NETWORK_PASSPHRASES.local,
}

/** The passphrase of a CAIP-2 Stellar network. Throws for an unknown id. */
export function networkPassphrase(network: string): string {
  const p = BY_CAIP2[network]
  if (!p) throw new Error(`unknown Stellar network ${JSON.stringify(network)}`)
  return p
}

/** The CAIP-2 id of a passphrase, or undefined for a network that has none. */
export function caip2(passphrase: string): string | undefined {
  return Object.entries(BY_CAIP2).find(([, p]) => p === passphrase)?.[0]
}
