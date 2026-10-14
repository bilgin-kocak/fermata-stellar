// Copied from Fermata `apps/gateway/src/upstream.ts` @ d7cc642 (github.com/bilgin-kocak/fermata, MIT);
// only the next line changed: the fallback it serves is Stellar's MPP Charge and x402 `exact`.
// The undici dispatcher for the unprotected fallback (Charge, exact), which calls the vendor directly.
// GATEWAY_RESOLVE ("host:port=ip:port,…") pins vendor hostnames to addresses, like curl --resolve.
import { lookup as dnsLookup, type LookupAddress } from 'node:dns'
import { Agent } from 'undici'

export type ResolveMap = Map<string, string>

export function parseResolve(spec = ''): ResolveMap {
  return new Map(
    spec
      .split(',')
      .filter(Boolean)
      .map((r) => r.split('=') as [string, string]),
  )
}

type LookupCb = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void

/** A `net.connect` lookup that answers pinned hostnames and defers everything else to DNS. */
export function pinnedLookup(resolve: ResolveMap) {
  return (hostname: string, options: { all?: boolean }, cb: LookupCb) => {
    const target = [...resolve.entries()].find(([k]) => k.split(':')[0] === hostname)?.[1]?.split(':')[0]
    // Node ≥ 22.21 asks for { all: true } (Happy Eyeballs) and then expects an address list.
    if (target && options.all) return cb(null, [{ address: target, family: 4 }])
    if (target) return cb(null, target, 4)
    return dnsLookup(hostname, options as never, cb as never)
  }
}

export function upstreamDispatcher(resolve: ResolveMap, ca?: Buffer) {
  return new Agent({ connect: { ca, lookup: pinnedLookup(resolve) as never } })
}
