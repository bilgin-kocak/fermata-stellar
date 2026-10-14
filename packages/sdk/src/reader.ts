// Read-only views of the escrow and of chain time, by simulation through the generated client: no
// account and no key needed. Services are immutable, so they are cached once found.
import { Buffer } from 'buffer'
import { Client as EscrowClient, Status } from './escrow/bindings.ts'
import { fromHex, toHex, type Hex } from './hex.ts'
import { rpcServer } from './soroban.ts'

export type ServiceInfo = {
  serviceId: Hex
  owner: string
  label: Hex
  payout: string
  token: string
  verifier: Hex
  pricePerCall: bigint
  settlementWindow: number
  predicateHash: Hex
  originHash: Hex
  notaryKeyHash: Hex
}

export type HoldInfo = {
  callId: Hex
  agent: string
  serviceId: Hex
  requestHash: Hex
  amount: bigint
  heldAt: bigint
  deadline: bigint
  feeBps: number
  status: Status
}

export { Status as HoldStatus }

export class EscrowReader {
  readonly client: EscrowClient
  private readonly services = new Map<string, ServiceInfo>()

  constructor(
    readonly escrow: string,
    readonly rpcUrl: string,
    readonly networkPassphrase: string,
  ) {
    this.client = new EscrowClient({
      contractId: escrow,
      networkPassphrase,
      rpcUrl,
      allowHttp: rpcUrl.startsWith('http://'),
    })
  }

  /** The registered service, or undefined. */
  async service(serviceId: Hex): Promise<ServiceInfo | undefined> {
    const key = serviceId.toLowerCase()
    const cached = this.services.get(key)
    if (cached) return cached
    const s = (await this.client.get_service({ service_id: Buffer.from(fromHex(serviceId, 32)) })).result
    if (!s) return undefined
    const info: ServiceInfo = {
      serviceId: key,
      owner: s.owner,
      label: toHex(s.label),
      payout: s.payout,
      token: s.token,
      verifier: toHex(s.verifier),
      pricePerCall: BigInt(s.price_per_call),
      settlementWindow: Number(s.settlement_window),
      predicateHash: toHex(s.predicate_hash),
      originHash: toHex(s.origin_hash),
      notaryKeyHash: toHex(s.notary_key_hash),
    }
    this.services.set(key, info)
    return info
  }

  /** The hold for `callId`, or undefined when the call id was never held. */
  async hold(callId: Hex): Promise<HoldInfo | undefined> {
    const h = (await this.client.get_hold({ call_id: Buffer.from(fromHex(callId, 32)) })).result
    if (!h) return undefined
    return {
      callId: callId.toLowerCase(),
      agent: h.agent,
      serviceId: toHex(h.service_id),
      requestHash: toHex(h.request_hash),
      amount: BigInt(h.amount),
      heldAt: BigInt(h.held_at),
      deadline: BigInt(h.deadline),
      feeBps: Number(h.fee_bps),
      status: h.status,
    }
  }

  /** The latest ledger's close time (unix seconds): the clock `settle` and `claim_timeout` check. */
  async now(): Promise<bigint> {
    const latest = await rpcServer(this.rpcUrl).getLatestLedger()
    return BigInt(latest.closeTime)
  }
}
