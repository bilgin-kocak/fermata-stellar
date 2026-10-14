// The escrow's events and the token transfers that move its money, decoded from Soroban events.
//
// An escrow event's topics are its name (a symbol) followed by the struct's `#[topic]` fields; its
// value is a map of the other fields (contracts/escrow/src/events.rs). A Stellar Asset Contract's
// `transfer` event has the topics ("transfer", from, to, "CODE:ISSUER") and the amount as its value.
// On Tempo every movement carried the call id as a memo; here the escrow's event and the token's
// transfers share a transaction, which is how reconciliation joins them.
import { rpc, xdr } from '@stellar/stellar-sdk'
import { toHex, type Hex } from './hex.ts'
import { contractOf, field, scAddress, scBigint, scBytes, scFields, scHex32, scSymbol } from './soroban.ts'

export type ServiceRegistered = {
  name: 'service_registered'
  serviceId: Hex
  owner: string
  token: string
  label: Hex
  payout: string
  verifier: Hex
  pricePerCall: bigint
  settlementWindow: number
}
export type Held = { name: 'held'; callId: Hex; serviceId: Hex; agent: string; amount: bigint; requestHash: Hex }
export type Released = {
  name: 'released'
  callId: Hex
  serviceId: Hex
  payout: string
  amount: bigint
  fee: bigint
  presentationHash: Hex
}
export type Refunded = {
  name: 'refunded'
  callId: Hex
  serviceId: Hex
  agent: string
  amount: bigint
  presentationHash: Hex
}
export type TimedOut = { name: 'timed_out'; callId: Hex; serviceId: Hex; agent: string; amount: bigint }
export type FeeBpsUpdated = { name: 'fee_bps_updated'; feeBps: number }
export type TreasuryUpdated = { name: 'treasury_updated'; treasury: string }

export type EscrowEventData = ServiceRegistered | Held | Released | Refunded | TimedOut | FeeBpsUpdated | TreasuryUpdated
/** A SEP-41 transfer, as a Stellar Asset Contract emits it. */
export type TransferData = { name: 'transfer'; token: string; from: string; to: string; amount: bigint; asset?: string }

/** Where an event happened. `id` is the RPC's event id (ledger order, then position). */
export type EventPosition = { ledger: number; txHash: Hex; id: string; ledgerClosedAt?: string }
export type EscrowEvent = EscrowEventData & EventPosition
export type TransferEvent = TransferData & EventPosition

const u32 = (v: xdr.ScVal): number => {
  const n = scBigint(v)
  if (n < 0n || n > 0xffffffffn) throw new Error(`not a u32: ${n}`)
  return Number(n)
}

/** Decodes one escrow event; returns undefined for an event this version does not know. */
export function decodeEscrowEvent(topics: readonly xdr.ScVal[], value: xdr.ScVal): EscrowEventData | undefined {
  const name = topics[0] ? scSymbol(topics[0]) : undefined
  const t = (i: number) => {
    const v = topics[i]
    if (!v) throw new Error(`${name}: missing topic ${i}`)
    return v
  }
  switch (name) {
    case 'service_registered': {
      const f = scFields(value)
      return {
        name,
        serviceId: scHex32(t(1)),
        owner: scAddress(t(2)),
        token: scAddress(t(3)),
        label: toHex(scBytes(field(f, 'label'))),
        payout: scAddress(field(f, 'payout')),
        verifier: scHex32(field(f, 'verifier')),
        pricePerCall: scBigint(field(f, 'price_per_call')),
        settlementWindow: u32(field(f, 'settlement_window')),
      }
    }
    case 'held': {
      const f = scFields(value)
      return {
        name,
        callId: scHex32(t(1)),
        serviceId: scHex32(t(2)),
        agent: scAddress(t(3)),
        amount: scBigint(field(f, 'amount')),
        requestHash: scHex32(field(f, 'request_hash')),
      }
    }
    case 'released': {
      const f = scFields(value)
      return {
        name,
        callId: scHex32(t(1)),
        serviceId: scHex32(t(2)),
        payout: scAddress(t(3)),
        amount: scBigint(field(f, 'amount')),
        fee: scBigint(field(f, 'fee')),
        presentationHash: scHex32(field(f, 'presentation_hash')),
      }
    }
    case 'refunded': {
      const f = scFields(value)
      return {
        name,
        callId: scHex32(t(1)),
        serviceId: scHex32(t(2)),
        agent: scAddress(t(3)),
        amount: scBigint(field(f, 'amount')),
        presentationHash: scHex32(field(f, 'presentation_hash')),
      }
    }
    case 'timed_out': {
      const f = scFields(value)
      return { name, callId: scHex32(t(1)), serviceId: scHex32(t(2)), agent: scAddress(t(3)), amount: scBigint(field(f, 'amount')) }
    }
    case 'fee_bps_updated':
      return { name, feeBps: u32(field(scFields(value), 'fee_bps')) }
    case 'treasury_updated':
      return { name, treasury: scAddress(t(1)) }
    default:
      return undefined
  }
}

/** Decodes a SEP-41 `transfer` event of `token`; undefined for any other event. */
export function decodeTransfer(token: string, topics: readonly xdr.ScVal[], value: xdr.ScVal): TransferData | undefined {
  if (topics.length < 3 || scSymbol(topics[0]!) !== 'transfer') return undefined
  // CAP-67: the amount, or a map {amount, to_muxed_id} when the recipient is muxed.
  const amount =
    value.switch().value === xdr.ScValType.scvMap().value ? scBigint(field(scFields(value), 'amount')) : scBigint(value)
  const asset = topics[3]?.switch().value === xdr.ScValType.scvString().value ? topics[3].str().toString() : undefined
  return { name: 'transfer', token, from: scAddress(topics[1]!), to: scAddress(topics[2]!), amount, ...(asset ? { asset } : {}) }
}

/** The contract events of a successful transaction, in order, with their contract ids. */
export function contractEventsOf(tx: rpc.Api.GetSuccessfulTransactionResponse): { contract: string; topics: xdr.ScVal[]; value: xdr.ScVal }[] {
  const out: { contract: string; topics: xdr.ScVal[]; value: xdr.ScVal }[] = []
  for (const opEvents of tx.events?.contractEventsXdr ?? []) {
    for (const e of opEvents) {
      const contract = contractOf(e)
      if (!contract || e.type().name !== 'contract') continue
      const body = e.body().v0()
      out.push({ contract, topics: body.topics(), value: body.data() })
    }
  }
  return out
}

/** The escrow events in a successful transaction. */
export function escrowEventsOf(tx: rpc.Api.GetSuccessfulTransactionResponse, escrow: string): EscrowEventData[] {
  return contractEventsOf(tx)
    .filter((e) => e.contract === escrow)
    .map((e) => decodeEscrowEvent(e.topics, e.value))
    .filter((e): e is EscrowEventData => e !== undefined)
}

/** The transfers of `token` in a successful transaction. */
export function transfersOf(tx: rpc.Api.GetSuccessfulTransactionResponse, token: string): TransferData[] {
  return contractEventsOf(tx)
    .filter((e) => e.contract === token)
    .map((e) => decodeTransfer(token, e.topics, e.value))
    .filter((e): e is TransferData => e !== undefined)
}

/** JSON-safe copy of an event (bigints as decimal strings), for APIs and files. */
export function eventToJson<E extends object>(event: E): { [K in keyof E]: E[K] extends bigint ? string : E[K] } {
  return Object.fromEntries(Object.entries(event).map(([k, v]) => [k, typeof v === 'bigint' ? v.toString() : v])) as never
}
