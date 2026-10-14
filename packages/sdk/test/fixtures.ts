// Synthetic indexed events for the scores and reconciliation tests.
import { sha256 } from '@noble/hashes/sha2.js'
import { accountAddress, contractAddress, toHex, utf8, type IndexedEvent } from '../src/index.ts'

export const escrow = contractAddress(new Uint8Array(32).fill(0xe5))
export const token = contractAddress(new Uint8Array(32).fill(0x70))
export const owner = accountAddress(new Uint8Array(32).fill(0x01))
export const payout = accountAddress(new Uint8Array(32).fill(0x02))
export const treasury = accountAddress(new Uint8Array(32).fill(0x03))
export const agents = [accountAddress(new Uint8Array(32).fill(0xa1)), accountAddress(new Uint8Array(32).fill(0xa2))]
export const h = (s: string) => toHex(sha256(utf8(s)))
export const A = h('service A')
export const B = h('service B')

let ledger = 10
let n = 0
const pos = (tx: string) => {
  ledger++
  return { ledger, txHash: h(tx), id: `${String(ledger).padStart(10, '0')}-${String(n++).padStart(10, '0')}` }
}

export function registered(serviceId: string, verifier = h('verifier')): IndexedEvent[] {
  const p = pos(`register ${serviceId}`)
  return [
    { name: 'treasury_updated', treasury, ...pos('deploy') },
    { name: 'service_registered', serviceId, owner, token, label: '00'.repeat(12), payout, verifier, pricePerCall: 10_000n, settlementWindow: 120, ...p },
  ]
}

export type Outcome = 'released' | 'failed' | 'timeout' | 'open'

/** One call's events and its token transfers, as the indexer would record them. */
export function call(serviceId: string, outcome: Outcome, agent = agents[0]!, amount = 10_000n, fee = 50n): IndexedEvent[] {
  const callId = h(`call ${n}`)
  const hp = pos(`hold ${callId}`)
  const out: IndexedEvent[] = [
    { name: 'held', callId, serviceId, agent, amount, requestHash: h(`request ${callId}`), ...hp },
    { name: 'transfer', token, from: agent, to: escrow, amount, ...hp, id: `${hp.id}a` },
  ]
  if (outcome === 'open') return out
  const sp = pos(`settle ${callId}`)
  if (outcome === 'released') {
    out.push(
      { name: 'released', callId, serviceId, payout, amount, fee, presentationHash: h(`p ${callId}`), ...sp },
      { name: 'transfer', token, from: escrow, to: payout, amount: amount - fee, ...sp, id: `${sp.id}a` },
      { name: 'transfer', token, from: escrow, to: treasury, amount: fee, ...sp, id: `${sp.id}b` },
    )
  } else if (outcome === 'failed') {
    out.push(
      { name: 'refunded', callId, serviceId, agent, amount, presentationHash: h(`p ${callId}`), ...sp },
      { name: 'transfer', token, from: escrow, to: agent, amount, ...sp, id: `${sp.id}a` },
    )
  } else {
    out.push(
      { name: 'timed_out', callId, serviceId, agent, amount, ...sp },
      { name: 'transfer', token, from: escrow, to: agent, amount, ...sp, id: `${sp.id}a` },
    )
  }
  return out
}

export const calls = (serviceId: string, outcomes: Outcome[], agent = agents[0]!) => outcomes.flatMap((o) => call(serviceId, o, agent))
