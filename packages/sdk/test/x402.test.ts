// The `fermata` x402 requirements: a call id only the server can mint, bound to one request.
import { describe, expect, it } from 'vitest'
import { contractAddress, fermataRequirements, fermataRequirementsProblem, holdTermsOf, type FermataOffer } from '../src/index.ts'

const offer: FermataOffer = {
  network: 'stellar:testnet',
  escrow: contractAddress(new Uint8Array(32).fill(0xe5)),
  token: contractAddress(new Uint8Array(32).fill(0x70)),
  amount: 100_000n,
  serviceId: '5e'.repeat(32),
  requestHash: 'ab'.repeat(32),
}
const secret = 'a gateway secret of at least thirty-two bytes'

describe('fermata x402 requirements', () => {
  it('carry the hold the agent signs, with a fresh call id each time', () => {
    const a = fermataRequirements(offer, secret)
    const b = fermataRequirements(offer, secret)
    expect(a.scheme).toBe('fermata')
    expect(a.payTo).toBe(offer.escrow)
    expect(a.asset).toBe(offer.token)
    expect(a.amount).toBe('100000')
    expect(holdTermsOf(a)).toMatchObject({ escrow: offer.escrow, serviceId: offer.serviceId, requestHash: offer.requestHash, token: offer.token, amount: 100_000n })
    expect(holdTermsOf(a).callId).not.toBe(holdTermsOf(b).callId)
  })

  it('are accepted back only unchanged, from this server, for this request, before they expire', () => {
    const r = fermataRequirements(offer, secret)
    expect(fermataRequirementsProblem(r, offer, secret)).toBeUndefined()
    expect(fermataRequirementsProblem(r, offer, 'another secret, also thirty-two bytes long')).toMatch(/did not issue/)
    expect(fermataRequirementsProblem(r, { ...offer, requestHash: 'cd'.repeat(32) }, secret)).toMatch(/another request/)
    expect(fermataRequirementsProblem({ ...r, amount: '1' }, offer, secret)).toMatch(/price/)
    const forged = { ...r, extra: { ...r.extra, callId: 'ff'.repeat(32) } }
    expect(fermataRequirementsProblem(forged, offer, secret)).toMatch(/did not issue/)
    const later = Date.now() + 301_000
    expect(fermataRequirementsProblem(r, offer, secret, later)).toMatch(/expired/)
    expect(fermataRequirementsProblem({ ...r, extra: { ...r.extra, expires: 'soon' } }, offer, secret)).toMatch(/malformed/)
  })
})
