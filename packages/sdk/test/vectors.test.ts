// Golden-vector parity: the SDK encodes, signs and verifies verdicts byte for byte like the contract
// and `fermata-verdict` (test-vectors/verdict-v1.json), and accepts the verdicts the attestor signed
// for real TLSNotary presentations (test-vectors/attest-v1.json).
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import {
  CANONICAL_LEN,
  MESSAGE_LEN,
  NETWORK_PASSPHRASES,
  Outcome,
  canonicalVerdict,
  networkId,
  requestHash,
  serviceId,
  signVerdict,
  toContractVerdict,
  toHex,
  verdictMessage,
  verifyVerdict,
  type Domain,
} from '../src/index.ts'

const root = new URL('../../../', import.meta.url)
const vectors = JSON.parse(readFileSync(new URL('test-vectors/verdict-v1.json', root), 'utf8'))
const attest = JSON.parse(readFileSync(new URL('test-vectors/attest-v1.json', root), 'utf8'))

type VerdictVector = (typeof vectors.verdicts)[number]
const domainOf = (v: VerdictVector): Domain => ({ networkPassphrase: v.network_passphrase, contract: v.contract })

describe('verdict-v1.json', () => {
  const seed = vectors.signer.seed as string

  it('rebuilds every canonical verdict and message', () => {
    for (const v of vectors.verdicts) {
      expect(toHex(networkId(v.network_passphrase)), v.name).toBe(v.network_id)
      const canonical = canonicalVerdict(v.verdict)
      expect(canonical.length).toBe(CANONICAL_LEN)
      expect(toHex(canonical), v.name).toBe(v.canonical)
      const message = verdictMessage(domainOf(v), v.verdict)
      expect(message.length).toBe(MESSAGE_LEN)
      expect(toHex(message), v.name).toBe(v.message)
      // the contract id may be given as C… or as hex
      expect(toHex(verdictMessage({ ...domainOf(v), contract: v.contract_id }, v.verdict))).toBe(v.message)
    }
  })

  it('reproduces every signature from the seed and verifies it', async () => {
    for (const v of vectors.verdicts) {
      expect(await signVerdict(seed, domainOf(v), v.verdict), v.name).toBe(v.signature)
      expect(await verifyVerdict(vectors.signer.address, domainOf(v), v.verdict, v.signature), v.name).toBe(true)
    }
  })

  it('a signature for another network or escrow does not verify here', async () => {
    const [testnet, , mainnet, otherEscrow] = vectors.verdicts as VerdictVector[]
    const here = domainOf(testnet!)
    expect(await verifyVerdict(vectors.signer.public_key, here, testnet!.verdict, mainnet!.signature)).toBe(false)
    expect(await verifyVerdict(vectors.signer.public_key, here, testnet!.verdict, otherEscrow!.signature)).toBe(false)
    expect(await verifyVerdict(vectors.signer.public_key, here, testnet!.verdict, testnet!.signature)).toBe(true)
  })

  it('every field and the domain are signed', async () => {
    const v = vectors.verdicts[0] as VerdictVector
    const flip = (h: string) => (h.startsWith('0') ? '1' : '0') + h.slice(1)
    const fields = ['call_id', 'service_id', 'request_hash', 'predicate_hash', 'presentation_hash', 'response_hash'] as const
    for (const f of fields) {
      const tampered = { ...v.verdict, [f]: flip(v.verdict[f]) }
      expect(await verifyVerdict(vectors.signer.public_key, domainOf(v), tampered, v.signature), f).toBe(false)
    }
    for (const tampered of [
      { ...v.verdict, outcome: Outcome.Failed },
      { ...v.verdict, issued_at: v.verdict.issued_at + 1 },
    ]) {
      expect(await verifyVerdict(vectors.signer.public_key, domainOf(v), tampered, v.signature)).toBe(false)
    }
    const otherNetwork = { ...domainOf(v), networkPassphrase: NETWORK_PASSPHRASES.local }
    expect(await verifyVerdict(vectors.signer.public_key, otherNetwork, v.verdict, v.signature)).toBe(false)
  })

  it('rejects malformed input', async () => {
    const v = vectors.verdicts[0] as VerdictVector
    expect(() => canonicalVerdict({ ...v.verdict, call_id: '11' })).toThrow()
    expect(() => canonicalVerdict({ ...v.verdict, outcome: -1 })).toThrow()
    expect(() => canonicalVerdict({ ...v.verdict, issued_at: -1 })).toThrow()
    expect(await verifyVerdict(vectors.signer.public_key, domainOf(v), v.verdict, '00')).toBe(false)
  })
})

describe('attest-v1.json (verdicts the attestor signed for real presentations)', () => {
  const domain: Domain = { networkPassphrase: attest.network_passphrase, contract: attest.contract }
  const cases = [
    ['delivered', Outcome.Delivered],
    ['failed', Outcome.Failed],
  ] as const

  it('rebuilds the messages and verifies the signatures', async () => {
    for (const [name, outcome] of cases) {
      const c = attest[name]
      expect(c.verdict.outcome).toBe(outcome)
      expect(toHex(verdictMessage(domain, c.verdict)), name).toBe(c.message)
      expect(await verifyVerdict(attest.signer.address, domain, c.verdict, c.signature), name).toBe(true)
    }
  })

  it('derives the service ids and request hashes the escrow holds', () => {
    for (const [name] of cases) {
      const c = attest[name]
      expect(serviceId(attest.owner, `0x${c.label}`), name).toBe(c.service_id)
      expect(requestHash(c.service_id, 'GET', attest.target), name).toBe(c.verdict.request_hash)
    }
  })

  it('converts a verdict to the escrow client form', () => {
    const v = attest.delivered.verdict
    const onchain = toContractVerdict(v)
    expect(onchain.call_id.toString('hex')).toBe(v.call_id)
    expect(onchain.presentation_hash.toString('hex')).toBe(v.presentation_hash)
    expect(onchain.issued_at).toBe(BigInt(v.issued_at))
    expect(onchain.outcome).toBe(Outcome.Delivered)
    expect(() => toContractVerdict({ ...v, outcome: 3 })).toThrow()
  })
})
