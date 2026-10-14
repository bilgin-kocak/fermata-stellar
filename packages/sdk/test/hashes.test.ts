// Ported from Fermata `packages/sdk/test/hashes.test.ts` and `requestHash.test.ts` @ d7cc642: the
// same vectors, shared with the attestor and `fermata-verdict` (test-vectors/verdict-v1.json).
import { readFileSync } from 'node:fs'
import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, it } from 'vitest'
import { canonicalOrigin, notaryKeyHash, originHash, predicateHash, requestHash, toHex } from '../src/index.ts'

const root = new URL('../../../', import.meta.url)
const vectors = JSON.parse(readFileSync(new URL('test-vectors/verdict-v1.json', root), 'utf8'))
const id = (byte: string) => '00'.repeat(31) + byte

describe('registration hashes', () => {
  it('originHash matches the attestor', () => {
    expect(originHash('https://vendor.fermata.test:8443')).toBe(
      '99d1433da9b4903068a8548272ad3128e24be018828f8b1f14282b37b8261f29',
    )
    expect(originHash('https://Vendor.Fermata.Test:8443/')).toBe(originHash('https://vendor.fermata.test:8443'))
    expect(originHash(vectors.hashes.origin_hash.origin)).toBe(vectors.hashes.origin_hash.value)
  })

  it('canonicalises like the attestor', () => {
    expect(canonicalOrigin('https://api.example.com:443')).toBe('https://api.example.com')
    for (const bad of ['http://a.com', 'https://a.com/x', 'https://a.com?q', 'https://u@a.com', 'https://', 'https://a.com:99999']) {
      expect(() => canonicalOrigin(bad), bad).toThrow()
    }
  })

  it('notaryKeyHash matches the attestor', () => {
    expect(notaryKeyHash('0x02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27')).toBe(
      '138b5a9c7e4489edde45496ce6770b6d91d5a0bcebb81ead85a3704242008aff',
    )
    expect(notaryKeyHash(vectors.hashes.notary_key_hash.key)).toBe(vectors.hashes.notary_key_hash.value)
    expect(() => notaryKeyHash('0x1234')).toThrow()
  })

  it('predicateHash of the demo predicate matches the vectors', () => {
    const bytes = readFileSync(new URL('predicates/quote-v1.json', root))
    expect(predicateHash(bytes)).toBe(vectors.hashes.predicate_hash.value)
    const attest = JSON.parse(readFileSync(new URL('test-vectors/attest-v1.json', root), 'utf8'))
    expect(predicateHash(bytes)).toBe(attest.predicate_hash)
  })
})

describe('requestHash', () => {
  it('matches the attestor and fermata-verdict for the shared request', () => {
    expect(requestHash(id('01'), 'POST', '/v1/quote', '{"symbol":"BTC-USD"}')).toBe(
      'e8b23a0b9ea8101a4a0173a94062d4c5a197bc08b706e069c58eafccc47444b7',
    )
    const h = vectors.hashes.request_hash
    expect(requestHash(h.service_id, h.method, h.target, h.body)).toBe(h.value)
  })

  it('upper-cases the method, keeps the query, hashes an empty body as sha256("")', () => {
    const sid = id('02')
    expect(requestHash(sid, 'get', '/v1/quote?symbol=BTC')).toBe(requestHash(sid, 'GET', '/v1/quote?symbol=BTC', ''))
    expect(requestHash(sid, 'GET', '/v1/quote?symbol=BTC')).not.toBe(requestHash(sid, 'GET', '/v1/quote'))
    expect(toHex(sha256(new Uint8Array()))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    expect(requestHash(sid, 'POST', '/x', new TextEncoder().encode('{}'))).toBe(requestHash(sid, 'POST', '/x', '{}'))
  })

  it('rejects absolute-form targets and short service ids', () => {
    expect(() => requestHash(id('01'), 'GET', 'https://host/x')).toThrow()
    expect(() => requestHash('0x01', 'GET', '/x')).toThrow()
  })
})
