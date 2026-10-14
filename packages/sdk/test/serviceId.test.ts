import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import {
  accountAddress,
  contractAddress,
  isTrustedService,
  label,
  labelText,
  ownerXdr,
  serviceId,
  toHex,
} from '../src/index.ts'

const root = new URL('../../../', import.meta.url)
const vectors = JSON.parse(readFileSync(new URL('test-vectors/verdict-v1.json', root), 'utf8'))

describe('serviceId', () => {
  it('derives the vector id from the owner and the label', () => {
    const svc = vectors.service
    expect(toHex(ownerXdr(svc.owner))).toBe(svc.owner_xdr)
    expect(toHex(label(svc.label_text))).toBe(svc.label)
    expect(serviceId(svc.owner, svc.label_text)).toBe(svc.service_id)
    expect(serviceId(svc.owner, `0x${svc.label}`)).toBe(svc.service_id)
  })

  it('uses the XDR of ScVal::Address: 44 bytes for an account, 40 for a contract', () => {
    const account = accountAddress(new Uint8Array(32).fill(0x22))
    const contract = contractAddress(new Uint8Array(32).fill(0x22))
    expect(toHex(ownerXdr(account))).toBe('00000012' + '00000000' + '00000000' + '22'.repeat(32))
    expect(toHex(ownerXdr(contract))).toBe('00000012' + '00000001' + '22'.repeat(32))
    // the same key as an account and as a contract gives two ids
    expect(serviceId(account, 'quote')).not.toBe(serviceId(contract, 'quote'))
    expect(serviceId(account, 'quote')).not.toBe(serviceId(account, 'quotes'))
  })

  it('takes labels of 1 to 12 ASCII bytes, or 0x and 24 hex characters', () => {
    expect(labelText(label('quote'))).toBe('quote')
    expect(label('twelve-bytes').length).toBe(12)
    for (const bad of ['', 'thirteen-byte', 'naïve', 'a\u0000b', '0x1234']) {
      expect(() => label(bad), bad).toThrow()
    }
    expect(labelText(new Uint8Array(12))).toBeUndefined()
  })
})

describe('isTrustedService', () => {
  it('checks the verifier key (and optionally the token)', () => {
    const fermataKey = new Uint8Array(32).fill(0x0b)
    const vendorKey = new Uint8Array(32).fill(0xbe)
    const usdc = 'CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA'
    const service = { verifier: toHex(fermataKey), token: usdc }
    expect(isTrustedService(service, { trustedVerifiers: [accountAddress(fermataKey)] })).toBe(true)
    expect(isTrustedService(service, { trustedVerifiers: [toHex(fermataKey)], expectedToken: usdc })).toBe(true)
    expect(isTrustedService(service, { trustedVerifiers: [accountAddress(vendorKey)] })).toBe(false)
    expect(
      isTrustedService(service, { trustedVerifiers: [toHex(fermataKey)], expectedToken: contractAddress(vendorKey) }),
    ).toBe(false)
  })
})
