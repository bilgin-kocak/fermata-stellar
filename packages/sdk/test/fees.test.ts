import { describe, expect, it } from 'vitest'
import { batchSplit, MAX_FEE_BPS, MAX_PRICE, releaseSplit } from '../src/index.ts'

// USDC has 7 decimals on Stellar: 1 USDC is 10 000 000 units.
const USDC = 10_000_000n

describe('releaseSplit', () => {
  it('takes 0.5 % of a 1 USDC call for the treasury and pays the rest to the vendor', () => {
    expect(releaseSplit(USDC, 50)).toEqual({ payout: 9_950_000n, fee: 50_000n })
  })

  it('rounds the fee down, as the escrow does', () => {
    expect(releaseSplit(199n, 50)).toEqual({ payout: 199n, fee: 0n })
    expect(releaseSplit(200n, 50)).toEqual({ payout: 199n, fee: 1n })
    expect(releaseSplit(1n, MAX_FEE_BPS)).toEqual({ payout: 1n, fee: 0n })
  })

  it('pays everything to the vendor with no fee, and 95 % at the largest fee', () => {
    expect(releaseSplit(USDC, 0)).toEqual({ payout: USDC, fee: 0n })
    expect(releaseSplit(USDC, MAX_FEE_BPS)).toEqual({ payout: 9_500_000n, fee: 500_000n })
  })

  it('takes the largest price the escrow accepts', () => {
    const { payout, fee } = releaseSplit(MAX_PRICE, MAX_FEE_BPS)
    expect(payout + fee).toBe(MAX_PRICE)
    expect(fee).toBe((MAX_PRICE * 500n) / 10_000n)
  })

  it('rejects what the escrow would never hold', () => {
    for (const bps of [-1, MAX_FEE_BPS + 1, 1.5, Number.NaN]) {
      expect(() => releaseSplit(USDC, bps), `fee ${bps}`).toThrow(/fee_bps/)
    }
    for (const amount of [0n, -1n, MAX_PRICE + 1n]) {
      expect(() => releaseSplit(amount, 50), `amount ${amount}`).toThrow(/amount/)
    }
  })
})

describe('batchSplit', () => {
  it('pays the delivered calls and refunds the rest of the batch', () => {
    expect(batchSplit(USDC, 50, 3, 4)).toEqual({ payoutAmount: 3n * 9_950_000n, fee: 3n * 50_000n, refund: USDC })
  })

  it('rounds the fee per call, not on the batch total, as settle_batch does', () => {
    // 1.5 units of fee per call round down to 1, so 10 calls pay 10, where 0.5 % of 3 000 would be 15.
    expect(batchSplit(300n, 50, 10, 10)).toEqual({ payoutAmount: 2_990n, fee: 10n, refund: 0n })
  })

  it('refunds the whole batch when nothing is paid', () => {
    expect(batchSplit(USDC, 50, 0, 5)).toEqual({ payoutAmount: 0n, fee: 0n, refund: 5n * USDC })
  })

  it('always moves exactly count × price', () => {
    for (const [price, bps, paid, count] of [
      [1n, 0, 1, 1],
      [7n, 499, 2, 9],
      [123_457n, 37, 40, 50],
      [USDC, MAX_FEE_BPS, 1000, 1000],
    ] as const) {
      const { payoutAmount, fee, refund } = batchSplit(price, bps, paid, count)
      expect(payoutAmount + fee + refund).toBe(BigInt(count) * price)
    }
  })

  it('rejects a paid count outside the batch', () => {
    for (const [paid, count] of [
      [3, 2],
      [-1, 2],
      [1.5, 2],
      [0, 0],
    ]) {
      expect(() => batchSplit(USDC, 50, paid!, count!), `${paid} of ${count}`).toThrow(/paid|count/)
    }
  })
})
