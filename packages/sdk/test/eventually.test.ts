// Ported from Fermata `packages/sdk/test/eventually.test.ts` @ d7cc642 (MIT), unchanged.
import { describe, expect, it } from 'vitest'
import { eventually } from '../src/eventually.ts'

describe('eventually', () => {
  it('retries errors and not-ready values, then returns the first ready one', async () => {
    let n = 0
    const v = await eventually(
      async () => {
        n++
        if (n === 1) throw new Error('not found')
        return n
      },
      (x) => x >= 3,
      5,
      1,
    )
    expect([v, n]).toEqual([3, 3])
  })
  it('gives up after `tries`: the last error is thrown, or the last value returned', async () => {
    await expect(
      eventually(
        async () => {
          throw new Error('still not found')
        },
        undefined,
        3,
        1,
      ),
    ).rejects.toThrow('still not found')
    expect(await eventually(async () => 1, (x) => x > 1, 3, 1)).toBe(1)
  })
})
