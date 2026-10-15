// Who gets what when money leaves the escrow or a session, computed as the contracts compute it, so
// an agent or a vendor can show the split before settling and a test can expect it exactly.
//
// The escrow's `release` (contracts/escrow/src/lib.rs): fee = amount × fee_bps / 10 000, rounded
// down; the payout gets the rest. Refunds never pay a fee.
//
// The session's `settle_batch` (contracts/session/src/lib.rs) rounds the fee once per call, not on
// the batch total: fee_unit = price × fee_bps / 10 000, then paid × fee_unit to the treasury,
// paid × (price − fee_unit) to the payout and (count − paid) × price back to the agent.

export const BPS = 10_000n
/** The largest fee the escrow accepts: 5 %. */
export const MAX_FEE_BPS = 500
/** The largest price the escrow accepts, so that price × fee_bps fits an i128. */
export const MAX_PRICE = (2n ** 127n - 1n) / BPS

/** A released hold: `payout` to the service's payout address, `fee` to the treasury. */
export type ReleaseSplit = { payout: bigint; fee: bigint }

/** A settled batch, with the field names of the `batch_settled` event. */
export type BatchSplit = { payoutAmount: bigint; fee: bigint; refund: bigint }

/** What `release` pays for a hold of `amount` at `feeBps` (the hold's `feeBps`, fixed when it was made). */
export function releaseSplit(amount: bigint, feeBps: number): ReleaseSplit {
  if (amount <= 0n || amount > MAX_PRICE) throw new Error(`amount out of range: ${amount}`)
  if (!Number.isInteger(feeBps) || feeBps < 0 || feeBps > MAX_FEE_BPS) {
    throw new Error(`fee_bps out of range: ${feeBps}`)
  }
  const fee = (amount * BigInt(feeBps)) / BPS
  return { payout: amount - fee, fee }
}

/** What `settle_batch` pays when `paid` of the batch's `count` calls are paid, at the session's price and fee. */
export function batchSplit(price: bigint, feeBps: number, paid: number, count: number): BatchSplit {
  if (!Number.isInteger(count) || count < 1) throw new Error(`count out of range: ${count}`)
  if (!Number.isInteger(paid) || paid < 0 || paid > count) throw new Error(`paid out of range: ${paid} of ${count}`)
  const feeUnit = releaseSplit(price, feeBps).fee
  return {
    payoutAmount: BigInt(paid) * (price - feeUnit),
    fee: BigInt(paid) * feeUnit,
    refund: BigInt(count - paid) * price,
  }
}
