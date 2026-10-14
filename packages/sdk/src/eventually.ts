// Ported from Fermata `packages/sdk/src/eventually.ts` @ d7cc642 (github.com/bilgin-kocak/fermata,
// MIT), unchanged apart from this note. Stellar RPC providers are load-balanced too: a node can
// answer from a ledger or two behind a transaction another node just accepted.

/**
 * Reads until `ready` holds, retrying errors too, for up to `tries` × `delayMs`. A load-balanced RPC
 * can answer from a node a ledger or two behind the transaction a caller just submitted: its
 * result is "not found" and its state unchanged for a moment. Throws the last error, or returns the
 * last value when it never became ready.
 */
export async function eventually<T>(read: () => Promise<T>, ready: (v: T) => boolean = () => true, tries = 12, delayMs = 500): Promise<T> {
  let last: { value: T } | { error: unknown } = { error: new Error('no attempt made') }
  for (let i = 0; i < tries; i++) {
    try {
      const value = await read()
      if (ready(value)) return value
      last = { value }
    } catch (error) {
      last = { error }
    }
    if (i < tries - 1) await new Promise((r) => setTimeout(r, delayMs))
  }
  if ('error' in last) throw last.error
  return last.value
}
