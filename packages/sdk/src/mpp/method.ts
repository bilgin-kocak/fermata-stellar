// The `fermata` MPP payment method on Stellar.
//
// Ported from Fermata `packages/sdk/src/method.ts` @ d7cc642 (github.com/bilgin-kocak/fermata, MIT).
// Kept: the method name and intent, the server-minted call id, and the credential that names the
// call. Changed for Stellar: the network is a CAIP-2 id instead of an EVM chain id; addresses are
// `G…`/`C…` and hashes are hex without `0x`; and, as in Stellar's MPP Charge, there are two
// credentials: `transaction` (the agent signs only the authorization of `hold`, and the server
// submits it and pays the fee) and `hold` (the agent submitted the hold and sends its hash).
import { Method, z, type Receipt } from 'mppx'

/**
 * Instead of paying the vendor, the agent holds the price in the escrow; the gateway proves the
 * vendor's response with TLSNotary and settles on a signed verdict (release to the vendor, or
 * refund). The challenge names the escrow and network, the service, the request hash of this exact
 * HTTP request, a server-minted call id, the amount (base units) and the currency (the service's
 * token contract).
 */
export const fermataMethod = Method.from({
  name: 'fermata',
  intent: 'charge',
  schema: {
    request: z.object({
      /** Price in token base units (a string of digits), equal to the service's price per call. */
      amount: z.string(),
      /** The token contract (`C…`). */
      currency: z.string(),
      /** The escrow contract (`C…`). */
      escrow: z.string(),
      /** CAIP-2 network id, `stellar:testnet` or `stellar:pubnet`. */
      network: z.string(),
      serviceId: z.string(),
      requestHash: z.string(),
      /** Minted by the server's `request` hook (the schema is parsed before the hook runs). */
      callId: z.optional(z.string()),
      /** The server accepts a `transaction` credential: it submits the hold and pays the fee. */
      sponsored: z.optional(z.boolean()),
    }),
    credential: {
      payload: z.discriminatedUnion('type', [
        /** The hold with the agent's signed authorization, the all-zero account as source. */
        z.object({ type: z.literal('transaction'), transaction: z.string().check(z.maxLength(16_384)), callId: z.string() }),
        /** The hash of a hold the agent submitted. */
        z.object({ type: z.literal('hold'), txHash: z.string(), callId: z.string() }),
      ]),
    },
  },
})

export type FermataRequest = z.output<(typeof fermataMethod)['schema']['request']>

/**
 * The Payment-Receipt of a call paid with `fermata` through a Fermata gateway: mppx's receipt plus
 * the call fields the gateway adds. Read it with `Receipt.fromResponse(res) as FermataReceipt`.
 */
export type FermataReceipt = Receipt.Receipt & {
  callId?: string
  holdTx?: string
  /** The release or refund transaction, once the call is settled. */
  txHash?: string | null
  presentationHash?: string | null
  /** `AWAITING_TIMEOUT`: no proof, so the escrow refunds the agent once the settlement window closes. */
  outcome?: 'DELIVERED' | 'FAILED' | 'AWAITING_TIMEOUT' | null
}
