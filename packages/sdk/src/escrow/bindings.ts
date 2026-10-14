import { Buffer } from "buffer";
import { Address } from "@stellar/stellar-sdk";
import {
  AssembledTransaction,
  Client as ContractClient,
  ClientOptions as ContractClientOptions,
  MethodOptions,
  Result,
  Spec as ContractSpec,
} from "@stellar/stellar-sdk/contract";
import type {
  u32,
  i32,
  u64,
  i64,
  u128,
  i128,
  u256,
  i256,
  Option,
  Timepoint,
  Duration,
} from "@stellar/stellar-sdk/contract";
export * from "@stellar/stellar-sdk";
export * as contract from "@stellar/stellar-sdk/contract";
export * as rpc from "@stellar/stellar-sdk/rpc";

if (typeof window !== "undefined") {
  //@ts-ignore Buffer exists
  window.Buffer = window.Buffer || Buffer;
}




/**
 * Life cycle of a call. A call id is usable once, ever: once a hold exists for it, its record is
 * never removed (an expired one is archived and restored on access, never deleted).
 */
export enum Status {
  Held = 1,
  Released = 2,
  Refunded = 3,
  TimedOut = 4,
}


/**
 * A vendor's paid endpoint. Immutable once registered: the held amount, the verifier key and the
 * pinned hashes are read from it when a hold settles.
 */
export interface Service {
  /**
 * The 12-byte label the id was derived from (on Tempo it was the id's last 12 bytes).
 */
label: Buffer;
  /**
 * Hash of the accepted notary key (checked off-chain by the verifier).
 */
notary_key_hash: Buffer;
  /**
 * Hash of the upstream origin the proof must be against (checked off-chain by the verifier).
 */
origin_hash: Buffer;
  owner: string;
  payout: string;
  /**
 * sha256 of the delivery-predicate JSON the verifier enforces.
 */
predicate_hash: Buffer;
  price_per_call: i128;
  /**
 * Seconds after `hold` during which `settle` is accepted; afterwards only `claim_timeout`.
 */
settlement_window: u32;
  token: string;
  /**
 * The Ed25519 public key whose verdicts this service accepts.
 */
verifier: Buffer;
}


/**
 * The verifier's decision about one call: the fields of Fermata's EIP-712 `Verdict`, in order.
 * `outcome` is a `u32` because Soroban has no `u8` value type.
 */
export interface Verdict {
  call_id: Buffer;
  issued_at: u64;
  outcome: u32;
  predicate_hash: Buffer;
  presentation_hash: Buffer;
  request_hash: Buffer;
  response_hash: Buffer;
  service_id: Buffer;
}


/**
 * What `get_hold` returns. As on Tempo, `amount` and `deadline` are 0 unless the call is Held.
 */
export interface HoldView {
  agent: string;
  amount: i128;
  deadline: u64;
  fee_bps: u32;
  held_at: u64;
  request_hash: Buffer;
  service_id: Buffer;
  status: Status;
}

/**
 * Contract errors. The names follow `FermataEscrow.sol`; codes are public ABI and never reused.
 * 
 * Codes start at 101 so they cannot be confused with the Stellar Asset Contract's own error codes
 * (1–15, e.g. 10 = insufficient balance), which a failed token transfer inside `hold`, `settle`
 * or `claim_timeout` propagates unchanged.
 * 
 * Not carried over, because Soroban reports them itself: `NotOwner` (a failed `require_auth` is a
 * host auth error), `InvalidSignature` and `WrongVerifier` (`ed25519_verify` traps with a host
 * crypto error), `TransferFailed` (SEP-41 transfers trap instead of returning `false`),
 * `RecipientBlocked` (a SAC transfer to a blocked recipient fails on its own), `ZeroAddress`
 * (a Stellar `Address` cannot be zero) and `ServiceIdNotOwned` (ids are derived from the
 * authenticated owner).
 */
export const Errors = {
  /**
   * A fee above `MAX_FEE_BPS`.
   */
  101: {message:"FeeTooHigh"},
  /**
   * A payout or treasury that would lock the funds (this escrow, or the service's token).
   */
  102: {message:"InvalidRecipient"},
  /**
   * A verifier key of 32 zero bytes.
   */
  103: {message:"InvalidVerifier"},
  /**
   * A price outside `1..=MAX_PRICE` or a settlement window outside `1..=MAX_WINDOW`.
   */
  104: {message:"InvalidService"},
  105: {message:"ServiceExists"},
  106: {message:"UnknownService"},
  /**
   * A zero call id or request hash.
   */
  107: {message:"InvalidCall"},
  108: {message:"CallIdUsed"},
  109: {message:"NotHeld"},
  110: {message:"WindowClosed"},
  111: {message:"WindowOpen"},
  112: {message:"CallIdMismatch"},
  113: {message:"ServiceMismatch"},
  114: {message:"RequestMismatch"},
  115: {message:"PredicateMismatch"},
  116: {message:"InvalidOutcome"},
  117: {message:"InvalidPresentation"}
}








export interface Client {
  /**
   * Construct and simulate a hold transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Holds the service's price from `agent` for one call. `agent` must authorize this call,
   * including the token transfer to the escrow, which carries the exact amount.
   * 
   * `request_hash` = sha256(service_id ‖ METHOD ‖ request-target ‖ sha256(body)), computed
   * off-chain; the verifier checks the proved request against it.
   */
  hold: ({agent, call_id, service_id, request_hash}: {agent: string, call_id: Buffer, service_id: Buffer, request_hash: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a owner transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  owner: (options?: MethodOptions) => Promise<AssembledTransaction<string>>

  /**
   * Construct and simulate a settle transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Settles a hold with the service verifier's signed verdict. DELIVERED pays the vendor
   * (price − fee) and the treasury (fee); FAILED refunds the agent in full. Only inside the
   * settlement window; afterwards the only exit is `claim_timeout`. Callable by anyone.
   * 
   * A signature that does not verify fails the call with the host's crypto error.
   */
  settle: ({call_id, verdict, signature}: {call_id: Buffer, verdict: Verdict, signature: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a fee_bps transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  fee_bps: (options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a get_hold transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * `None` for a call id that was never held.
   */
  get_hold: ({call_id}: {call_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<HoldView>>>

  /**
   * Construct and simulate a treasury transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  treasury: (options?: MethodOptions) => Promise<AssembledTransaction<string>>

  /**
   * Construct and simulate a service_id transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * The id `register_service` derives for `owner` and `label`.
   */
  service_id: ({owner, label}: {owner: string, label: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Buffer>>

  /**
   * Construct and simulate a get_service transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_service: ({service_id}: {service_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<Service>>>

  /**
   * Construct and simulate a set_fee_bps transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_fee_bps: ({fee_bps}: {fee_bps: u32}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a set_treasury transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_treasury: ({treasury}: {treasury: string}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a claim_timeout transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Refunds the agent when no verdict settled the hold inside its window. Callable by anyone;
   * the money always goes to the agent.
   */
  claim_timeout: ({call_id}: {call_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a verdict_message transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * The exact bytes the verifier signs for `verdict` on this network and this contract.
   */
  verdict_message: ({verdict}: {verdict: Verdict}, options?: MethodOptions) => Promise<AssembledTransaction<Buffer>>

  /**
   * Construct and simulate a register_service transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Registers an immutable paid service and returns its id,
   * `sha256("FERMATA_STELLAR_SERVICE_V1" ‖ XDR(owner) ‖ label)`. Needs `owner`'s authorization,
   * so nobody can register under another owner's ids.
   * 
   * - `verifier`: the Ed25519 public key whose verdicts settle this service's holds.
   * - `predicate_hash`: sha256 of the delivery-predicate JSON the verifier enforces.
   * - `origin_hash`, `notary_key_hash`: the origin and notary the proof must come from
   * (checked off-chain by the verifier).
   */
  register_service: ({owner, label, payout, token, price_per_call, settlement_window, verifier, predicate_hash, origin_hash, notary_key_hash}: {owner: string, label: Buffer, payout: string, token: string, price_per_call: i128, settlement_window: u32, verifier: Buffer, predicate_hash: Buffer, origin_hash: Buffer, notary_key_hash: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Result<Buffer>>>

  /**
   * Construct and simulate a settlement_deadline transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * The last ledger timestamp at which `settle` is accepted for a held call (0 when not held).
   */
  settlement_deadline: ({call_id}: {call_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<u64>>

}
export class Client extends ContractClient {
  static async deploy<T = Client>(
        /** Constructor/Initialization Args for the contract's `__constructor` method */
        {owner, treasury, fee_bps}: {owner: string, treasury: string, fee_bps: u32},
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options: MethodOptions &
      Omit<ContractClientOptions, "contractId"> & {
        /** The hash of the Wasm blob, which must already be installed on-chain. */
        wasmHash: Buffer | string;
        /** Salt used to generate the contract's ID. Passed through to {@link Operation.createCustomContract}. Default: random. */
        salt?: Buffer | Uint8Array;
        /** The format used to decode `wasmHash`, if it's provided as a string. */
        format?: "hex" | "base64";
      }
  ): Promise<AssembledTransaction<T>> {
    return ContractClient.deploy({owner, treasury, fee_bps}, options)
  }
  constructor(public readonly options: ContractClientOptions) {
    super(
      new ContractSpec([ "AAAAAAAAAT5Ib2xkcyB0aGUgc2VydmljZSdzIHByaWNlIGZyb20gYGFnZW50YCBmb3Igb25lIGNhbGwuIGBhZ2VudGAgbXVzdCBhdXRob3JpemUgdGhpcyBjYWxsLAppbmNsdWRpbmcgdGhlIHRva2VuIHRyYW5zZmVyIHRvIHRoZSBlc2Nyb3csIHdoaWNoIGNhcnJpZXMgdGhlIGV4YWN0IGFtb3VudC4KCmByZXF1ZXN0X2hhc2hgID0gc2hhMjU2KHNlcnZpY2VfaWQg4oCWIE1FVEhPRCDigJYgcmVxdWVzdC10YXJnZXQg4oCWIHNoYTI1Nihib2R5KSksIGNvbXB1dGVkCm9mZi1jaGFpbjsgdGhlIHZlcmlmaWVyIGNoZWNrcyB0aGUgcHJvdmVkIHJlcXVlc3QgYWdhaW5zdCBpdC4AAAAAAARob2xkAAAABAAAAAAAAAAFYWdlbnQAAAAAAAATAAAAAAAAAAdjYWxsX2lkAAAAA+4AAAAgAAAAAAAAAApzZXJ2aWNlX2lkAAAAAAPuAAAAIAAAAAAAAAAMcmVxdWVzdF9oYXNoAAAD7gAAACAAAAABAAAD6QAAAAIAAAAD",
        "AAAAAAAAAAAAAAAFb3duZXIAAAAAAAAAAAAAAQAAABM=",
        "AAAAAAAAAVFTZXR0bGVzIGEgaG9sZCB3aXRoIHRoZSBzZXJ2aWNlIHZlcmlmaWVyJ3Mgc2lnbmVkIHZlcmRpY3QuIERFTElWRVJFRCBwYXlzIHRoZSB2ZW5kb3IKKHByaWNlIOKIkiBmZWUpIGFuZCB0aGUgdHJlYXN1cnkgKGZlZSk7IEZBSUxFRCByZWZ1bmRzIHRoZSBhZ2VudCBpbiBmdWxsLiBPbmx5IGluc2lkZSB0aGUKc2V0dGxlbWVudCB3aW5kb3c7IGFmdGVyd2FyZHMgdGhlIG9ubHkgZXhpdCBpcyBgY2xhaW1fdGltZW91dGAuIENhbGxhYmxlIGJ5IGFueW9uZS4KCkEgc2lnbmF0dXJlIHRoYXQgZG9lcyBub3QgdmVyaWZ5IGZhaWxzIHRoZSBjYWxsIHdpdGggdGhlIGhvc3QncyBjcnlwdG8gZXJyb3IuAAAAAAAABnNldHRsZQAAAAAAAwAAAAAAAAAHY2FsbF9pZAAAAAPuAAAAIAAAAAAAAAAHdmVyZGljdAAAAAfQAAAAB1ZlcmRpY3QAAAAAAAAAAAlzaWduYXR1cmUAAAAAAAPuAAAAQAAAAAEAAAPpAAAAAgAAAAM=",
        "AAAAAAAAAAAAAAAHZmVlX2JwcwAAAAAAAAAAAQAAAAQ=",
        "AAAAAAAAAClgTm9uZWAgZm9yIGEgY2FsbCBpZCB0aGF0IHdhcyBuZXZlciBoZWxkLgAAAAAAAAhnZXRfaG9sZAAAAAEAAAAAAAAAB2NhbGxfaWQAAAAD7gAAACAAAAABAAAD6AAAB9AAAAAISG9sZFZpZXc=",
        "AAAAAAAAAAAAAAAIdHJlYXN1cnkAAAAAAAAAAQAAABM=",
        "AAAAAAAAADpUaGUgaWQgYHJlZ2lzdGVyX3NlcnZpY2VgIGRlcml2ZXMgZm9yIGBvd25lcmAgYW5kIGBsYWJlbGAuAAAAAAAKc2VydmljZV9pZAAAAAAAAgAAAAAAAAAFb3duZXIAAAAAAAATAAAAAAAAAAVsYWJlbAAAAAAAA+4AAAAMAAAAAQAAA+4AAAAg",
        "AAAAAAAAAAAAAAALZ2V0X3NlcnZpY2UAAAAAAQAAAAAAAAAKc2VydmljZV9pZAAAAAAD7gAAACAAAAABAAAD6AAAB9AAAAAHU2VydmljZQA=",
        "AAAAAAAAAAAAAAALc2V0X2ZlZV9icHMAAAAAAQAAAAAAAAAHZmVlX2JwcwAAAAAEAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAAAAAAAAAAAMc2V0X3RyZWFzdXJ5AAAAAQAAAAAAAAAIdHJlYXN1cnkAAAATAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAAAAAOhSdW5zIG9uY2UsIGF0b21pY2FsbHksIGF0IGRlcGxveW1lbnQuCgotIGBvd25lcmA6IG1heSBjaGFuZ2UgdGhlIGZlZSBhbmQgdGhlIHRyZWFzdXJ5LCBub3RoaW5nIGVsc2UuCi0gYHRyZWFzdXJ5YDogcmVjZWl2ZXMgdGhlIHJlbGVhc2UgZmVlLgotIGBmZWVfYnBzYDogcmVsZWFzZSBmZWUgaW4gYmFzaXMgcG9pbnRzIChhdCBtb3N0IGBNQVhfRkVFX0JQU2ApOyBuZXZlciBjaGFyZ2VkIG9uIHJlZnVuZHMuAAAADV9fY29uc3RydWN0b3IAAAAAAAADAAAAAAAAAAVvd25lcgAAAAAAABMAAAAAAAAACHRyZWFzdXJ5AAAAEwAAAAAAAAAHZmVlX2JwcwAAAAAEAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAAAAAH1SZWZ1bmRzIHRoZSBhZ2VudCB3aGVuIG5vIHZlcmRpY3Qgc2V0dGxlZCB0aGUgaG9sZCBpbnNpZGUgaXRzIHdpbmRvdy4gQ2FsbGFibGUgYnkgYW55b25lOwp0aGUgbW9uZXkgYWx3YXlzIGdvZXMgdG8gdGhlIGFnZW50LgAAAAAAAA1jbGFpbV90aW1lb3V0AAAAAAAAAQAAAAAAAAAHY2FsbF9pZAAAAAPuAAAAIAAAAAEAAAPpAAAAAgAAAAM=",
        "AAAAAAAAAFNUaGUgZXhhY3QgYnl0ZXMgdGhlIHZlcmlmaWVyIHNpZ25zIGZvciBgdmVyZGljdGAgb24gdGhpcyBuZXR3b3JrIGFuZCB0aGlzIGNvbnRyYWN0LgAAAAAPdmVyZGljdF9tZXNzYWdlAAAAAAEAAAAAAAAAB3ZlcmRpY3QAAAAH0AAAAAdWZXJkaWN0AAAAAAEAAAAO",
        "AAAAAAAAAeRSZWdpc3RlcnMgYW4gaW1tdXRhYmxlIHBhaWQgc2VydmljZSBhbmQgcmV0dXJucyBpdHMgaWQsCmBzaGEyNTYoIkZFUk1BVEFfU1RFTExBUl9TRVJWSUNFX1YxIiDigJYgWERSKG93bmVyKSDigJYgbGFiZWwpYC4gTmVlZHMgYG93bmVyYCdzIGF1dGhvcml6YXRpb24sCnNvIG5vYm9keSBjYW4gcmVnaXN0ZXIgdW5kZXIgYW5vdGhlciBvd25lcidzIGlkcy4KCi0gYHZlcmlmaWVyYDogdGhlIEVkMjU1MTkgcHVibGljIGtleSB3aG9zZSB2ZXJkaWN0cyBzZXR0bGUgdGhpcyBzZXJ2aWNlJ3MgaG9sZHMuCi0gYHByZWRpY2F0ZV9oYXNoYDogc2hhMjU2IG9mIHRoZSBkZWxpdmVyeS1wcmVkaWNhdGUgSlNPTiB0aGUgdmVyaWZpZXIgZW5mb3JjZXMuCi0gYG9yaWdpbl9oYXNoYCwgYG5vdGFyeV9rZXlfaGFzaGA6IHRoZSBvcmlnaW4gYW5kIG5vdGFyeSB0aGUgcHJvb2YgbXVzdCBjb21lIGZyb20KKGNoZWNrZWQgb2ZmLWNoYWluIGJ5IHRoZSB2ZXJpZmllcikuAAAAEHJlZ2lzdGVyX3NlcnZpY2UAAAAKAAAAAAAAAAVvd25lcgAAAAAAABMAAAAAAAAABWxhYmVsAAAAAAAD7gAAAAwAAAAAAAAABnBheW91dAAAAAAAEwAAAAAAAAAFdG9rZW4AAAAAAAATAAAAAAAAAA5wcmljZV9wZXJfY2FsbAAAAAAACwAAAAAAAAARc2V0dGxlbWVudF93aW5kb3cAAAAAAAAEAAAAAAAAAAh2ZXJpZmllcgAAA+4AAAAgAAAAAAAAAA5wcmVkaWNhdGVfaGFzaAAAAAAD7gAAACAAAAAAAAAAC29yaWdpbl9oYXNoAAAAA+4AAAAgAAAAAAAAAA9ub3Rhcnlfa2V5X2hhc2gAAAAD7gAAACAAAAABAAAD6QAAA+4AAAAgAAAAAw==",
        "AAAAAAAAAFpUaGUgbGFzdCBsZWRnZXIgdGltZXN0YW1wIGF0IHdoaWNoIGBzZXR0bGVgIGlzIGFjY2VwdGVkIGZvciBhIGhlbGQgY2FsbCAoMCB3aGVuIG5vdCBoZWxkKS4AAAAAABNzZXR0bGVtZW50X2RlYWRsaW5lAAAAAAEAAAAAAAAAB2NhbGxfaWQAAAAD7gAAACAAAAABAAAABg==",
        "AAAAAwAAALBMaWZlIGN5Y2xlIG9mIGEgY2FsbC4gQSBjYWxsIGlkIGlzIHVzYWJsZSBvbmNlLCBldmVyOiBvbmNlIGEgaG9sZCBleGlzdHMgZm9yIGl0LCBpdHMgcmVjb3JkIGlzCm5ldmVyIHJlbW92ZWQgKGFuIGV4cGlyZWQgb25lIGlzIGFyY2hpdmVkIGFuZCByZXN0b3JlZCBvbiBhY2Nlc3MsIG5ldmVyIGRlbGV0ZWQpLgAAAAAAAAAGU3RhdHVzAAAAAAAEAAAAAAAAAARIZWxkAAAAAQAAAAAAAAAIUmVsZWFzZWQAAAACAAAAAAAAAAhSZWZ1bmRlZAAAAAMAAAAAAAAACFRpbWVkT3V0AAAABA==",
        "AAAAAQAAAJJBIHZlbmRvcidzIHBhaWQgZW5kcG9pbnQuIEltbXV0YWJsZSBvbmNlIHJlZ2lzdGVyZWQ6IHRoZSBoZWxkIGFtb3VudCwgdGhlIHZlcmlmaWVyIGtleSBhbmQgdGhlCnBpbm5lZCBoYXNoZXMgYXJlIHJlYWQgZnJvbSBpdCB3aGVuIGEgaG9sZCBzZXR0bGVzLgAAAAAAAAAAAAdTZXJ2aWNlAAAAAAoAAABTVGhlIDEyLWJ5dGUgbGFiZWwgdGhlIGlkIHdhcyBkZXJpdmVkIGZyb20gKG9uIFRlbXBvIGl0IHdhcyB0aGUgaWQncyBsYXN0IDEyIGJ5dGVzKS4AAAAABWxhYmVsAAAAAAAD7gAAAAwAAABESGFzaCBvZiB0aGUgYWNjZXB0ZWQgbm90YXJ5IGtleSAoY2hlY2tlZCBvZmYtY2hhaW4gYnkgdGhlIHZlcmlmaWVyKS4AAAAPbm90YXJ5X2tleV9oYXNoAAAAA+4AAAAgAAAAWkhhc2ggb2YgdGhlIHVwc3RyZWFtIG9yaWdpbiB0aGUgcHJvb2YgbXVzdCBiZSBhZ2FpbnN0IChjaGVja2VkIG9mZi1jaGFpbiBieSB0aGUgdmVyaWZpZXIpLgAAAAAAC29yaWdpbl9oYXNoAAAAA+4AAAAgAAAAAAAAAAVvd25lcgAAAAAAABMAAAAAAAAABnBheW91dAAAAAAAEwAAADxzaGEyNTYgb2YgdGhlIGRlbGl2ZXJ5LXByZWRpY2F0ZSBKU09OIHRoZSB2ZXJpZmllciBlbmZvcmNlcy4AAAAOcHJlZGljYXRlX2hhc2gAAAAAA+4AAAAgAAAAAAAAAA5wcmljZV9wZXJfY2FsbAAAAAAACwAAAFhTZWNvbmRzIGFmdGVyIGBob2xkYCBkdXJpbmcgd2hpY2ggYHNldHRsZWAgaXMgYWNjZXB0ZWQ7IGFmdGVyd2FyZHMgb25seSBgY2xhaW1fdGltZW91dGAuAAAAEXNldHRsZW1lbnRfd2luZG93AAAAAAAABAAAAAAAAAAFdG9rZW4AAAAAAAATAAAAO1RoZSBFZDI1NTE5IHB1YmxpYyBrZXkgd2hvc2UgdmVyZGljdHMgdGhpcyBzZXJ2aWNlIGFjY2VwdHMuAAAAAAh2ZXJpZmllcgAAA+4AAAAg",
        "AAAAAQAAAJlUaGUgdmVyaWZpZXIncyBkZWNpc2lvbiBhYm91dCBvbmUgY2FsbDogdGhlIGZpZWxkcyBvZiBGZXJtYXRhJ3MgRUlQLTcxMiBgVmVyZGljdGAsIGluIG9yZGVyLgpgb3V0Y29tZWAgaXMgYSBgdTMyYCBiZWNhdXNlIFNvcm9iYW4gaGFzIG5vIGB1OGAgdmFsdWUgdHlwZS4AAAAAAAAAAAAAB1ZlcmRpY3QAAAAACAAAAAAAAAAHY2FsbF9pZAAAAAPuAAAAIAAAAAAAAAAJaXNzdWVkX2F0AAAAAAAABgAAAAAAAAAHb3V0Y29tZQAAAAAEAAAAAAAAAA5wcmVkaWNhdGVfaGFzaAAAAAAD7gAAACAAAAAAAAAAEXByZXNlbnRhdGlvbl9oYXNoAAAAAAAD7gAAACAAAAAAAAAADHJlcXVlc3RfaGFzaAAAA+4AAAAgAAAAAAAAAA1yZXNwb25zZV9oYXNoAAAAAAAD7gAAACAAAAAAAAAACnNlcnZpY2VfaWQAAAAAA+4AAAAg",
        "AAAAAQAAAFxXaGF0IGBnZXRfaG9sZGAgcmV0dXJucy4gQXMgb24gVGVtcG8sIGBhbW91bnRgIGFuZCBgZGVhZGxpbmVgIGFyZSAwIHVubGVzcyB0aGUgY2FsbCBpcyBIZWxkLgAAAAAAAAAISG9sZFZpZXcAAAAIAAAAAAAAAAVhZ2VudAAAAAAAABMAAAAAAAAABmFtb3VudAAAAAAACwAAAAAAAAAIZGVhZGxpbmUAAAAGAAAAAAAAAAdmZWVfYnBzAAAAAAQAAAAAAAAAB2hlbGRfYXQAAAAABgAAAAAAAAAMcmVxdWVzdF9oYXNoAAAD7gAAACAAAAAAAAAACnNlcnZpY2VfaWQAAAAAA+4AAAAgAAAAAAAAAAZzdGF0dXMAAAAAB9AAAAAGU3RhdHVzAAA=",
        "AAAABAAAAyNDb250cmFjdCBlcnJvcnMuIFRoZSBuYW1lcyBmb2xsb3cgYEZlcm1hdGFFc2Nyb3cuc29sYDsgY29kZXMgYXJlIHB1YmxpYyBBQkkgYW5kIG5ldmVyIHJldXNlZC4KCkNvZGVzIHN0YXJ0IGF0IDEwMSBzbyB0aGV5IGNhbm5vdCBiZSBjb25mdXNlZCB3aXRoIHRoZSBTdGVsbGFyIEFzc2V0IENvbnRyYWN0J3Mgb3duIGVycm9yIGNvZGVzCigx4oCTMTUsIGUuZy4gMTAgPSBpbnN1ZmZpY2llbnQgYmFsYW5jZSksIHdoaWNoIGEgZmFpbGVkIHRva2VuIHRyYW5zZmVyIGluc2lkZSBgaG9sZGAsIGBzZXR0bGVgCm9yIGBjbGFpbV90aW1lb3V0YCBwcm9wYWdhdGVzIHVuY2hhbmdlZC4KCk5vdCBjYXJyaWVkIG92ZXIsIGJlY2F1c2UgU29yb2JhbiByZXBvcnRzIHRoZW0gaXRzZWxmOiBgTm90T3duZXJgIChhIGZhaWxlZCBgcmVxdWlyZV9hdXRoYCBpcyBhCmhvc3QgYXV0aCBlcnJvciksIGBJbnZhbGlkU2lnbmF0dXJlYCBhbmQgYFdyb25nVmVyaWZpZXJgIChgZWQyNTUxOV92ZXJpZnlgIHRyYXBzIHdpdGggYSBob3N0CmNyeXB0byBlcnJvciksIGBUcmFuc2ZlckZhaWxlZGAgKFNFUC00MSB0cmFuc2ZlcnMgdHJhcCBpbnN0ZWFkIG9mIHJldHVybmluZyBgZmFsc2VgKSwKYFJlY2lwaWVudEJsb2NrZWRgIChhIFNBQyB0cmFuc2ZlciB0byBhIGJsb2NrZWQgcmVjaXBpZW50IGZhaWxzIG9uIGl0cyBvd24pLCBgWmVyb0FkZHJlc3NgCihhIFN0ZWxsYXIgYEFkZHJlc3NgIGNhbm5vdCBiZSB6ZXJvKSBhbmQgYFNlcnZpY2VJZE5vdE93bmVkYCAoaWRzIGFyZSBkZXJpdmVkIGZyb20gdGhlCmF1dGhlbnRpY2F0ZWQgb3duZXIpLgAAAAAAAAAABUVycm9yAAAAAAAAEQAAABpBIGZlZSBhYm92ZSBgTUFYX0ZFRV9CUFNgLgAAAAAACkZlZVRvb0hpZ2gAAAAAAGUAAABVQSBwYXlvdXQgb3IgdHJlYXN1cnkgdGhhdCB3b3VsZCBsb2NrIHRoZSBmdW5kcyAodGhpcyBlc2Nyb3csIG9yIHRoZSBzZXJ2aWNlJ3MgdG9rZW4pLgAAAAAAABBJbnZhbGlkUmVjaXBpZW50AAAAZgAAACBBIHZlcmlmaWVyIGtleSBvZiAzMiB6ZXJvIGJ5dGVzLgAAAA9JbnZhbGlkVmVyaWZpZXIAAAAAZwAAAFBBIHByaWNlIG91dHNpZGUgYDEuLj1NQVhfUFJJQ0VgIG9yIGEgc2V0dGxlbWVudCB3aW5kb3cgb3V0c2lkZSBgMS4uPU1BWF9XSU5ET1dgLgAAAA5JbnZhbGlkU2VydmljZQAAAAAAaAAAAAAAAAANU2VydmljZUV4aXN0cwAAAAAAAGkAAAAAAAAADlVua25vd25TZXJ2aWNlAAAAAABqAAAAH0EgemVybyBjYWxsIGlkIG9yIHJlcXVlc3QgaGFzaC4AAAAAC0ludmFsaWRDYWxsAAAAAGsAAAAAAAAACkNhbGxJZFVzZWQAAAAAAGwAAAAAAAAAB05vdEhlbGQAAAAAbQAAAAAAAAAMV2luZG93Q2xvc2VkAAAAbgAAAAAAAAAKV2luZG93T3BlbgAAAAAAbwAAAAAAAAAOQ2FsbElkTWlzbWF0Y2gAAAAAAHAAAAAAAAAAD1NlcnZpY2VNaXNtYXRjaAAAAABxAAAAAAAAAA9SZXF1ZXN0TWlzbWF0Y2gAAAAAcgAAAAAAAAARUHJlZGljYXRlTWlzbWF0Y2gAAAAAAABzAAAAAAAAAA5JbnZhbGlkT3V0Y29tZQAAAAAAdAAAAAAAAAATSW52YWxpZFByZXNlbnRhdGlvbgAAAAB1",
        "AAAABQAAAAAAAAAAAAAABEhlbGQAAAABAAAABGhlbGQAAAAFAAAAAAAAAAdjYWxsX2lkAAAAA+4AAAAgAAAAAQAAAAAAAAAKc2VydmljZV9pZAAAAAAD7gAAACAAAAABAAAAAAAAAAVhZ2VudAAAAAAAABMAAAABAAAAAAAAAAZhbW91bnQAAAAAAAsAAAAAAAAAAAAAAAxyZXF1ZXN0X2hhc2gAAAPuAAAAIAAAAAAAAAAC",
        "AAAABQAAACxBIEZBSUxFRCB2ZXJkaWN0IHJlZnVuZGVkIHRoZSBhZ2VudCBpbiBmdWxsLgAAAAAAAAAIUmVmdW5kZWQAAAABAAAACHJlZnVuZGVkAAAABQAAAAAAAAAHY2FsbF9pZAAAAAPuAAAAIAAAAAEAAAAAAAAACnNlcnZpY2VfaWQAAAAAA+4AAAAgAAAAAQAAAAAAAAAFYWdlbnQAAAAAAAATAAAAAQAAAAAAAAAGYW1vdW50AAAAAAALAAAAAAAAAAAAAAARcHJlc2VudGF0aW9uX2hhc2gAAAAAAAPuAAAAIAAAAAAAAAAC",
        "AAAABQAAAEpBIERFTElWRVJFRCB2ZXJkaWN0IHBhaWQgdGhlIHZlbmRvciBgYW1vdW50IC0gZmVlYCBhbmQgdGhlIHRyZWFzdXJ5IGBmZWVgLgAAAAAAAAAAAAhSZWxlYXNlZAAAAAEAAAAIcmVsZWFzZWQAAAAGAAAAAAAAAAdjYWxsX2lkAAAAA+4AAAAgAAAAAQAAAAAAAAAKc2VydmljZV9pZAAAAAAD7gAAACAAAAABAAAAAAAAAAZwYXlvdXQAAAAAABMAAAABAAAAAAAAAAZhbW91bnQAAAAAAAsAAAAAAAAAAAAAAANmZWUAAAAACwAAAAAAAAAAAAAAEXByZXNlbnRhdGlvbl9oYXNoAAAAAAAD7gAAACAAAAAAAAAAAg==",
        "AAAABQAAAIxObyB2ZXJkaWN0IHNldHRsZWQgdGhlIGhvbGQgaW5zaWRlIGl0cyB3aW5kb3c7IHRoZSBhZ2VudCB3YXMgcmVmdW5kZWQgaW4gZnVsbC4KKE9uIFRlbXBvIHRoaXMgd2FzIGBSZWZ1bmRlZGAgd2l0aCBhIHplcm8gcHJlc2VudGF0aW9uIGhhc2guKQAAAAAAAAAIVGltZWRPdXQAAAABAAAACXRpbWVkX291dAAAAAAAAAQAAAAAAAAAB2NhbGxfaWQAAAAD7gAAACAAAAABAAAAAAAAAApzZXJ2aWNlX2lkAAAAAAPuAAAAIAAAAAEAAAAAAAAABWFnZW50AAAAAAAAEwAAAAEAAAAAAAAABmFtb3VudAAAAAAACwAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAADUZlZUJwc1VwZGF0ZWQAAAAAAAABAAAAD2ZlZV9icHNfdXBkYXRlZAAAAAABAAAAAAAAAAdmZWVfYnBzAAAAAAQAAAAAAAAAAg==",
        "AAAABQAAAAAAAAAAAAAAD1RyZWFzdXJ5VXBkYXRlZAAAAAABAAAAEHRyZWFzdXJ5X3VwZGF0ZWQAAAABAAAAAAAAAAh0cmVhc3VyeQAAABMAAAABAAAAAg==",
        "AAAABQAAAAAAAAAAAAAAEVNlcnZpY2VSZWdpc3RlcmVkAAAAAAAAAQAAABJzZXJ2aWNlX3JlZ2lzdGVyZWQAAAAAAAgAAAAAAAAACnNlcnZpY2VfaWQAAAAAA+4AAAAgAAAAAQAAAAAAAAAFb3duZXIAAAAAAAATAAAAAQAAAAAAAAAFdG9rZW4AAAAAAAATAAAAAQAAAAAAAAAFbGFiZWwAAAAAAAPuAAAADAAAAAAAAAAAAAAABnBheW91dAAAAAAAEwAAAAAAAAAAAAAACHZlcmlmaWVyAAAD7gAAACAAAAAAAAAAAAAAAA5wcmljZV9wZXJfY2FsbAAAAAAACwAAAAAAAAAAAAAAEXNldHRsZW1lbnRfd2luZG93AAAAAAAABAAAAAAAAAAC" ]),
      options
    )
  }
  public readonly fromJSON = {
    hold: this.txFromJSON<Result<void>>,
        owner: this.txFromJSON<string>,
        settle: this.txFromJSON<Result<void>>,
        fee_bps: this.txFromJSON<u32>,
        get_hold: this.txFromJSON<Option<HoldView>>,
        treasury: this.txFromJSON<string>,
        service_id: this.txFromJSON<Buffer>,
        get_service: this.txFromJSON<Option<Service>>,
        set_fee_bps: this.txFromJSON<Result<void>>,
        set_treasury: this.txFromJSON<Result<void>>,
        claim_timeout: this.txFromJSON<Result<void>>,
        verdict_message: this.txFromJSON<Buffer>,
        register_service: this.txFromJSON<Result<Buffer>>,
        settlement_deadline: this.txFromJSON<u64>
  }
}