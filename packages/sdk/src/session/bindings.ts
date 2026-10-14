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
 * One deposit for up to `max_calls` calls of one service, settled in batches. The service's
 * terms are copied from the escrow's registry at opening (services are immutable there).
 */
export interface Session {
  agent: string;
  /**
 * The batch size B: at most B calls per batch, exactly B for sampled sessions except the last.
 */
batch_size: u32;
  /**
 * `chain(settled)`; `session_id` before the first batch.
 */
chain: Buffer;
  /**
 * The last ledger timestamp at which a batch is accepted: `expires_at + settlement_window`.
 */
deadline: u64;
  /**
 * The escrow's fee at opening; later fee changes do not apply to this session.
 */
fee_bps: u32;
  max_calls: u32;
  opened_at: u64;
  payout: string;
  predicate_hash: Buffer;
  /**
 * The service's price per call; the deposit is `max_calls × price`.
 */
price: i128;
  /**
 * One call in `sample_k` is proved; 1 proves every call.
 */
sample_k: u32;
  /**
 * The last revealed seed (the commitment before the first batch); zero when `sample_k` is 1.
 */
seed: Buffer;
  service_id: Buffer;
  /**
 * Calls settled so far; the next batch starts at call `settled + 1`.
 */
settled: u32;
  status: SessionStatus;
  /**
 * The agent's Ed25519 key for tickets (not its account key).
 */
ticket_key: Buffer;
  token: string;
  /**
 * The Ed25519 key whose batch statements settle this session (the service's verifier).
 */
verifier: Buffer;
}

/**
 * Life cycle of a session. A session id is usable once, ever.
 */
export enum SessionStatus {
  Open = 1,
  Closed = 2,
}

/**
 * Contract errors. Codes are public ABI and never reused. They start at 201, apart from the
 * escrow's (101–117) and the Stellar Asset Contract's own codes (1–15, e.g. 10 = insufficient
 * balance), which a failed token transfer propagates unchanged.
 * 
 * A ticket or statement signature that does not verify is not a contract error: the host's
 * `ed25519_verify` traps with a crypto error, as in the escrow.
 */
export const Errors = {
  /**
   * Opening terms outside the limits (calls, k, batch size, expiry, deposit), a zero session
   * id or ticket key, a seed that does not match k, or a service whose payout is this contract.
   */
  201: {message:"InvalidSession"},
  202: {message:"SessionExists"},
  /**
   * The escrow has no service with this id.
   */
  203: {message:"UnknownService"},
  /**
   * No open session with this id.
   */
  204: {message:"NotOpen"},
  /**
   * The session's deadline has passed; only `close_session` remains.
   */
  205: {message:"WindowClosed"},
  /**
   * The session's deadline has not passed yet.
   */
  206: {message:"WindowOpen"},
  /**
   * A batch that settles no call, goes past `max_calls`, is longer than B, or (sampled) is not
   * the next B calls.
   */
  207: {message:"InvalidBatch"},
  /**
   * Request hashes or entries whose length is not the batch's number of calls.
   */
  208: {message:"LengthMismatch"},
  /**
   * A seed that is not the next one in the verifier's chain, or a non-zero seed when k = 1.
   */
  209: {message:"InvalidSeed"},
  /**
   * A result that the sample or the hashes do not allow.
   */
  210: {message:"InvalidEntry"},
  /**
   * The escrow's treasury is this contract: fees sent there could never leave.
   */
  211: {message:"InvalidRecipient"}
}




export interface Client {
  /**
   * Construct and simulate a escrow transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  escrow: (options?: MethodOptions) => Promise<AssembledTransaction<string>>

  /**
   * Construct and simulate a call_id transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * The id call `n` of a session is proved against (its `X-Fermata-Call` header).
   */
  call_id: ({session_id, n}: {session_id: Buffer, n: u32}, options?: MethodOptions) => Promise<AssembledTransaction<Buffer>>

  /**
   * Construct and simulate a sampled transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Whether call `n` is proved in a batch with this seed, sampling one call in `k`.
   */
  sampled: ({seed, n, k}: {seed: Buffer, n: u32, k: u32}, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a get_session transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * `None` for a session id that was never opened.
   */
  get_session: ({session_id}: {session_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<Session>>>

  /**
   * Construct and simulate a open_session transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Opens a session: the agent deposits `max_calls × price` for the service. `agent` must
   * authorize this call, including the token transfer, which carries the exact deposit.
   * 
   * - `ticket_key`: the Ed25519 key the agent signs its tickets with (not its account key).
   * - `sample_k`: one call in k is proved; 1 proves every call.
   * - `batch_size`: at most this many calls per batch (exactly this many when k > 1, except
   * the last batch).
   * - `seed`: the verifier's seed-chain commitment when k > 1; 32 zero bytes when k = 1.
   * - `expires_at`: when calls stop; batches are accepted until `expires_at` plus the
   * service's settlement window.
   */
  open_session: ({agent, session_id, service_id, max_calls, ticket_key, sample_k, batch_size, seed, expires_at}: {agent: string, session_id: Buffer, service_id: Buffer, max_calls: u32, ticket_key: Buffer, sample_k: u32, batch_size: u32, seed: Buffer, expires_at: u64}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a settle_batch transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Settles calls `settled + 1` through `to` with the agent's ticket for call `to` and the
   * verifier's statement. Callable by anyone, until the session's deadline.
   * 
   * - `request_hashes`: the calls' request hashes, 32 bytes each, concatenated in call order.
   * - `ticket`: the agent's signature over `ticket(to)`, which commits it to all those requests.
   * - `seed`: the batch's revealed seed when k > 1; 32 zero bytes when k = 1.
   * - `entries`: one 68-byte entry per call, concatenated in call order.
   * - `statement`: the verifier's signature over the batch statement.
   * 
   * Proved DELIVERED calls and unproved answered calls are paid, minus `k − 1` calls for each
   * proved failure (never below zero); the rest of the batch is refunded to the agent. A
   * signature that does not verify fails the call with the host's crypto error.
   */
  settle_batch: ({session_id, to, request_hashes, ticket, seed, entries, statement}: {session_id: Buffer, to: u32, request_hashes: Buffer, ticket: Buffer, seed: Buffer, entries: Buffer, statement: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a close_session transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * After the session's deadline, returns what is left of the deposit to the agent. Callable by
   * anyone; the money always goes to the agent.
   */
  close_session: ({session_id}: {session_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a ticket_message transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * The exact bytes the agent's ticket key signs for call `n` of a session, on this network and
   * this contract.
   */
  ticket_message: ({session_id, n, chain}: {session_id: Buffer, n: u32, chain: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Buffer>>

  /**
   * Construct and simulate a statement_message transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * The exact bytes the verifier signs for a batch statement, on this network and this contract.
   */
  statement_message: ({session_id, service_id, predicate_hash, from, to, chain, seed, entries}: {session_id: Buffer, service_id: Buffer, predicate_hash: Buffer, from: u32, to: u32, chain: Buffer, seed: Buffer, entries: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Buffer>>

}
export class Client extends ContractClient {
  static async deploy<T = Client>(
        /** Constructor/Initialization Args for the contract's `__constructor` method */
        {escrow}: {escrow: string},
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
    return ContractClient.deploy({escrow}, options)
  }
  constructor(public readonly options: ContractClientOptions) {
    super(
      new ContractSpec([ "AAAAAAAAAAAAAAAGZXNjcm93AAAAAAAAAAAAAQAAABM=",
        "AAAAAAAAAE1UaGUgaWQgY2FsbCBgbmAgb2YgYSBzZXNzaW9uIGlzIHByb3ZlZCBhZ2FpbnN0IChpdHMgYFgtRmVybWF0YS1DYWxsYCBoZWFkZXIpLgAAAAAAAAdjYWxsX2lkAAAAAAIAAAAAAAAACnNlc3Npb25faWQAAAAAA+4AAAAgAAAAAAAAAAFuAAAAAAAABAAAAAEAAAPuAAAAIA==",
        "AAAAAAAAAE9XaGV0aGVyIGNhbGwgYG5gIGlzIHByb3ZlZCBpbiBhIGJhdGNoIHdpdGggdGhpcyBzZWVkLCBzYW1wbGluZyBvbmUgY2FsbCBpbiBga2AuAAAAAAdzYW1wbGVkAAAAAAMAAAAAAAAABHNlZWQAAAPuAAAAIAAAAAAAAAABbgAAAAAAAAQAAAAAAAAAAWsAAAAAAAAEAAAAAQAAAAE=",
        "AAAAAAAAAC5gTm9uZWAgZm9yIGEgc2Vzc2lvbiBpZCB0aGF0IHdhcyBuZXZlciBvcGVuZWQuAAAAAAALZ2V0X3Nlc3Npb24AAAAAAQAAAAAAAAAKc2Vzc2lvbl9pZAAAAAAD7gAAACAAAAABAAAD6AAAB9AAAAAHU2Vzc2lvbgA=",
        "AAAAAAAAAmxPcGVucyBhIHNlc3Npb246IHRoZSBhZ2VudCBkZXBvc2l0cyBgbWF4X2NhbGxzIMOXIHByaWNlYCBmb3IgdGhlIHNlcnZpY2UuIGBhZ2VudGAgbXVzdAphdXRob3JpemUgdGhpcyBjYWxsLCBpbmNsdWRpbmcgdGhlIHRva2VuIHRyYW5zZmVyLCB3aGljaCBjYXJyaWVzIHRoZSBleGFjdCBkZXBvc2l0LgoKLSBgdGlja2V0X2tleWA6IHRoZSBFZDI1NTE5IGtleSB0aGUgYWdlbnQgc2lnbnMgaXRzIHRpY2tldHMgd2l0aCAobm90IGl0cyBhY2NvdW50IGtleSkuCi0gYHNhbXBsZV9rYDogb25lIGNhbGwgaW4gayBpcyBwcm92ZWQ7IDEgcHJvdmVzIGV2ZXJ5IGNhbGwuCi0gYGJhdGNoX3NpemVgOiBhdCBtb3N0IHRoaXMgbWFueSBjYWxscyBwZXIgYmF0Y2ggKGV4YWN0bHkgdGhpcyBtYW55IHdoZW4gayA+IDEsIGV4Y2VwdAp0aGUgbGFzdCBiYXRjaCkuCi0gYHNlZWRgOiB0aGUgdmVyaWZpZXIncyBzZWVkLWNoYWluIGNvbW1pdG1lbnQgd2hlbiBrID4gMTsgMzIgemVybyBieXRlcyB3aGVuIGsgPSAxLgotIGBleHBpcmVzX2F0YDogd2hlbiBjYWxscyBzdG9wOyBiYXRjaGVzIGFyZSBhY2NlcHRlZCB1bnRpbCBgZXhwaXJlc19hdGAgcGx1cyB0aGUKc2VydmljZSdzIHNldHRsZW1lbnQgd2luZG93LgAAAAxvcGVuX3Nlc3Npb24AAAAJAAAAAAAAAAVhZ2VudAAAAAAAABMAAAAAAAAACnNlc3Npb25faWQAAAAAA+4AAAAgAAAAAAAAAApzZXJ2aWNlX2lkAAAAAAPuAAAAIAAAAAAAAAAJbWF4X2NhbGxzAAAAAAAABAAAAAAAAAAKdGlja2V0X2tleQAAAAAD7gAAACAAAAAAAAAACHNhbXBsZV9rAAAABAAAAAAAAAAKYmF0Y2hfc2l6ZQAAAAAABAAAAAAAAAAEc2VlZAAAA+4AAAAgAAAAAAAAAApleHBpcmVzX2F0AAAAAAAGAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAAAAAyVTZXR0bGVzIGNhbGxzIGBzZXR0bGVkICsgMWAgdGhyb3VnaCBgdG9gIHdpdGggdGhlIGFnZW50J3MgdGlja2V0IGZvciBjYWxsIGB0b2AgYW5kIHRoZQp2ZXJpZmllcidzIHN0YXRlbWVudC4gQ2FsbGFibGUgYnkgYW55b25lLCB1bnRpbCB0aGUgc2Vzc2lvbidzIGRlYWRsaW5lLgoKLSBgcmVxdWVzdF9oYXNoZXNgOiB0aGUgY2FsbHMnIHJlcXVlc3QgaGFzaGVzLCAzMiBieXRlcyBlYWNoLCBjb25jYXRlbmF0ZWQgaW4gY2FsbCBvcmRlci4KLSBgdGlja2V0YDogdGhlIGFnZW50J3Mgc2lnbmF0dXJlIG92ZXIgYHRpY2tldCh0bylgLCB3aGljaCBjb21taXRzIGl0IHRvIGFsbCB0aG9zZSByZXF1ZXN0cy4KLSBgc2VlZGA6IHRoZSBiYXRjaCdzIHJldmVhbGVkIHNlZWQgd2hlbiBrID4gMTsgMzIgemVybyBieXRlcyB3aGVuIGsgPSAxLgotIGBlbnRyaWVzYDogb25lIDY4LWJ5dGUgZW50cnkgcGVyIGNhbGwsIGNvbmNhdGVuYXRlZCBpbiBjYWxsIG9yZGVyLgotIGBzdGF0ZW1lbnRgOiB0aGUgdmVyaWZpZXIncyBzaWduYXR1cmUgb3ZlciB0aGUgYmF0Y2ggc3RhdGVtZW50LgoKUHJvdmVkIERFTElWRVJFRCBjYWxscyBhbmQgdW5wcm92ZWQgYW5zd2VyZWQgY2FsbHMgYXJlIHBhaWQsIG1pbnVzIGBrIOKIkiAxYCBjYWxscyBmb3IgZWFjaApwcm92ZWQgZmFpbHVyZSAobmV2ZXIgYmVsb3cgemVybyk7IHRoZSByZXN0IG9mIHRoZSBiYXRjaCBpcyByZWZ1bmRlZCB0byB0aGUgYWdlbnQuIEEKc2lnbmF0dXJlIHRoYXQgZG9lcyBub3QgdmVyaWZ5IGZhaWxzIHRoZSBjYWxsIHdpdGggdGhlIGhvc3QncyBjcnlwdG8gZXJyb3IuAAAAAAAADHNldHRsZV9iYXRjaAAAAAcAAAAAAAAACnNlc3Npb25faWQAAAAAA+4AAAAgAAAAAAAAAAJ0bwAAAAAABAAAAAAAAAAOcmVxdWVzdF9oYXNoZXMAAAAAAA4AAAAAAAAABnRpY2tldAAAAAAD7gAAAEAAAAAAAAAABHNlZWQAAAPuAAAAIAAAAAAAAAAHZW50cmllcwAAAAAOAAAAAAAAAAlzdGF0ZW1lbnQAAAAAAAPuAAAAQAAAAAEAAAPpAAAAAgAAAAM=",
        "AAAAAAAAAG1SdW5zIG9uY2UsIGF0IGRlcGxveW1lbnQuIGBlc2Nyb3dgIGlzIHRoZSBGZXJtYXRhIGVzY3JvdyB3aG9zZSBzZXJ2aWNlcywgZmVlIGFuZCB0cmVhc3VyeQp0aGlzIGNvbnRyYWN0IHVzZXMuAAAAAAAADV9fY29uc3RydWN0b3IAAAAAAAABAAAAAAAAAAZlc2Nyb3cAAAAAABMAAAAA",
        "AAAAAAAAAIdBZnRlciB0aGUgc2Vzc2lvbidzIGRlYWRsaW5lLCByZXR1cm5zIHdoYXQgaXMgbGVmdCBvZiB0aGUgZGVwb3NpdCB0byB0aGUgYWdlbnQuIENhbGxhYmxlIGJ5CmFueW9uZTsgdGhlIG1vbmV5IGFsd2F5cyBnb2VzIHRvIHRoZSBhZ2VudC4AAAAADWNsb3NlX3Nlc3Npb24AAAAAAAABAAAAAAAAAApzZXNzaW9uX2lkAAAAAAPuAAAAIAAAAAEAAAPpAAAAAgAAAAM=",
        "AAAAAAAAAGpUaGUgZXhhY3QgYnl0ZXMgdGhlIGFnZW50J3MgdGlja2V0IGtleSBzaWducyBmb3IgY2FsbCBgbmAgb2YgYSBzZXNzaW9uLCBvbiB0aGlzIG5ldHdvcmsgYW5kCnRoaXMgY29udHJhY3QuAAAAAAAOdGlja2V0X21lc3NhZ2UAAAAAAAMAAAAAAAAACnNlc3Npb25faWQAAAAAA+4AAAAgAAAAAAAAAAFuAAAAAAAABAAAAAAAAAAFY2hhaW4AAAAAAAPuAAAAIAAAAAEAAAAO",
        "AAAAAAAAAFxUaGUgZXhhY3QgYnl0ZXMgdGhlIHZlcmlmaWVyIHNpZ25zIGZvciBhIGJhdGNoIHN0YXRlbWVudCwgb24gdGhpcyBuZXR3b3JrIGFuZCB0aGlzIGNvbnRyYWN0LgAAABFzdGF0ZW1lbnRfbWVzc2FnZQAAAAAAAAgAAAAAAAAACnNlc3Npb25faWQAAAAAA+4AAAAgAAAAAAAAAApzZXJ2aWNlX2lkAAAAAAPuAAAAIAAAAAAAAAAOcHJlZGljYXRlX2hhc2gAAAAAA+4AAAAgAAAAAAAAAARmcm9tAAAABAAAAAAAAAACdG8AAAAAAAQAAAAAAAAABWNoYWluAAAAAAAD7gAAACAAAAAAAAAABHNlZWQAAAPuAAAAIAAAAAAAAAAHZW50cmllcwAAAAAOAAAAAQAAAA4=",
        "AAAAAQAAALBPbmUgZGVwb3NpdCBmb3IgdXAgdG8gYG1heF9jYWxsc2AgY2FsbHMgb2Ygb25lIHNlcnZpY2UsIHNldHRsZWQgaW4gYmF0Y2hlcy4gVGhlIHNlcnZpY2Uncwp0ZXJtcyBhcmUgY29waWVkIGZyb20gdGhlIGVzY3JvdydzIHJlZ2lzdHJ5IGF0IG9wZW5pbmcgKHNlcnZpY2VzIGFyZSBpbW11dGFibGUgdGhlcmUpLgAAAAAAAAAHU2Vzc2lvbgAAAAASAAAAAAAAAAVhZ2VudAAAAAAAABMAAABcVGhlIGJhdGNoIHNpemUgQjogYXQgbW9zdCBCIGNhbGxzIHBlciBiYXRjaCwgZXhhY3RseSBCIGZvciBzYW1wbGVkIHNlc3Npb25zIGV4Y2VwdCB0aGUgbGFzdC4AAAAKYmF0Y2hfc2l6ZQAAAAAABAAAADZgY2hhaW4oc2V0dGxlZClgOyBgc2Vzc2lvbl9pZGAgYmVmb3JlIHRoZSBmaXJzdCBiYXRjaC4AAAAAAAVjaGFpbgAAAAAAA+4AAAAgAAAAWVRoZSBsYXN0IGxlZGdlciB0aW1lc3RhbXAgYXQgd2hpY2ggYSBiYXRjaCBpcyBhY2NlcHRlZDogYGV4cGlyZXNfYXQgKyBzZXR0bGVtZW50X3dpbmRvd2AuAAAAAAAACGRlYWRsaW5lAAAABgAAAExUaGUgZXNjcm93J3MgZmVlIGF0IG9wZW5pbmc7IGxhdGVyIGZlZSBjaGFuZ2VzIGRvIG5vdCBhcHBseSB0byB0aGlzIHNlc3Npb24uAAAAB2ZlZV9icHMAAAAABAAAAAAAAAAJbWF4X2NhbGxzAAAAAAAABAAAAAAAAAAJb3BlbmVkX2F0AAAAAAAABgAAAAAAAAAGcGF5b3V0AAAAAAATAAAAAAAAAA5wcmVkaWNhdGVfaGFzaAAAAAAD7gAAACAAAABCVGhlIHNlcnZpY2UncyBwcmljZSBwZXIgY2FsbDsgdGhlIGRlcG9zaXQgaXMgYG1heF9jYWxscyDDlyBwcmljZWAuAAAAAAAFcHJpY2UAAAAAAAALAAAANk9uZSBjYWxsIGluIGBzYW1wbGVfa2AgaXMgcHJvdmVkOyAxIHByb3ZlcyBldmVyeSBjYWxsLgAAAAAACHNhbXBsZV9rAAAABAAAAFpUaGUgbGFzdCByZXZlYWxlZCBzZWVkICh0aGUgY29tbWl0bWVudCBiZWZvcmUgdGhlIGZpcnN0IGJhdGNoKTsgemVybyB3aGVuIGBzYW1wbGVfa2AgaXMgMS4AAAAAAARzZWVkAAAD7gAAACAAAAAAAAAACnNlcnZpY2VfaWQAAAAAA+4AAAAgAAAAQkNhbGxzIHNldHRsZWQgc28gZmFyOyB0aGUgbmV4dCBiYXRjaCBzdGFydHMgYXQgY2FsbCBgc2V0dGxlZCArIDFgLgAAAAAAB3NldHRsZWQAAAAABAAAAAAAAAAGc3RhdHVzAAAAAAfQAAAADVNlc3Npb25TdGF0dXMAAAAAAAA6VGhlIGFnZW50J3MgRWQyNTUxOSBrZXkgZm9yIHRpY2tldHMgKG5vdCBpdHMgYWNjb3VudCBrZXkpLgAAAAAACnRpY2tldF9rZXkAAAAAA+4AAAAgAAAAAAAAAAV0b2tlbgAAAAAAABMAAABUVGhlIEVkMjU1MTkga2V5IHdob3NlIGJhdGNoIHN0YXRlbWVudHMgc2V0dGxlIHRoaXMgc2Vzc2lvbiAodGhlIHNlcnZpY2UncyB2ZXJpZmllcikuAAAACHZlcmlmaWVyAAAD7gAAACA=",
        "AAAAAwAAADtMaWZlIGN5Y2xlIG9mIGEgc2Vzc2lvbi4gQSBzZXNzaW9uIGlkIGlzIHVzYWJsZSBvbmNlLCBldmVyLgAAAAAAAAAADVNlc3Npb25TdGF0dXMAAAAAAAACAAAAKENhbGxzIG1heSBiZSBzZXR0bGVkIHVudGlsIHRoZSBkZWFkbGluZS4AAAAET3BlbgAAAAEAAACNRXZlcnkgY2FsbCBzZXR0bGVkLCBhIHNob3J0IHNhbXBsZWQgYmF0Y2ggZW5kZWQgaXQsIG9yIGl0IHdhcyBjbG9zZWQgYWZ0ZXIgaXRzIGRlYWRsaW5lLgpXaGF0IHdhcyBsZWZ0IG9mIHRoZSBkZXBvc2l0IHdlbnQgYmFjayB0byB0aGUgYWdlbnQuAAAAAAAABkNsb3NlZAAAAAAAAg==",
        "AAAABAAAAY9Db250cmFjdCBlcnJvcnMuIENvZGVzIGFyZSBwdWJsaWMgQUJJIGFuZCBuZXZlciByZXVzZWQuIFRoZXkgc3RhcnQgYXQgMjAxLCBhcGFydCBmcm9tIHRoZQplc2Nyb3cncyAoMTAx4oCTMTE3KSBhbmQgdGhlIFN0ZWxsYXIgQXNzZXQgQ29udHJhY3QncyBvd24gY29kZXMgKDHigJMxNSwgZS5nLiAxMCA9IGluc3VmZmljaWVudApiYWxhbmNlKSwgd2hpY2ggYSBmYWlsZWQgdG9rZW4gdHJhbnNmZXIgcHJvcGFnYXRlcyB1bmNoYW5nZWQuCgpBIHRpY2tldCBvciBzdGF0ZW1lbnQgc2lnbmF0dXJlIHRoYXQgZG9lcyBub3QgdmVyaWZ5IGlzIG5vdCBhIGNvbnRyYWN0IGVycm9yOiB0aGUgaG9zdCdzCmBlZDI1NTE5X3ZlcmlmeWAgdHJhcHMgd2l0aCBhIGNyeXB0byBlcnJvciwgYXMgaW4gdGhlIGVzY3Jvdy4AAAAAAAAAAAVFcnJvcgAAAAAAAAsAAAC0T3BlbmluZyB0ZXJtcyBvdXRzaWRlIHRoZSBsaW1pdHMgKGNhbGxzLCBrLCBiYXRjaCBzaXplLCBleHBpcnksIGRlcG9zaXQpLCBhIHplcm8gc2Vzc2lvbgppZCBvciB0aWNrZXQga2V5LCBhIHNlZWQgdGhhdCBkb2VzIG5vdCBtYXRjaCBrLCBvciBhIHNlcnZpY2Ugd2hvc2UgcGF5b3V0IGlzIHRoaXMgY29udHJhY3QuAAAADkludmFsaWRTZXNzaW9uAAAAAADJAAAAAAAAAA1TZXNzaW9uRXhpc3RzAAAAAAAAygAAACdUaGUgZXNjcm93IGhhcyBubyBzZXJ2aWNlIHdpdGggdGhpcyBpZC4AAAAADlVua25vd25TZXJ2aWNlAAAAAADLAAAAHU5vIG9wZW4gc2Vzc2lvbiB3aXRoIHRoaXMgaWQuAAAAAAAAB05vdE9wZW4AAAAAzAAAAEBUaGUgc2Vzc2lvbidzIGRlYWRsaW5lIGhhcyBwYXNzZWQ7IG9ubHkgYGNsb3NlX3Nlc3Npb25gIHJlbWFpbnMuAAAADFdpbmRvd0Nsb3NlZAAAAM0AAAAqVGhlIHNlc3Npb24ncyBkZWFkbGluZSBoYXMgbm90IHBhc3NlZCB5ZXQuAAAAAAAKV2luZG93T3BlbgAAAAAAzgAAAGxBIGJhdGNoIHRoYXQgc2V0dGxlcyBubyBjYWxsLCBnb2VzIHBhc3QgYG1heF9jYWxsc2AsIGlzIGxvbmdlciB0aGFuIEIsIG9yIChzYW1wbGVkKSBpcyBub3QKdGhlIG5leHQgQiBjYWxscy4AAAAMSW52YWxpZEJhdGNoAAAAzwAAAEpSZXF1ZXN0IGhhc2hlcyBvciBlbnRyaWVzIHdob3NlIGxlbmd0aCBpcyBub3QgdGhlIGJhdGNoJ3MgbnVtYmVyIG9mIGNhbGxzLgAAAAAADkxlbmd0aE1pc21hdGNoAAAAAADQAAAAV0Egc2VlZCB0aGF0IGlzIG5vdCB0aGUgbmV4dCBvbmUgaW4gdGhlIHZlcmlmaWVyJ3MgY2hhaW4sIG9yIGEgbm9uLXplcm8gc2VlZCB3aGVuIGsgPSAxLgAAAAALSW52YWxpZFNlZWQAAAAA0QAAADRBIHJlc3VsdCB0aGF0IHRoZSBzYW1wbGUgb3IgdGhlIGhhc2hlcyBkbyBub3QgYWxsb3cuAAAADEludmFsaWRFbnRyeQAAANIAAABKVGhlIGVzY3JvdydzIHRyZWFzdXJ5IGlzIHRoaXMgY29udHJhY3Q6IGZlZXMgc2VudCB0aGVyZSBjb3VsZCBuZXZlciBsZWF2ZS4AAAAAABBJbnZhbGlkUmVjaXBpZW50AAAA0w==",
        "AAAABQAAAKlDYWxscyBgZnJvbSArIDFgIHRocm91Z2ggYHRvYCB3ZXJlIHNldHRsZWQ6IGBwYWlkYCBvZiB0aGVtIHBhaWQgdGhlIHZlbmRvciBgcGF5b3V0X2Ftb3VudGAgaW4KYWxsIGFuZCB0aGUgdHJlYXN1cnkgYGZlZWA7IGByZWZ1bmRgIHdlbnQgYmFjayB0byB0aGUgYWdlbnQgZm9yIHRoZSBvdGhlcnMuAAAAAAAAAAAAAAxCYXRjaFNldHRsZWQAAAABAAAADWJhdGNoX3NldHRsZWQAAAAAAAAOAAAAAAAAAApzZXNzaW9uX2lkAAAAAAPuAAAAIAAAAAEAAAAAAAAACnNlcnZpY2VfaWQAAAAAA+4AAAAgAAAAAQAAAAAAAAAEZnJvbQAAAAQAAAAAAAAAAAAAAAJ0bwAAAAAABAAAAAAAAAAAAAAACWRlbGl2ZXJlZAAAAAAAAAQAAAAAAAAAAAAAAAZmYWlsZWQAAAAAAAQAAAAAAAAAAAAAAAhhbnN3ZXJlZAAAAAQAAAAAAAAAAAAAAAp1bmFuc3dlcmVkAAAAAAAEAAAAAAAAAAAAAAAEcGFpZAAAAAQAAAAAAAAAAAAAAA1wYXlvdXRfYW1vdW50AAAAAAAACwAAAAAAAAAAAAAAA2ZlZQAAAAALAAAAAAAAAAAAAAAGcmVmdW5kAAAAAAALAAAAAAAAAAxgY2hhaW4odG8pYC4AAAAFY2hhaW4AAAAAAAPuAAAAIAAAAAAAAAAAAAAADGVudHJpZXNfaGFzaAAAA+4AAAAgAAAAAAAAAAI=",
        "AAAABQAAAFJUaGUgc2Vzc2lvbiBlbmRlZDsgYHJlZnVuZGAgKHdoYXQgd2FzIGxlZnQgb2YgdGhlIGRlcG9zaXQpIHdlbnQgYmFjayB0byB0aGUgYWdlbnQuAAAAAAAAAAAADVNlc3Npb25DbG9zZWQAAAAAAAABAAAADnNlc3Npb25fY2xvc2VkAAAAAAAEAAAAAAAAAApzZXNzaW9uX2lkAAAAAAPuAAAAIAAAAAEAAAAAAAAACnNlcnZpY2VfaWQAAAAAA+4AAAAgAAAAAQAAAAAAAAAFYWdlbnQAAAAAAAATAAAAAQAAAAAAAAAGcmVmdW5kAAAAAAALAAAAAAAAAAI=",
        "AAAABQAAAENUaGUgYWdlbnQgZGVwb3NpdGVkIGBkZXBvc2l0ID0gbWF4X2NhbGxzIMOXIHByaWNlYCBmb3IgdGhlIHNlc3Npb24uAAAAAAAAAAANU2Vzc2lvbk9wZW5lZAAAAAAAAAEAAAAOc2Vzc2lvbl9vcGVuZWQAAAAAAAkAAAAAAAAACnNlc3Npb25faWQAAAAAA+4AAAAgAAAAAQAAAAAAAAAKc2VydmljZV9pZAAAAAAD7gAAACAAAAABAAAAAAAAAAVhZ2VudAAAAAAAABMAAAABAAAAAAAAAAdkZXBvc2l0AAAAAAsAAAAAAAAAAAAAAAltYXhfY2FsbHMAAAAAAAAEAAAAAAAAAAAAAAAFcHJpY2UAAAAAAAALAAAAAAAAAAAAAAAIc2FtcGxlX2sAAAAEAAAAAAAAAAAAAAAKYmF0Y2hfc2l6ZQAAAAAABAAAAAAAAAAAAAAACGRlYWRsaW5lAAAABgAAAAAAAAAC" ]),
      options
    )
  }
  public readonly fromJSON = {
    escrow: this.txFromJSON<string>,
        call_id: this.txFromJSON<Buffer>,
        sampled: this.txFromJSON<boolean>,
        get_session: this.txFromJSON<Option<Session>>,
        open_session: this.txFromJSON<Result<void>>,
        settle_batch: this.txFromJSON<Result<void>>,
        close_session: this.txFromJSON<Result<void>>,
        ticket_message: this.txFromJSON<Buffer>,
        statement_message: this.txFromJSON<Buffer>
  }
}