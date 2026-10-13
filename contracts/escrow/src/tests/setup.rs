//! Shared fixture: one Stellar Asset Contract (the host's real SAC code), one escrow (fee 50 bps)
//! and one registered service, mirroring Fermata's `EscrowBase.sol`. Verdicts are signed with
//! `crates/fermata-verdict`, so every settle in these tests also checks that the off-chain
//! encoding and the contract's on-chain encoding agree.

use std::vec::Vec as StdVec;

use ed25519_dalek::SigningKey;
use fermata_verdict as fv;
use soroban_sdk::{
    address_payload::AddressPayload,
    testutils::{Address as _, Events as _, Ledger as _, StellarAssetContract},
    token::{StellarAssetClient, TokenClient},
    xdr, Address, BytesN, ConversionError, Env, IntoVal, InvokeError, Symbol, TryFromVal, Val,
};

use crate::{Error, FermataEscrow, FermataEscrowClient, Status, Verdict};

/// 0.01 of a 7-decimal asset such as USDC on Stellar.
pub const PRICE: i128 = 100_000;
pub const WINDOW: u32 = 120;
pub const FEE_BPS: u32 = 50;
pub const START: u64 = 1_700_000_000;
pub const START_LEDGER: u32 = 1_000;
pub const AGENT_FUNDS: i128 = 10_000_000_000_000;
pub const PREDICATE: [u8; 32] = [0x44; 32];
pub const ORIGIN: [u8; 32] = [0x0a; 32];
pub const NOTARY: [u8; 32] = [0x0b; 32];
pub const REQUEST: [u8; 32] = [0x33; 32];
pub const VERIFIER_SEED: [u8; 32] = [0xbe; 32];

pub fn b32(env: &Env, bytes: [u8; 32]) -> BytesN<32> {
    BytesN::from_array(env, &bytes)
}

pub fn label(env: &Env, text: &str) -> BytesN<12> {
    BytesN::from_array(env, &fv::service::label(text).expect("valid label"))
}

/// sha256 of the concatenated parts.
pub fn hash(env: &Env, parts: &[&[u8]]) -> BytesN<32> {
    b32(env, fv::hashes::sha256(&parts.concat()))
}

/// A distinct call id per `n`.
pub fn call(env: &Env, n: u32) -> BytesN<32> {
    hash(env, &[b"call", &n.to_be_bytes()])
}

pub fn public_key(env: &Env, key: &SigningKey) -> BytesN<32> {
    b32(env, key.verifying_key().to_bytes())
}

/// The 32-byte id inside a contract address.
pub fn contract_id(address: &Address) -> [u8; 32] {
    match address.to_payload() {
        Some(AddressPayload::ContractIdHash(id)) => id.to_array(),
        _ => panic!("not a contract address"),
    }
}

/// The off-chain (`fermata-verdict`) form of a contract verdict.
pub fn offchain(v: &Verdict) -> fv::Verdict {
    fv::Verdict {
        call_id: v.call_id.to_array(),
        service_id: v.service_id.to_array(),
        request_hash: v.request_hash.to_array(),
        predicate_hash: v.predicate_hash.to_array(),
        outcome: v.outcome,
        presentation_hash: v.presentation_hash.to_array(),
        response_hash: v.response_hash.to_array(),
        issued_at: v.issued_at,
    }
}

/// The contract form of an off-chain verdict.
pub fn onchain(env: &Env, v: &fv::Verdict) -> Verdict {
    Verdict {
        call_id: b32(env, v.call_id),
        service_id: b32(env, v.service_id),
        request_hash: b32(env, v.request_hash),
        predicate_hash: b32(env, v.predicate_hash),
        outcome: v.outcome,
        presentation_hash: b32(env, v.presentation_hash),
        response_hash: b32(env, v.response_hash),
        issued_at: v.issued_at,
    }
}

/// A Stellar Asset Contract for a fresh classic asset.
pub struct Token {
    pub sac: StellarAssetContract,
    pub address: Address,
    pub client: TokenClient<'static>,
    pub admin: StellarAssetClient<'static>,
}

impl Token {
    pub fn new(env: &Env) -> Self {
        let sac = env.register_stellar_asset_contract_v2(Address::generate(env));
        let address = sac.address();
        Self {
            client: TokenClient::new(env, &address),
            admin: StellarAssetClient::new(env, &address),
            address,
            sac,
        }
    }

    pub fn balance(&self, who: &Address) -> i128 {
        self.client.balance(who)
    }

    pub fn mint(&self, to: &Address, amount: i128) {
        self.admin.mint(to, &amount);
    }
}

pub struct Fixture {
    pub env: Env,
    pub escrow: FermataEscrowClient<'static>,
    pub token: Token,
    pub owner: Address,
    pub treasury: Address,
    pub vendor: Address,
    pub payout: Address,
    pub agent: Address,
    pub verifier: SigningKey,
    pub service_id: BytesN<32>,
}

impl Fixture {
    pub fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().with_mut(|l| {
            l.timestamp = START;
            l.sequence_number = START_LEDGER;
            l.network_id = fv::network_id(fv::TESTNET_PASSPHRASE);
        });
        let owner = Address::generate(&env);
        let treasury = Address::generate(&env);
        let vendor = Address::generate(&env);
        let payout = Address::generate(&env);
        let agent = Address::generate(&env);
        let token = Token::new(&env);
        let escrow_id = env.register(FermataEscrow, (&owner, &treasury, FEE_BPS));
        let escrow = FermataEscrowClient::new(&env, &escrow_id);
        let verifier = SigningKey::from_bytes(&VERIFIER_SEED);
        let service_id = escrow.register_service(
            &vendor,
            &label(&env, "quote"),
            &payout,
            &token.address,
            &PRICE,
            &WINDOW,
            &public_key(&env, &verifier),
            &b32(&env, PREDICATE),
            &b32(&env, ORIGIN),
            &b32(&env, NOTARY),
        );
        token.mint(&agent, AGENT_FUNDS);
        Self {
            env,
            escrow,
            token,
            owner,
            treasury,
            vendor,
            payout,
            agent,
            verifier,
            service_id,
        }
    }

    pub fn escrow_id(&self) -> Address {
        self.escrow.address.clone()
    }

    pub fn request(&self) -> BytesN<32> {
        b32(&self.env, REQUEST)
    }

    /// Registers another service of the vendor's, paid to the same payout, same verifier.
    pub fn register(&self, label_text: &str, token: &Address, price: i128) -> BytesN<32> {
        self.escrow.register_service(
            &self.vendor,
            &label(&self.env, label_text),
            &self.payout,
            token,
            &price,
            &WINDOW,
            &public_key(&self.env, &self.verifier),
            &b32(&self.env, PREDICATE),
            &b32(&self.env, ORIGIN),
            &b32(&self.env, NOTARY),
        )
    }

    /// The agent holds the price of the default service for `call_id`.
    pub fn hold(&self, call_id: &BytesN<32>) {
        self.escrow
            .hold(&self.agent, call_id, &self.service_id, &self.request());
    }

    pub fn hold_on(&self, service_id: &BytesN<32>, call_id: &BytesN<32>) {
        self.escrow
            .hold(&self.agent, call_id, service_id, &self.request());
    }

    /// A verdict for the default service, as Fermata's `EscrowBase.verdict`.
    pub fn verdict(&self, call_id: &BytesN<32>, outcome: u32) -> Verdict {
        let id = call_id.to_array();
        Verdict {
            call_id: call_id.clone(),
            service_id: self.service_id.clone(),
            request_hash: self.request(),
            predicate_hash: b32(&self.env, PREDICATE),
            outcome,
            presentation_hash: hash(&self.env, &[b"presentation", &id]),
            response_hash: hash(&self.env, &[b"response", &id]),
            issued_at: self.env.ledger().timestamp(),
        }
    }

    /// This deployment's domain: the test network and this escrow.
    pub fn domain(&self) -> fv::Domain {
        fv::Domain {
            network_id: self.env.ledger().network_id().to_array(),
            contract_id: contract_id(&self.escrow_id()),
        }
    }

    pub fn sign(&self, v: &Verdict) -> BytesN<64> {
        self.sign_with(&self.verifier, v)
    }

    pub fn sign_with(&self, key: &SigningKey, v: &Verdict) -> BytesN<64> {
        self.sign_for(key, &self.domain(), v)
    }

    pub fn sign_for(&self, key: &SigningKey, domain: &fv::Domain, v: &Verdict) -> BytesN<64> {
        BytesN::from_array(&self.env, &fv::sign(key, domain, &offchain(v)))
    }

    /// Signs a fresh verdict with the service verifier and settles it.
    pub fn settle(&self, call_id: &BytesN<32>, outcome: u32) {
        let v = self.verdict(call_id, outcome);
        let sig = self.sign(&v);
        self.escrow.settle(call_id, &v, &sig);
    }

    /// `settle` through the raw host interface, so host errors keep their type and code.
    pub fn settle_raw(
        &self,
        call_id: &BytesN<32>,
        v: &Verdict,
        sig: &BytesN<64>,
    ) -> Result<(), soroban_sdk::Error> {
        let args = (call_id.clone(), v.clone(), sig.clone()).into_val(&self.env);
        match self.env.try_invoke_contract::<Val, soroban_sdk::Error>(
            &self.escrow_id(),
            &Symbol::new(&self.env, "settle"),
            args,
        ) {
            Ok(_) => Ok(()),
            Err(Ok(e)) => Err(e),
            Err(Err(e)) => panic!("unexpected invoke error {e:?}"),
        }
    }

    pub fn status(&self, call_id: &BytesN<32>) -> Option<Status> {
        self.escrow.get_hold(call_id).map(|h| h.status)
    }

    /// Moves the ledger clock forward (and the ledger sequence by one).
    pub fn warp(&self, seconds: u64) {
        self.env.ledger().with_mut(|l| {
            l.timestamp += seconds;
            l.sequence_number += 1;
        });
    }

    pub fn now(&self) -> u64 {
        self.env.ledger().timestamp()
    }
}

/// What a caller sees when the escrow traps on a host error, such as a failed Ed25519 check: the
/// host hands callers a generic `Error(Context, InvalidAction)` and records the cause,
/// `Error(Crypto, InvalidInput)` "failed ED25519 verification", in its diagnostics. Tests that use
/// it pair it with a positive control; the `should_panic` tests in `settle.rs` pin the cause.
pub fn trapped() -> soroban_sdk::Error {
    soroban_sdk::Error::from_type_and_code(
        xdr::ScErrorType::Context,
        xdr::ScErrorCode::InvalidAction,
    )
}

/// Token movements `(from, to, amount)` in the last invocation's events, in order: the SAC's
/// `transfer` events. Must be called before any other invocation (events reset on each call).
pub fn transfers(env: &Env, token: &Address) -> StdVec<(Address, Address, i128)> {
    let events = env.events().all().filter_by_contract(token);
    events
        .events()
        .iter()
        .filter_map(|e| {
            let xdr::ContractEventBody::V0(body) = &e.body;
            let topic = |i: usize| Val::try_from_val(env, &body.topics[i]).unwrap();
            let name = Symbol::try_from_val(env, &topic(0)).ok()?;
            if name != Symbol::new(env, "transfer") {
                return None;
            }
            let from = Address::try_from_val(env, &topic(1)).unwrap();
            let to = Address::try_from_val(env, &topic(2)).unwrap();
            let data = Val::try_from_val(env, &body.data).unwrap();
            Some((from, to, i128::try_from_val(env, &data).unwrap()))
        })
        .collect()
}

/// Stellar Asset Contract error codes (soroban-env-host `builtin_contracts/contract_error.rs`),
/// propagated unchanged when a token transfer inside the escrow fails.
pub const SAC_BALANCE_ERROR: u32 = 10;
pub const SAC_BALANCE_DEAUTHORIZED: u32 = 11;

/// Asserts that a `try_` call failed with the contract error `expected`.
#[track_caller]
pub fn expect_error<T: core::fmt::Debug>(
    result: Result<Result<T, ConversionError>, Result<Error, InvokeError>>,
    expected: Error,
) {
    match result {
        Err(Ok(e)) => assert_eq!(e, expected),
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

/// Asserts that a `try_` call failed with an error code from the token contract.
#[track_caller]
pub fn expect_token_error<T: core::fmt::Debug>(
    result: Result<Result<T, ConversionError>, Result<Error, InvokeError>>,
    code: u32,
) {
    match result {
        Err(Err(InvokeError::Contract(c))) => assert_eq!(c, code),
        other => panic!("expected token error {code}, got {other:?}"),
    }
}

/// Asserts that a `try_` call failed in the host (auth, crypto, trap), not with a contract error.
#[track_caller]
pub fn expect_abort<T: core::fmt::Debug>(
    result: Result<Result<T, ConversionError>, Result<Error, InvokeError>>,
) {
    match result {
        Err(Err(InvokeError::Abort)) => {}
        other => panic!("expected a host error, got {other:?}"),
    }
}
