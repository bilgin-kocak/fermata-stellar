//! Shared fixture: a Stellar Asset Contract, the real escrow (`contracts/escrow`, fee 50 bps) with
//! one registered service, and the session contract next to it. Tickets and statements are signed
//! with `crates/fermata-verdict`, so every settlement also checks that the off-chain encoding and
//! the contract's on-chain encoding agree.

use std::vec::Vec as StdVec;

use ed25519_dalek::SigningKey;
use fermata_escrow::{FermataEscrow, FermataEscrowClient};
use fermata_verdict::{self as fv, session as fs};
use soroban_sdk::{
    address_payload::AddressPayload,
    testutils::{Address as _, Events as _, Ledger as _},
    token::{StellarAssetClient, TokenClient},
    xdr, Address, Bytes, BytesN, ConversionError, Env, InvokeError, Symbol, TryFromVal, Val,
};

use crate::{Error, FermataSession, FermataSessionClient, Session};

/// 0.01 of a 7-decimal asset such as USDC on Stellar.
pub const PRICE: i128 = 100_000;
pub const WINDOW: u32 = 120;
pub const FEE_BPS: u32 = 50;
pub const FEE: i128 = PRICE * FEE_BPS as i128 / 10_000;
pub const START: u64 = 1_700_000_000;
pub const START_LEDGER: u32 = 1_000;
pub const AGENT_FUNDS: i128 = 10_000_000_000_000;
pub const PREDICATE: [u8; 32] = [0x44; 32];
pub const VERIFIER_SEED: [u8; 32] = [0xbe; 32];
pub const TICKET_SEED: [u8; 32] = [0x7c; 32];
pub const DAY: u64 = 86_400;
pub const B: u32 = 8;

pub fn b32(env: &Env, bytes: [u8; 32]) -> BytesN<32> {
    BytesN::from_array(env, &bytes)
}

/// A distinct session id per `n`.
pub fn sid(env: &Env, n: u32) -> BytesN<32> {
    b32(env, fs_hash(b"session", n))
}

pub fn fs_hash(tag: &[u8], n: u32) -> [u8; 32] {
    fermata_verdict::session_vectors::per_call(tag, n)
}

/// The request hash of call `n` in the tests.
pub fn request(n: u32) -> [u8; 32] {
    fs_hash(b"request", n)
}

pub fn delivered(n: u32) -> fs::Entry {
    fs::Entry::proved(true, fs_hash(b"presentation", n), fs_hash(b"response", n))
}

pub fn failed(n: u32) -> fs::Entry {
    fs::Entry::proved(false, fs_hash(b"presentation", n), fs_hash(b"response", n))
}

pub fn answered() -> fs::Entry {
    fs::Entry::answered()
}

pub fn unanswered() -> fs::Entry {
    fs::Entry::unanswered()
}

/// The 32-byte id inside a contract address.
pub fn contract_id(address: &Address) -> [u8; 32] {
    match address.to_payload() {
        Some(AddressPayload::ContractIdHash(id)) => id.to_array(),
        _ => panic!("not a contract address"),
    }
}

/// One batch, ready for `settle_batch`.
#[derive(Clone)]
pub struct Batch {
    pub to: u32,
    pub request_hashes: Bytes,
    pub ticket: BytesN<64>,
    pub seed: BytesN<32>,
    pub entries: Bytes,
    pub statement: BytesN<64>,
}

pub struct Fixture {
    pub env: Env,
    pub escrow: FermataEscrowClient<'static>,
    pub session: FermataSessionClient<'static>,
    pub token: TokenClient<'static>,
    pub token_admin: StellarAssetClient<'static>,
    pub treasury: Address,
    pub vendor: Address,
    pub payout: Address,
    pub agent: Address,
    pub verifier: SigningKey,
    pub ticket_key: SigningKey,
    pub service_id: BytesN<32>,
}

impl Fixture {
    /// The fixture with both contracts compiled natively, as most tests run them.
    pub fn new() -> Self {
        Self::with_contracts(
            |env, args| env.register(FermataEscrow, args),
            |env, escrow| env.register(FermataSession, (escrow,)),
        )
    }

    /// The fixture with the escrow registered by `escrow` (given its constructor arguments) and
    /// the session contract by `session` (given the escrow's address); for example from the built
    /// wasm, so that the wasm VM's own instructions are metered.
    pub fn with_contracts(
        escrow: impl FnOnce(&Env, (Address, Address, u32)) -> Address,
        session: impl FnOnce(&Env, &Address) -> Address,
    ) -> Self {
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
        let sac = env.register_stellar_asset_contract_v2(Address::generate(&env));
        let token = TokenClient::new(&env, &sac.address());
        let token_admin = StellarAssetClient::new(&env, &sac.address());
        let escrow_id = escrow(&env, (owner, treasury.clone(), FEE_BPS));
        let escrow = FermataEscrowClient::new(&env, &escrow_id);
        let verifier = SigningKey::from_bytes(&VERIFIER_SEED);
        let service_id = escrow.register_service(
            &vendor,
            &BytesN::from_array(&env, &fv::service::label("quote").unwrap()),
            &payout,
            &sac.address(),
            &PRICE,
            &WINDOW,
            &b32(&env, verifier.verifying_key().to_bytes()),
            &b32(&env, PREDICATE),
            &b32(&env, [0x0a; 32]),
            &b32(&env, [0x0b; 32]),
        );
        let session_id = session(&env, &escrow_id);
        let session = FermataSessionClient::new(&env, &session_id);
        token_admin.mint(&agent, &AGENT_FUNDS);
        Self {
            env,
            escrow,
            session,
            token,
            token_admin,
            treasury,
            vendor,
            payout,
            agent,
            verifier,
            ticket_key: SigningKey::from_bytes(&TICKET_SEED),
            service_id,
        }
    }

    pub fn ticket_pk(&self) -> BytesN<32> {
        b32(&self.env, self.ticket_key.verifying_key().to_bytes())
    }

    pub fn zero(&self) -> BytesN<32> {
        b32(&self.env, [0; 32])
    }

    pub fn now(&self) -> u64 {
        self.env.ledger().timestamp()
    }

    /// Opens a session on the default service, expiring in a day.
    pub fn open(&self, id: &BytesN<32>, max_calls: u32, k: u32, batch: u32, seed: [u8; 32]) {
        self.session.open_session(
            &self.agent,
            id,
            &self.service_id,
            &max_calls,
            &self.ticket_pk(),
            &k,
            &batch,
            &b32(&self.env, seed),
            &(self.now() + DAY),
        );
    }

    /// Opens a session in which every call is proved (k = 1), batches of up to `B`.
    pub fn open_plain(&self, id: &BytesN<32>, max_calls: u32) {
        self.open(id, max_calls, 1, B, [0; 32]);
    }

    pub fn get(&self, id: &BytesN<32>) -> Session {
        self.session.get_session(id).expect("session exists")
    }

    /// The session contract's domain: the test network and its id.
    pub fn domain(&self) -> fv::Domain {
        fv::Domain {
            network_id: self.env.ledger().network_id().to_array(),
            contract_id: contract_id(&self.session.address),
        }
    }

    /// The next batch of session `id`, from its stored state: `requests` for the next calls, each
    /// with its entry, the ticket for the last of them and a statement signed by the verifier.
    pub fn next_batch(
        &self,
        id: &BytesN<32>,
        requests: &[[u8; 32]],
        seed: [u8; 32],
        entries: &[fs::Entry],
    ) -> Batch {
        let s = self.get(id);
        self.batch_with(
            &self.ticket_key,
            &self.verifier,
            &self.domain(),
            id,
            s.settled,
            s.chain.to_array(),
            requests,
            seed,
            entries,
        )
    }

    /// A batch built from explicit inputs, so tests can change any one of them.
    #[allow(clippy::too_many_arguments)]
    pub fn batch_with(
        &self,
        ticket_key: &SigningKey,
        verifier: &SigningKey,
        domain: &fv::Domain,
        id: &BytesN<32>,
        from: u32,
        from_chain: [u8; 32],
        requests: &[[u8; 32]],
        seed: [u8; 32],
        entries: &[fs::Entry],
    ) -> Batch {
        let session_id = id.to_array();
        let to = from + requests.len() as u32;
        let chain = fs::extend_chain(&from_chain, requests);
        let statement = fs::Statement {
            session_id,
            service_id: self.service_id.to_array(),
            predicate_hash: PREDICATE,
            from,
            to,
            chain,
            seed,
            entries_hash: fs::entries_hash(entries),
        };
        let env = &self.env;
        Batch {
            to,
            request_hashes: Bytes::from_slice(env, &requests.concat()),
            ticket: BytesN::from_array(
                env,
                &fs::sign_ticket(ticket_key, domain, &session_id, to, &chain),
            ),
            seed: b32(env, seed),
            entries: Bytes::from_slice(
                env,
                &entries
                    .iter()
                    .flat_map(|e| e.bytes())
                    .collect::<StdVec<u8>>(),
            ),
            statement: BytesN::from_array(env, &fs::sign_statement(verifier, domain, &statement)),
        }
    }

    pub fn settle(&self, id: &BytesN<32>, b: &Batch) {
        self.session.settle_batch(
            id,
            &b.to,
            &b.request_hashes,
            &b.ticket,
            &b.seed,
            &b.entries,
            &b.statement,
        );
    }

    #[allow(clippy::type_complexity)]
    pub fn try_settle(
        &self,
        id: &BytesN<32>,
        b: &Batch,
    ) -> Result<Result<(), ConversionError>, Result<Error, InvokeError>> {
        self.session.try_settle_batch(
            id,
            &b.to,
            &b.request_hashes,
            &b.ticket,
            &b.seed,
            &b.entries,
            &b.statement,
        )
    }

    pub fn balance(&self, who: &Address) -> i128 {
        self.token.balance(who)
    }

    /// Moves the ledger clock forward (and the ledger sequence by one).
    pub fn warp(&self, seconds: u64) {
        self.env.ledger().with_mut(|l| {
            l.timestamp += seconds;
            l.sequence_number += 1;
        });
    }
}

/// Token movements `(from, to, amount)` in the last invocation's events, in order. Must be called
/// before any other invocation (events reset on each call).
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
