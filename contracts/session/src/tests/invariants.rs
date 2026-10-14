//! Randomized action sequences over sessions, in the manner of the escrow's invariant suite
//! (`contracts/escrow/src/tests/invariants.rs`, after Fermata's `FermataEscrow.invariant.t.sol`):
//! openings with every call proved or one call in four sampled, batches with random results,
//! closings, time jumps, fee changes, replays and tampered batches, across three services on two
//! tokens and three agents, with exact balance deltas asserted on every step. After every step:
//!
//! - per token, the session contract holds exactly the sum of `(max_calls − settled) × price` over
//!   the open sessions, counted from ghost state and from the contract's own records;
//! - every session's record matches the ghost (settled calls, chain, seed, status, fee snapshot),
//!   so `settled` only grows and a closed session never reopens;
//! - money is conserved: held + paid out = paid in, and no token leaves the known holders.
//!
//! 128 sequences of up to 64 actions, as the escrow's suite.

use std::vec::Vec as StdVec;

use ed25519_dalek::SigningKey;
use fermata_escrow::{FermataEscrow, FermataEscrowClient};
use fermata_verdict::{self as fv, session as fs};
use proptest::prelude::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    token::{StellarAssetClient, TokenClient},
    Address, Bytes, BytesN, Env,
};

use super::setup::*;
use crate::{Error, FermataSession, FermataSessionClient, SessionStatus};

#[derive(Clone, Debug)]
enum Action {
    Open {
        agent: usize,
        service: usize,
        calls: u32,
        sampled: bool,
        batch: u32,
        hours: u64,
    },
    Settle {
        session: usize,
        size: usize,
        results: u64,
    },
    Close {
        session: usize,
    },
    Warp {
        seconds: u64,
    },
    SetFee {
        bps: u32,
    },
    Replay {
        session: usize,
    },
    Tamper {
        session: usize,
        entries: bool,
    },
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        2 => (
            any::<usize>(),
            any::<usize>(),
            1u32..=40,
            any::<bool>(),
            1u32..=8,
            1u64..=48,
        )
            .prop_map(|(agent, service, calls, sampled, batch, hours)| Action::Open {
                agent,
                service,
                calls,
                sampled,
                batch,
                hours,
            }),
        4 => (any::<usize>(), any::<usize>(), any::<u64>()).prop_map(|(session, size, results)| {
            Action::Settle {
                session,
                size,
                results,
            }
        }),
        1 => any::<usize>().prop_map(|session| Action::Close { session }),
        1 => (0u64..=7_200).prop_map(|seconds| Action::Warp { seconds }),
        1 => (0u32..=500).prop_map(|bps| Action::SetFee { bps }),
        1 => any::<usize>().prop_map(|session| Action::Replay { session }),
        1 => (any::<usize>(), any::<bool>())
            .prop_map(|(session, entries)| Action::Tamper { session, entries }),
    ]
}

/// What the suite knows about a session, kept independently of the contract.
#[derive(Clone)]
struct Ghost {
    id: BytesN<32>,
    agent: usize,
    service: usize,
    max_calls: u32,
    k: u32,
    batch: u32,
    fee_bps: u32,
    deadline: u64,
    settled: u32,
    chain: [u8; 32],
    /// The verifier's seed chain: `seeds[0]` at opening, batch j reveals `seeds[j]`.
    seeds: StdVec<[u8; 32]>,
    batches: usize,
    status: SessionStatus,
    last: Option<Batch>,
}

struct ServiceInfo {
    id: BytesN<32>,
    token: usize,
    price: i128,
    window: u32,
    payout: Address,
}

struct Agent {
    address: Address,
    ticket_key: SigningKey,
}

struct Handler {
    env: Env,
    escrow: FermataEscrowClient<'static>,
    session: FermataSessionClient<'static>,
    tokens: StdVec<TokenClient<'static>>,
    treasury: Address,
    verifier: SigningKey,
    agents: StdVec<Agent>,
    services: StdVec<ServiceInfo>,
    holders: StdVec<Address>,
    sessions: StdVec<Ghost>,
    held: [i128; 2],
    paid_in: [i128; 2],
    paid_out: [i128; 2],
    minted: [i128; 2],
    opened: u32,
    settled_batches: u32,
    nonce: u32,
}

impl Handler {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().with_mut(|l| {
            l.timestamp = START;
            l.sequence_number = START_LEDGER;
            l.network_id = fv::network_id(fv::TESTNET_PASSPHRASE);
        });
        let treasury = Address::generate(&env);
        let escrow_id = env.register(FermataEscrow, (Address::generate(&env), &treasury, FEE_BPS));
        let escrow = FermataEscrowClient::new(&env, &escrow_id);
        let session_id = env.register(FermataSession, (&escrow_id,));
        let session = FermataSessionClient::new(&env, &session_id);
        let mut admins = StdVec::new();
        let mut tokens = StdVec::new();
        for _ in 0..2 {
            let sac = env.register_stellar_asset_contract_v2(Address::generate(&env));
            admins.push(StellarAssetClient::new(&env, &sac.address()));
            tokens.push(TokenClient::new(&env, &sac.address()));
        }
        let mut h = Self {
            holders: std::vec![session_id, escrow_id, treasury.clone()],
            env,
            escrow,
            session,
            tokens,
            treasury,
            verifier: SigningKey::from_bytes(&VERIFIER_SEED),
            agents: StdVec::new(),
            services: StdVec::new(),
            sessions: StdVec::new(),
            held: [0; 2],
            paid_in: [0; 2],
            paid_out: [0; 2],
            minted: [0; 2],
            opened: 0,
            settled_batches: 0,
            nonce: 0,
        };
        // A price of 199 makes the fee round to zero below 51 bps; windows from 30 s to 120 s.
        let vendor = Address::generate(&h.env);
        h.add_service(&vendor, "quote", 0, 10_000, 60);
        h.add_service(&vendor, "tiny", 0, 199, 30);
        h.add_service(&Address::generate(&h.env), "bulk", 1, 1_234_567, 120);
        for i in 0..3u32 {
            let address = Address::generate(&h.env);
            for (t, admin) in admins.iter().enumerate() {
                admin.mint(&address, &1_000_000_000_000_000);
                h.minted[t] += 1_000_000_000_000_000;
            }
            h.holders.push(address.clone());
            h.agents.push(Agent {
                address,
                ticket_key: SigningKey::from_bytes(&fs_hash(b"ticket-key", i)),
            });
        }
        h
    }

    fn add_service(
        &mut self,
        vendor: &Address,
        name: &str,
        token: usize,
        price: i128,
        window: u32,
    ) {
        let payout = Address::generate(&self.env);
        let id = self.escrow.register_service(
            vendor,
            &BytesN::from_array(&self.env, &fv::service::label(name).unwrap()),
            &payout,
            &self.tokens[token].address,
            &price,
            &window,
            &b32(&self.env, self.verifier.verifying_key().to_bytes()),
            &b32(&self.env, PREDICATE),
            &b32(&self.env, [0; 32]),
            &b32(&self.env, [0; 32]),
        );
        self.holders.push(payout.clone());
        self.services.push(ServiceInfo {
            id,
            token,
            price,
            window,
            payout,
        });
    }

    fn now(&self) -> u64 {
        self.env.ledger().timestamp()
    }

    fn apply(&mut self, action: &Action) {
        match *action {
            Action::Open {
                agent,
                service,
                calls,
                sampled,
                batch,
                hours,
            } => {
                self.open(agent, service, calls, sampled, batch, hours);
            }
            Action::Settle {
                session,
                size,
                results,
            } => self.settle(session, size, results),
            Action::Close { session } => self.close(session),
            Action::Warp { seconds } => self.env.ledger().with_mut(|l| {
                l.timestamp += seconds;
                l.sequence_number += 1;
            }),
            Action::SetFee { bps } => self.escrow.set_fee_bps(&bps),
            Action::Replay { session } => self.replay(session),
            Action::Tamper { session, entries } => self.tamper(session, entries),
        }
    }

    fn open(
        &mut self,
        agent: usize,
        service: usize,
        calls: u32,
        sampled: bool,
        batch: u32,
        hours: u64,
    ) -> usize {
        let agent = agent % self.agents.len();
        let service = service % self.services.len();
        let (k, seeds) = if sampled {
            self.nonce += 1;
            let secret = fs_hash(b"invariant-secret", self.nonce);
            (4, fs::seed_chain(&secret, calls.div_ceil(batch)))
        } else {
            (1, std::vec![[0; 32]])
        };
        self.nonce += 1;
        let id = b32(&self.env, fs_hash(b"invariant-session", self.nonce));
        let expires_at = self.now() + hours * 3_600;
        let s = &self.services[service];
        let (t, price, window) = (s.token, s.price, s.window);
        let deposit = i128::from(calls) * price;
        let a = &self.agents[agent];
        let token = &self.tokens[t];
        let agent_before = token.balance(&a.address);
        let contract_before = token.balance(&self.session.address);

        self.session.open_session(
            &a.address,
            &id,
            &s.id,
            &calls,
            &b32(&self.env, a.ticket_key.verifying_key().to_bytes()),
            &k,
            &batch,
            &b32(&self.env, seeds[0]),
            &expires_at,
        );

        assert_eq!(
            token.balance(&a.address),
            agent_before - deposit,
            "open agent delta"
        );
        assert_eq!(
            token.balance(&self.session.address),
            contract_before + deposit,
            "open contract delta"
        );
        self.sessions.push(Ghost {
            chain: id.to_array(),
            id,
            agent,
            service,
            max_calls: calls,
            k,
            batch,
            fee_bps: self.escrow.fee_bps(),
            deadline: expires_at + u64::from(window),
            settled: 0,
            seeds,
            batches: 0,
            status: SessionStatus::Open,
            last: None,
        });
        self.held[t] += deposit;
        self.paid_in[t] += deposit;
        self.opened += 1;
        self.sessions.len() - 1
    }

    /// An open session, opening one first if none is open.
    fn open_session(&mut self, seed: usize) -> usize {
        let open: StdVec<usize> = (0..self.sessions.len())
            .filter(|&i| self.sessions[i].status == SessionStatus::Open)
            .collect();
        if open.is_empty() {
            let calls = 1 + (seed % 24) as u32;
            return self.open(
                seed,
                seed >> 8,
                calls,
                seed & 1 == 1,
                1 + (seed % 8) as u32,
                24,
            );
        }
        open[seed % open.len()]
    }

    /// The next batch of session `i`: `size` picks how many calls, `results` their results.
    fn next_batch(&self, i: usize, size: usize, results: u64) -> (Batch, StdVec<fs::Entry>) {
        let g = &self.sessions[i];
        let remaining = g.max_calls - g.settled;
        let count = if g.k == 1 || size.is_multiple_of(3) {
            // Any size up to B (with sampling, a shorter batch is the last one).
            remaining.min(1 + (size % g.batch as usize) as u32)
        } else {
            remaining.min(g.batch)
        };
        let seed = if g.k == 1 {
            [0; 32]
        } else {
            g.seeds[g.batches + 1]
        };
        let id = g.id.to_array();
        let requests: StdVec<[u8; 32]> = (g.settled + 1..=g.settled + count)
            .map(|n| fs::chain_next(&id, &fs_hash(b"request", n)))
            .collect();
        let entries: StdVec<fs::Entry> = (g.settled + 1..=g.settled + count)
            .enumerate()
            .map(|(j, n)| {
                let bits = (results >> (2 * (j % 32))) & 3;
                if fs::sampled(&seed, n, g.k) {
                    match bits {
                        1 => failed(n),
                        2 => unanswered(),
                        _ => delivered(n),
                    }
                } else if bits == 2 {
                    unanswered()
                } else {
                    answered()
                }
            })
            .collect();
        (self.batch(i, &requests, seed, &entries, &entries), entries)
    }

    /// A batch of session `i` whose statement covers `signed` and which submits `entries`.
    fn batch(
        &self,
        i: usize,
        requests: &[[u8; 32]],
        seed: [u8; 32],
        signed: &[fs::Entry],
        entries: &[fs::Entry],
    ) -> Batch {
        let g = &self.sessions[i];
        let domain = fv::Domain {
            network_id: self.env.ledger().network_id().to_array(),
            contract_id: contract_id(&self.session.address),
        };
        let session_id = g.id.to_array();
        let to = g.settled + requests.len() as u32;
        let chain = fs::extend_chain(&g.chain, requests);
        let statement = fs::Statement {
            session_id,
            service_id: self.services[g.service].id.to_array(),
            predicate_hash: PREDICATE,
            from: g.settled,
            to,
            chain,
            seed,
            entries_hash: fs::entries_hash(signed),
        };
        let ticket_key = &self.agents[g.agent].ticket_key;
        let env = &self.env;
        Batch {
            to,
            request_hashes: Bytes::from_slice(env, &requests.concat()),
            ticket: BytesN::from_array(
                env,
                &fs::sign_ticket(ticket_key, &domain, &session_id, to, &chain),
            ),
            seed: b32(env, seed),
            entries: Bytes::from_slice(
                env,
                &entries
                    .iter()
                    .flat_map(|e| e.bytes())
                    .collect::<StdVec<u8>>(),
            ),
            statement: BytesN::from_array(
                env,
                &fs::sign_statement(&self.verifier, &domain, &statement),
            ),
        }
    }

    fn try_settle(
        &self,
        i: usize,
        b: &Batch,
    ) -> Result<Result<(), soroban_sdk::ConversionError>, Result<Error, soroban_sdk::InvokeError>>
    {
        self.session.try_settle_batch(
            &self.sessions[i].id,
            &b.to,
            &b.request_hashes,
            &b.ticket,
            &b.seed,
            &b.entries,
            &b.statement,
        )
    }

    /// Settles the next batch of an open session. After its deadline the batch must be refused
    /// with WindowClosed.
    fn settle(&mut self, seed: usize, size: usize, results: u64) {
        let i = self.open_session(seed);
        let (b, entries) = self.next_batch(i, size, results);
        let g = self.sessions[i].clone();
        if self.now() > g.deadline {
            expect_error(self.try_settle(i, &b), Error::WindowClosed);
            return;
        }
        let s = &self.services[g.service];
        let (t, price, payout) = (s.token, s.price, s.payout.clone());
        let count = b.to - g.settled;
        let n = |r: u32| entries.iter().filter(|e| e.result == r).count() as i64;
        let paid = (n(fs::RESULT_ANSWERED) + n(fs::RESULT_DELIVERED)
            - i64::from(g.k - 1) * n(fs::RESULT_FAILED))
        .max(0);
        let paid = i128::from(paid);
        let fee_unit = price * i128::from(g.fee_bps) / 10_000;
        let finished = b.to == g.max_calls || (g.k > 1 && count < g.batch);
        let rest = if finished {
            i128::from(g.max_calls - b.to) * price
        } else {
            0
        };
        let token = &self.tokens[t];
        let agent = &self.agents[g.agent].address;
        let payout_before = token.balance(&payout);
        let treasury_before = token.balance(&self.treasury);
        let agent_before = token.balance(agent);
        let contract_before = token.balance(&self.session.address);

        self.try_settle(i, &b).unwrap().unwrap();

        assert_eq!(
            token.balance(&payout),
            payout_before + paid * (price - fee_unit),
            "payout delta"
        );
        assert_eq!(
            token.balance(&self.treasury),
            treasury_before + paid * fee_unit,
            "fee delta"
        );
        assert_eq!(
            token.balance(agent),
            agent_before + (i128::from(count) - paid) * price + rest,
            "agent delta"
        );
        assert_eq!(
            token.balance(&self.session.address),
            contract_before - i128::from(count) * price - rest,
            "contract delta"
        );
        let out = i128::from(count) * price + rest;
        self.held[t] -= out;
        self.paid_out[t] += out;
        let g = &mut self.sessions[i];
        g.settled = b.to;
        g.chain = fs::extend_chain(
            &g.chain,
            &b.request_hashes
                .iter()
                .collect::<StdVec<u8>>()
                .chunks(32)
                .map(|c| c.try_into().unwrap())
                .collect::<StdVec<[u8; 32]>>(),
        );
        g.batches += 1;
        if finished {
            g.status = SessionStatus::Closed;
        }
        g.last = Some(b);
        self.settled_batches += 1;
    }

    /// Closes an open session: before its deadline `close_session` must fail with WindowOpen; then
    /// time moves past the deadline and anyone can refund the agent.
    fn close(&mut self, seed: usize) {
        let i = self.open_session(seed);
        let g = self.sessions[i].clone();
        if self.now() <= g.deadline {
            expect_error(self.session.try_close_session(&g.id), Error::WindowOpen);
            self.env.ledger().with_mut(|l| {
                l.timestamp = g.deadline + 1;
                l.sequence_number += 1;
            });
        }
        let s = &self.services[g.service];
        let (t, price) = (s.token, s.price);
        let agent = &self.agents[g.agent].address;
        let agent_before = self.tokens[t].balance(agent);
        self.session.close_session(&g.id);
        let rest = i128::from(g.max_calls - g.settled) * price;
        assert_eq!(
            self.tokens[t].balance(agent),
            agent_before + rest,
            "close refund delta"
        );
        self.held[t] -= rest;
        self.paid_out[t] += rest;
        self.sessions[i].status = SessionStatus::Closed;
    }

    /// A settled batch never settles again, and a used session id never opens again.
    fn replay(&mut self, seed: usize) {
        let with_batches: StdVec<usize> = (0..self.sessions.len())
            .filter(|&i| self.sessions[i].last.is_some())
            .collect();
        if with_batches.is_empty() {
            return;
        }
        let i = with_batches[seed % with_batches.len()];
        let g = self.sessions[i].clone();
        let expected = if g.status == SessionStatus::Closed {
            Error::NotOpen
        } else if self.now() > g.deadline {
            Error::WindowClosed
        } else {
            Error::InvalidBatch
        };
        expect_error(self.try_settle(i, g.last.as_ref().unwrap()), expected);
        let a = &self.agents[g.agent];
        let r = self.session.try_open_session(
            &a.address,
            &g.id,
            &self.services[g.service].id,
            &1,
            &b32(&self.env, a.ticket_key.verifying_key().to_bytes()),
            &1,
            &1,
            &b32(&self.env, [0; 32]),
            &(self.now() + 3_600),
        );
        expect_error(r, Error::SessionExists);
    }

    /// A batch with a request the agent did not sign, or with entries the verifier did not sign,
    /// fails in the host and changes nothing.
    fn tamper(&mut self, seed: usize, entries: bool) {
        let i = self.open_session(seed);
        let (good, signed) = self.next_batch(i, seed >> 4, seed as u64);
        let g = &self.sessions[i];
        let proved = signed.iter().position(|e| e.is_proved());
        let bad = match proved {
            Some(p) if entries => {
                let mut submitted = signed.clone();
                submitted[p].result = if submitted[p].result == fs::RESULT_DELIVERED {
                    fs::RESULT_FAILED
                } else {
                    fs::RESULT_DELIVERED
                };
                let requests: StdVec<[u8; 32]> = (g.settled + 1..=good.to)
                    .map(|n| fs::chain_next(&g.id.to_array(), &fs_hash(b"request", n)))
                    .collect();
                self.batch(i, &requests, good.seed.to_array(), &signed, &submitted)
            }
            _ => {
                let mut b = good.clone();
                let mut requests: StdVec<u8> = b.request_hashes.iter().collect();
                let last = requests.len() - 1;
                requests[last] ^= 1;
                b.request_hashes = Bytes::from_slice(&self.env, &requests);
                b
            }
        };
        if self.now() > g.deadline {
            expect_error(self.try_settle(i, &bad), Error::WindowClosed);
        } else {
            expect_abort(self.try_settle(i, &bad));
        }
    }

    fn check_invariants(&self) {
        let mut held_on_chain = [0i128; 2];
        for g in &self.sessions {
            let s = &self.services[g.service];
            let view = self
                .session
                .get_session(&g.id)
                .expect("an opened session has a record");
            assert_eq!(view.status, g.status, "status drift");
            assert_eq!(view.settled, g.settled, "settled drift");
            assert_eq!(view.chain.to_array(), g.chain, "chain drift");
            let seed = if g.k == 1 {
                [0; 32]
            } else {
                g.seeds[g.batches]
            };
            assert_eq!(view.seed.to_array(), seed, "seed drift");
            assert_eq!(view.agent, self.agents[g.agent].address, "agent drift");
            assert_eq!(view.service_id, s.id, "service id drift");
            assert_eq!(view.fee_bps, g.fee_bps, "fee snapshot drift");
            assert_eq!(view.deadline, g.deadline, "deadline drift");
            assert_eq!(
                (view.max_calls, view.sample_k, view.batch_size, view.price),
                (g.max_calls, g.k, g.batch, s.price),
                "terms drift"
            );
            if g.status == SessionStatus::Open {
                assert!(g.settled < g.max_calls, "an open session with nothing left");
                held_on_chain[s.token] += i128::from(view.max_calls - view.settled) * view.price;
            }
        }
        for (t, token) in self.tokens.iter().enumerate() {
            let balance = token.balance(&self.session.address);
            assert_eq!(balance, self.held[t], "contract != ghost held");
            assert_eq!(
                balance, held_on_chain[t],
                "contract != sum of open sessions"
            );
            assert_eq!(
                self.paid_in[t],
                self.held[t] + self.paid_out[t],
                "held + out != in"
            );
            let sum: i128 = self.holders.iter().map(|h| token.balance(h)).sum();
            assert_eq!(sum, self.minted[t], "tokens escaped the known holders");
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn session_invariants_hold_under_random_sequences(
        actions in proptest::collection::vec(action(), 1..=64)
    ) {
        let mut h = Handler::new();
        for action in &actions {
            h.apply(action);
            h.check_invariants();
        }
        // Guards against a vacuous run; skipped for short (shrunk) sequences, as in the escrow's.
        if actions.len() >= 32 {
            prop_assert!(h.opened > 0, "no session was opened");
            prop_assert!(h.settled_batches > 0, "no batch settled");
        }
    }
}
