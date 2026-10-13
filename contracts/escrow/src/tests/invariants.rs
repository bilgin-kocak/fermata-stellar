//! Fermata's Foundry invariant suite (`FermataEscrow.invariant.t.sol`) as randomized action
//! sequences: holds, settlements, timeouts, time jumps, fee changes and replay attempts across
//! four services on two tokens and three agents, with exact balance deltas asserted on every step
//! and ghost state kept alongside. After every step:
//!
//! - per token, the escrow holds exactly the sum of the prices of the calls still Held, counted
//!   from ghost state and from the escrow's own records;
//! - every call's on-chain record matches the ghost (status, agent, ids, fee snapshot; amount and
//!   deadline only while Held) and a final status never changes, so a call settles at most once;
//! - money is conserved: held + paid out = paid in, and no token leaves the known holders.
//!
//! 128 sequences of up to 64 actions, as Foundry's `runs = 128, depth = 64`.

use std::collections::HashMap;
use std::vec::Vec as StdVec;

use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, Address, BytesN, Env};

use super::setup::*;
use crate::{
    Error, FermataEscrow, FermataEscrowClient, Status, Verdict, OUTCOME_DELIVERED, OUTCOME_FAILED,
};

#[derive(Clone, Debug)]
enum Action {
    Hold { agent: usize, service: usize },
    Settle { call: usize, delivered: bool },
    Timeout { call: usize },
    Warp { seconds: u64 },
    SetFee { bps: u32 },
    Replay { call: usize },
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        (any::<usize>(), any::<usize>())
            .prop_map(|(agent, service)| Action::Hold { agent, service }),
        (any::<usize>(), any::<bool>())
            .prop_map(|(call, delivered)| Action::Settle { call, delivered }),
        any::<usize>().prop_map(|call| Action::Timeout { call }),
        (0u64..=7_200).prop_map(|seconds| Action::Warp { seconds }),
        (0u32..=500).prop_map(|bps| Action::SetFee { bps }),
        any::<usize>().prop_map(|call| Action::Replay { call }),
    ]
}

#[derive(Clone)]
struct Ghost {
    status: Status,
    agent: Address,
    service: usize,
    request_hash: BytesN<32>,
    fee_bps: u32,
    held_at: u64,
}

struct ServiceInfo {
    id: BytesN<32>,
    token: usize,
    price: i128,
    window: u32,
    payout: Address,
}

struct Handler {
    env: Env,
    escrow: FermataEscrowClient<'static>,
    tokens: StdVec<Token>,
    treasury: Address,
    verifier: SigningKey,
    agents: StdVec<Address>,
    services: StdVec<ServiceInfo>,
    holders: StdVec<Address>,
    calls: StdVec<BytesN<32>>,
    open: StdVec<BytesN<32>>,
    ghost: HashMap<[u8; 32], Ghost>,
    held: [i128; 2],
    paid_in: [i128; 2],
    paid_out: [i128; 2],
    minted: [i128; 2],
    holds: u32,
    finalised: u32,
    nonce: u32,
}

impl Handler {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().with_mut(|l| {
            l.timestamp = START;
            l.sequence_number = START_LEDGER;
        });
        let owner = Address::generate(&env);
        let treasury = Address::generate(&env);
        let escrow_id = env.register(FermataEscrow, (&owner, &treasury, 50u32));
        let escrow = FermataEscrowClient::new(&env, &escrow_id);
        let tokens = std::vec![Token::new(&env), Token::new(&env)];
        let verifier = SigningKey::from_bytes(&VERIFIER_SEED);
        let mut h = Self {
            holders: std::vec![escrow_id, treasury.clone()],
            env,
            escrow,
            tokens,
            treasury,
            verifier,
            agents: StdVec::new(),
            services: StdVec::new(),
            calls: StdVec::new(),
            open: StdVec::new(),
            ghost: HashMap::new(),
            held: [0; 2],
            paid_in: [0; 2],
            paid_out: [0; 2],
            minted: [0; 2],
            holds: 0,
            finalised: 0,
            nonce: 0,
        };
        // prices 1 and 199 make the fee round to zero at low bps; windows from 30 s to 1 h
        let vendor_a = Address::generate(&h.env);
        h.add_service(&vendor_a, "quote", 0, 10_000, 60);
        h.add_service(&vendor_a, "tiny", 0, 199, 30);
        h.add_service(&Address::generate(&h.env), "bulk", 1, 1_234_567, 120);
        h.add_service(&Address::generate(&h.env), "dust", 1, 1, 3_600);
        for _ in 0..3 {
            let agent = Address::generate(&h.env);
            for t in 0..2 {
                h.tokens[t].mint(&agent, 1_000_000_000_000_000);
                h.minted[t] += 1_000_000_000_000_000;
            }
            h.holders.push(agent.clone());
            h.agents.push(agent);
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
            &label(&self.env, name),
            &payout,
            &self.tokens[token].address,
            &price,
            &window,
            &public_key(&self.env, &self.verifier),
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

    fn deadline(&self, g: &Ghost) -> u64 {
        g.held_at + u64::from(self.services[g.service].window)
    }

    fn apply(&mut self, action: &Action) {
        match *action {
            Action::Hold { agent, service } => {
                self.hold(agent, service);
            }
            Action::Settle { call, delivered } => self.settle(call, delivered),
            Action::Timeout { call } => self.timeout(call),
            Action::Warp { seconds } => self.env.ledger().with_mut(|l| {
                l.timestamp += seconds;
                l.sequence_number += 1;
            }),
            Action::SetFee { bps } => self.escrow.set_fee_bps(&bps),
            Action::Replay { call } => self.replay(call),
        }
    }

    fn hold(&mut self, agent_seed: usize, service_seed: usize) -> BytesN<32> {
        let agent = self.agents[agent_seed % self.agents.len()].clone();
        let service = service_seed % self.services.len();
        let (sid, t, price) = {
            let s = &self.services[service];
            (s.id.clone(), s.token, s.price)
        };
        self.nonce += 1;
        let call_id = hash(&self.env, &[b"invariant-call", &self.nonce.to_be_bytes()]);
        let request_hash = hash(&self.env, &[b"request", &call_id.to_array()]);
        let agent_before = self.tokens[t].balance(&agent);
        let escrow_before = self.tokens[t].balance(&self.escrow.address);

        self.escrow.hold(&agent, &call_id, &sid, &request_hash);

        assert_eq!(
            self.tokens[t].balance(&agent),
            agent_before - price,
            "hold agent delta"
        );
        assert_eq!(
            self.tokens[t].balance(&self.escrow.address),
            escrow_before + price,
            "hold escrow delta"
        );
        self.ghost.insert(
            call_id.to_array(),
            Ghost {
                status: Status::Held,
                agent,
                service,
                request_hash,
                fee_bps: self.escrow.fee_bps(),
                held_at: self.now(),
            },
        );
        self.held[t] += price;
        self.paid_in[t] += price;
        self.calls.push(call_id.clone());
        self.open.push(call_id.clone());
        self.holds += 1;
        call_id
    }

    /// An open call, holding one first if none is open.
    fn open_call(&mut self, seed: usize) -> BytesN<32> {
        if self.open.is_empty() {
            return self.hold(seed, seed >> 8);
        }
        self.open[seed % self.open.len()].clone()
    }

    fn verdict(&self, call_id: &BytesN<32>, delivered: bool) -> (Verdict, BytesN<64>) {
        let g = &self.ghost[&call_id.to_array()];
        let v = Verdict {
            call_id: call_id.clone(),
            service_id: self.services[g.service].id.clone(),
            request_hash: g.request_hash.clone(),
            predicate_hash: b32(&self.env, PREDICATE),
            outcome: if delivered {
                OUTCOME_DELIVERED
            } else {
                OUTCOME_FAILED
            },
            presentation_hash: hash(&self.env, &[b"presentation", &call_id.to_array()]),
            response_hash: hash(&self.env, &[b"response", &call_id.to_array()]),
            issued_at: self.now(),
        };
        let domain = fermata_verdict::Domain {
            network_id: self.env.ledger().network_id().to_array(),
            contract_id: contract_id(&self.escrow.address),
        };
        let sig = fermata_verdict::sign(&self.verifier, &domain, &offchain(&v));
        (v, BytesN::from_array(&self.env, &sig))
    }

    /// Settles an open call. Outside its window the verdict must be rejected with WindowClosed.
    fn settle(&mut self, seed: usize, delivered: bool) {
        let call_id = self.open_call(seed);
        let g = self.ghost[&call_id.to_array()].clone();
        let (v, sig) = self.verdict(&call_id, delivered);
        if self.now() > self.deadline(&g) {
            expect_error(
                self.escrow.try_settle(&call_id, &v, &sig),
                Error::WindowClosed,
            );
            return;
        }
        let s = &self.services[g.service];
        let (t, price, payout) = (s.token, s.price, s.payout.clone());
        let fee = if delivered {
            price * i128::from(g.fee_bps) / 10_000
        } else {
            0
        };
        let token = &self.tokens[t];
        let payout_before = token.balance(&payout);
        let treasury_before = token.balance(&self.treasury);
        let agent_before = token.balance(&g.agent);

        self.escrow.settle(&call_id, &v, &sig);

        if delivered {
            assert_eq!(
                token.balance(&payout),
                payout_before + price - fee,
                "payout delta"
            );
            assert_eq!(
                token.balance(&self.treasury),
                treasury_before + fee,
                "fee delta"
            );
            assert_eq!(
                token.balance(&g.agent),
                agent_before,
                "agent paid on release"
            );
            self.finalise(&call_id, Status::Released);
        } else {
            assert_eq!(
                token.balance(&g.agent),
                agent_before + price,
                "refund delta"
            );
            assert_eq!(
                token.balance(&payout),
                payout_before,
                "payout paid on refund"
            );
            assert_eq!(
                token.balance(&self.treasury),
                treasury_before,
                "fee charged on refund"
            );
            self.finalise(&call_id, Status::Refunded);
        }
    }

    /// Times out an open call: inside the window `claim_timeout` must fail with WindowOpen; then
    /// time moves past the deadline and anyone can refund the agent.
    fn timeout(&mut self, seed: usize) {
        let call_id = self.open_call(seed);
        let g = self.ghost[&call_id.to_array()].clone();
        let deadline = self.deadline(&g);
        if self.now() <= deadline {
            expect_error(self.escrow.try_claim_timeout(&call_id), Error::WindowOpen);
            self.env.ledger().with_mut(|l| l.timestamp = deadline + 1);
        }
        let (t, price) = (
            self.services[g.service].token,
            self.services[g.service].price,
        );
        let agent_before = self.tokens[t].balance(&g.agent);
        self.escrow.claim_timeout(&call_id);
        assert_eq!(
            self.tokens[t].balance(&g.agent),
            agent_before + price,
            "timeout refund delta"
        );
        self.finalise(&call_id, Status::TimedOut);
    }

    /// A used call id can never be held again; a finalised one can never be settled or timed out.
    fn replay(&mut self, seed: usize) {
        if self.calls.is_empty() {
            return;
        }
        let call_id = self.calls[seed % self.calls.len()].clone();
        let g = self.ghost[&call_id.to_array()].clone();
        let sid = self.services[g.service].id.clone();
        expect_error(
            self.escrow
                .try_hold(&g.agent, &call_id, &sid, &g.request_hash),
            Error::CallIdUsed,
        );
        if g.status == Status::Held {
            return;
        }
        let (v, sig) = self.verdict(&call_id, true);
        expect_error(self.escrow.try_settle(&call_id, &v, &sig), Error::NotHeld);
        expect_error(self.escrow.try_claim_timeout(&call_id), Error::NotHeld);
    }

    fn finalise(&mut self, call_id: &BytesN<32>, status: Status) {
        let g = self.ghost.get_mut(&call_id.to_array()).unwrap();
        assert_eq!(g.status, Status::Held, "finalised call was not open");
        g.status = status;
        let s = &self.services[g.service];
        self.held[s.token] -= s.price;
        self.paid_out[s.token] += s.price;
        self.open.retain(|c| c != call_id);
        self.finalised += 1;
    }

    fn check_invariants(&self) {
        // the escrow holds exactly the open holds, per token, from ghost state and from its records
        let mut held_on_chain = [0i128; 2];
        for call_id in &self.calls {
            let g = &self.ghost[&call_id.to_array()];
            let s = &self.services[g.service];
            let view = self
                .escrow
                .get_hold(call_id)
                .expect("a held call has a record");
            // statuses match the ghost; finalised records keep their data
            assert_eq!(view.status, g.status, "status drift");
            assert_eq!(view.agent, g.agent, "agent drift");
            assert_eq!(view.service_id, s.id, "service id drift");
            assert_eq!(view.request_hash, g.request_hash, "request hash drift");
            assert_eq!(view.fee_bps, g.fee_bps, "fee snapshot drift");
            if g.status == Status::Held {
                assert_eq!(view.amount, s.price, "amount drift");
                assert_eq!(view.deadline, self.deadline(g), "deadline drift");
                held_on_chain[s.token] += view.amount;
            } else {
                assert_eq!(view.amount, 0, "amount after finalisation");
                assert_eq!(view.deadline, 0, "deadline after finalisation");
            }
        }
        for (t, token) in self.tokens.iter().enumerate() {
            let escrow_balance = token.balance(&self.escrow.address);
            assert_eq!(escrow_balance, self.held[t], "escrow != ghost held");
            assert_eq!(
                escrow_balance, held_on_chain[t],
                "escrow != sum of Held records"
            );
            // conservation
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
    fn escrow_invariants_hold_under_random_sequences(
        actions in proptest::collection::vec(action(), 1..=64)
    ) {
        let mut h = Handler::new();
        for action in &actions {
            h.apply(action);
            h.check_invariants();
        }
        // guards against a vacuous run; skipped for short (shrunk) sequences, as in Foundry
        if actions.len() >= 32 {
            prop_assert!(h.holds > 0, "no hold happened");
            prop_assert!(h.finalised > 0, "nothing was finalised");
        }
    }
}
