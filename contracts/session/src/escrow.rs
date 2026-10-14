//! The escrow's views this contract reads: its registry, its fee and its treasury. A client for
//! three functions of `contracts/escrow`, so the escrow's code is not linked into this contract.

use soroban_sdk::{contractclient, Address, BytesN, Env};

use crate::Service;

#[allow(dead_code)]
#[contractclient(name = "EscrowClient")]
pub trait Escrow {
    fn get_service(env: Env, service_id: BytesN<32>) -> Option<Service>;
    fn fee_bps(env: Env) -> u32;
    fn treasury(env: Env) -> Address;
}
