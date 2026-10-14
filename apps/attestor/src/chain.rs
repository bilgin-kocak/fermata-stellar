//! What the verifier reads from the escrow before signing (binding checks 1–5): the hold for a
//! call id, the service it belongs to, and the close time of the latest ledger.
//!
//! Replaces Fermata `apps/attestor/src/chain.rs` @ d7cc642 (github.com/bilgin-kocak/fermata,
//! Apache-2.0), which read the Tempo escrow with `eth_call`. Kept from it: the `ChainView` trait,
//! `MockChain`, the hand-rolled JSON-RPC transport with its retries, and the re-read of a hold
//! that is not visible yet. New: the reads are Soroban RPC `simulateTransaction` calls of the
//! escrow's `get_hold` and `get_service` views, sent from the all-zero account (`GAAAA…WHF`).
//! Simulation needs no funded account and no signature, so the attestor holds no Stellar account.
//! The results are XDR `ScVal`s, decoded strictly: every field present, with its exact type.

use std::{collections::HashMap, future::Future, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail, ensure};
use fermata_verdict::keys::{account_address, contract_address};
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use stellar_xdr::{
    AccountId, ContractId, Hash, HostFunction, Int128Parts, InvokeContractArgs,
    InvokeHostFunctionOp, Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions,
    PublicKey, ReadXdr, ScAddress, ScBytes, ScSymbol, ScVal, SequenceNumber, Transaction,
    TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
};
use tokio::{
    net::TcpStream,
    sync::Mutex,
    time::{sleep, timeout},
};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
};

/// `Status::Held` in `contracts/escrow`. Status 0 stands for a call that was never held.
pub const STATUS_HELD: u32 = 1;

/// `get_hold(call_id)` (the escrow's `HoldView`). Every field is zero or empty, and `status` is 0,
/// when the call was never held (`None`). As on Tempo, `amount` and `deadline` are 0 unless Held.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HoldInfo {
    /// The agent's address, `G…` or `C…`.
    pub agent: String,
    pub service_id: [u8; 32],
    pub request_hash: [u8; 32],
    pub amount: i128,
    pub held_at: u64,
    pub deadline: u64,
    pub fee_bps: u32,
    pub status: u32,
}

/// `get_service(service_id)`. Every field is zero or empty for an unknown service (`None`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceInfo {
    pub owner: String,
    pub label: [u8; 12],
    pub settlement_window: u32,
    pub payout: String,
    pub token: String,
    /// The Ed25519 public key whose verdicts settle this service's holds.
    pub verifier: [u8; 32],
    pub price_per_call: i128,
    pub predicate_hash: [u8; 32],
    pub origin_hash: [u8; 32],
    pub notary_key_hash: [u8; 32],
}

/// `SessionStatus::Open` in `contracts/session`. Status 0 stands for a session never opened.
pub const SESSION_OPEN: u32 = 1;

/// `get_session(session_id)` of the session contract (`contracts/session`, `Session`). Every field
/// is zero or empty, and `status` is 0, for a session id that was never opened (`None`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionInfo {
    pub agent: String,
    pub service_id: [u8; 32],
    pub token: String,
    pub payout: String,
    pub price: i128,
    pub fee_bps: u32,
    /// The Ed25519 key whose batch statements settle the session (the service's verifier).
    pub verifier: [u8; 32],
    pub predicate_hash: [u8; 32],
    /// The agent's Ed25519 key for tickets.
    pub ticket_key: [u8; 32],
    pub max_calls: u32,
    pub sample_k: u32,
    pub batch_size: u32,
    pub opened_at: u64,
    /// The last ledger time at which a batch is accepted: expiry plus the settlement window.
    pub deadline: u64,
    pub settled: u32,
    /// `chain(settled)`.
    pub chain: [u8; 32],
    pub seed: [u8; 32],
    pub status: u32,
}

/// Read-only chain access the verifier needs. `SorobanChain` in production, `MockChain` in tests.
pub trait ChainView: Send + Sync {
    fn hold(&self, call_id: [u8; 32]) -> impl Future<Output = Result<HoldInfo>> + Send;
    fn service(&self, service_id: [u8; 32]) -> impl Future<Output = Result<ServiceInfo>> + Send;
    fn latest_timestamp(&self) -> impl Future<Output = Result<u64>> + Send;
    /// The session `session_id` of the session contract `contract`.
    fn session(
        &self,
        contract: [u8; 32],
        session_id: [u8; 32],
    ) -> impl Future<Output = Result<SessionInfo>> + Send;
}

// ------------------------------------------------------------------------------------------- XDR

/// The transaction whose simulation reads `function(args)` from the escrow: one
/// `InvokeHostFunction` operation from the all-zero account, sequence number 1, no signatures.
/// It is never submitted.
pub fn invocation(
    escrow: &[u8; 32],
    function: &str,
    args: Vec<ScVal>,
) -> Result<TransactionEnvelope> {
    let call = InvokeContractArgs {
        contract_address: ScAddress::Contract(ContractId(Hash(*escrow))),
        function_name: ScSymbol(function.try_into()?),
        args: args.try_into()?,
    };
    let operation = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(call),
            auth: Default::default(),
        }),
    };
    Ok(TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![operation].try_into()?,
            ext: TransactionExt::V0,
        },
        signatures: Default::default(),
    }))
}

/// A `BytesN<32>` argument.
pub fn bytes32(b: &[u8; 32]) -> ScVal {
    ScVal::Bytes(ScBytes(b.to_vec().try_into().expect("32 bytes fit")))
}

/// The fields of a `#[contracttype]` struct: an `ScMap` keyed by field-name symbols. Exactly
/// `names` must be present.
fn fields<'a>(v: &'a ScVal, what: &str, names: &[&str]) -> Result<HashMap<String, &'a ScVal>> {
    let ScVal::Map(Some(map)) = v else {
        bail!("{what}: expected a map, got {v:?}");
    };
    let mut out = HashMap::new();
    for entry in map.0.iter() {
        let ScVal::Symbol(key) = &entry.key else {
            bail!("{what}: non-symbol key {:?}", entry.key);
        };
        out.insert(key.0.to_utf8_string_lossy(), &entry.val);
    }
    let mut got: Vec<&str> = out.keys().map(String::as_str).collect();
    got.sort_unstable();
    let mut want = names.to_vec();
    want.sort_unstable();
    ensure!(got == want, "{what}: fields {got:?}, expected {want:?}");
    Ok(out)
}

fn bytes_n<const N: usize>(f: &HashMap<String, &ScVal>, name: &str) -> Result<[u8; N]> {
    match f[name] {
        ScVal::Bytes(b) => {
            b.0.as_slice()
                .try_into()
                .map_err(|_| anyhow!("{name}: {} bytes, expected {N}", b.0.len()))
        }
        other => bail!("{name}: expected bytes, got {other:?}"),
    }
}

fn u32_field(f: &HashMap<String, &ScVal>, name: &str) -> Result<u32> {
    match f[name] {
        ScVal::U32(x) => Ok(*x),
        other => bail!("{name}: expected u32, got {other:?}"),
    }
}

fn u64_field(f: &HashMap<String, &ScVal>, name: &str) -> Result<u64> {
    match f[name] {
        ScVal::U64(x) => Ok(*x),
        other => bail!("{name}: expected u64, got {other:?}"),
    }
}

fn i128_field(f: &HashMap<String, &ScVal>, name: &str) -> Result<i128> {
    match f[name] {
        ScVal::I128(Int128Parts { hi, lo }) => Ok((i128::from(*hi) << 64) | i128::from(*lo)),
        other => bail!("{name}: expected i128, got {other:?}"),
    }
}

/// An account (`G…`) or contract (`C…`) address as its strkey.
fn address_field(f: &HashMap<String, &ScVal>, name: &str) -> Result<String> {
    match f[name] {
        ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
            Uint256(key),
        )))) => Ok(account_address(key)),
        ScVal::Address(ScAddress::Contract(ContractId(Hash(id)))) => Ok(contract_address(id)),
        other => bail!("{name}: expected an account or contract address, got {other:?}"),
    }
}

/// Decodes `get_hold`'s `Option<HoldView>`.
pub fn decode_hold(v: &ScVal) -> Result<HoldInfo> {
    if matches!(v, ScVal::Void) {
        return Ok(HoldInfo::default());
    }
    let f = fields(
        v,
        "HoldView",
        &[
            "agent",
            "amount",
            "deadline",
            "fee_bps",
            "held_at",
            "request_hash",
            "service_id",
            "status",
        ],
    )?;
    let hold = HoldInfo {
        agent: address_field(&f, "agent")?,
        service_id: bytes_n(&f, "service_id")?,
        request_hash: bytes_n(&f, "request_hash")?,
        amount: i128_field(&f, "amount")?,
        held_at: u64_field(&f, "held_at")?,
        deadline: u64_field(&f, "deadline")?,
        fee_bps: u32_field(&f, "fee_bps")?,
        status: u32_field(&f, "status")?,
    };
    ensure!(hold.status != 0, "HoldView with status 0");
    Ok(hold)
}

/// Decodes `get_service`'s `Option<Service>`.
pub fn decode_service(v: &ScVal) -> Result<ServiceInfo> {
    if matches!(v, ScVal::Void) {
        return Ok(ServiceInfo::default());
    }
    let f = fields(
        v,
        "Service",
        &[
            "label",
            "notary_key_hash",
            "origin_hash",
            "owner",
            "payout",
            "predicate_hash",
            "price_per_call",
            "settlement_window",
            "token",
            "verifier",
        ],
    )?;
    Ok(ServiceInfo {
        owner: address_field(&f, "owner")?,
        label: bytes_n(&f, "label")?,
        settlement_window: u32_field(&f, "settlement_window")?,
        payout: address_field(&f, "payout")?,
        token: address_field(&f, "token")?,
        verifier: bytes_n(&f, "verifier")?,
        price_per_call: i128_field(&f, "price_per_call")?,
        predicate_hash: bytes_n(&f, "predicate_hash")?,
        origin_hash: bytes_n(&f, "origin_hash")?,
        notary_key_hash: bytes_n(&f, "notary_key_hash")?,
    })
}

/// Decodes `get_session`'s `Option<Session>`.
pub fn decode_session(v: &ScVal) -> Result<SessionInfo> {
    if matches!(v, ScVal::Void) {
        return Ok(SessionInfo::default());
    }
    let f = fields(
        v,
        "Session",
        &[
            "agent",
            "batch_size",
            "chain",
            "deadline",
            "fee_bps",
            "max_calls",
            "opened_at",
            "payout",
            "predicate_hash",
            "price",
            "sample_k",
            "seed",
            "service_id",
            "settled",
            "status",
            "ticket_key",
            "token",
            "verifier",
        ],
    )?;
    let session = SessionInfo {
        agent: address_field(&f, "agent")?,
        service_id: bytes_n(&f, "service_id")?,
        token: address_field(&f, "token")?,
        payout: address_field(&f, "payout")?,
        price: i128_field(&f, "price")?,
        fee_bps: u32_field(&f, "fee_bps")?,
        verifier: bytes_n(&f, "verifier")?,
        predicate_hash: bytes_n(&f, "predicate_hash")?,
        ticket_key: bytes_n(&f, "ticket_key")?,
        max_calls: u32_field(&f, "max_calls")?,
        sample_k: u32_field(&f, "sample_k")?,
        batch_size: u32_field(&f, "batch_size")?,
        opened_at: u64_field(&f, "opened_at")?,
        deadline: u64_field(&f, "deadline")?,
        settled: u32_field(&f, "settled")?,
        chain: bytes_n(&f, "chain")?,
        seed: bytes_n(&f, "seed")?,
        status: u32_field(&f, "status")?,
    };
    ensure!(session.status != 0, "Session with status 0");
    Ok(session)
}

// ---------------------------------------------------------------------------------------- JSON-RPC

/// Soroban RPC client for one escrow on one network. Plain `http://` (a local network) or
/// `https://` (Mozilla roots). Talks to the RPC directly; no HTTP proxy support.
#[derive(Clone)]
pub struct SorobanChain {
    pub rpc: String,
    pub network_passphrase: String,
    /// The escrow's contract id (the 32 bytes inside its `C…` address).
    pub escrow: [u8; 32],
    tls: TlsConnector,
}

impl SorobanChain {
    /// Connects, checks that the RPC serves `network_passphrase` and that `escrow` answers the
    /// escrow's `fee_bps` view.
    pub async fn connect(rpc: &str, network_passphrase: &str, escrow: [u8; 32]) -> Result<Self> {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let tls = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let chain = Self {
            rpc: rpc.to_string(),
            network_passphrase: network_passphrase.to_string(),
            escrow,
            tls,
        };
        let network = chain.call("getNetwork", Value::Null).await?;
        let served = network
            .get("passphrase")
            .and_then(Value::as_str)
            .context("getNetwork without a passphrase")?;
        ensure!(
            served == network_passphrase,
            "{rpc} serves {served:?}, not {network_passphrase:?}"
        );
        match chain.simulate("fee_bps", vec![]).await {
            Ok(ScVal::U32(_)) => Ok(chain),
            Ok(other) => bail!(
                "{} on {rpc} is not the escrow: fee_bps returned {other:?}",
                contract_address(&escrow)
            ),
            Err(e) => Err(e.context(format!(
                "no escrow at {} on {rpc}",
                contract_address(&escrow)
            ))),
        }
    }

    /// One JSON-RPC call, retried: public RPCs drop connections and time out now and then, and a
    /// transient error here must not turn a proven delivery into "no verdict" (a timeout refund).
    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut last = anyhow!("RPC {method}: no attempt made");
        for attempt in 1..=3u64 {
            match timeout(
                Duration::from_secs(10),
                self.call_once(method, params.clone()),
            )
            .await
            {
                Ok(Ok(v)) => return Ok(v),
                Ok(Err(e)) => last = e,
                Err(_) => last = anyhow!("RPC {method} timed out after 10 s"),
            }
            if attempt < 3 {
                sleep(Duration::from_millis(500 * attempt)).await;
            }
        }
        Err(last)
    }

    async fn call_once(&self, method: &str, params: Value) -> Result<Value> {
        let uri: hyper::Uri = self
            .rpc
            .parse()
            .with_context(|| format!("bad RPC url {}", self.rpc))?;
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => bail!("RPC url must be http(s): {}", self.rpc),
        };
        let host = uri.host().context("RPC url has no host")?.to_string();
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        let mut call = json!({"jsonrpc": "2.0", "id": 1, "method": method});
        if !params.is_null() {
            call["params"] = params;
        }
        let path = uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
            .to_string();
        let request = Request::post(path)
            .header("host", &host)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(serde_json::to_vec(&call)?)))?;

        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            .with_context(|| format!("connecting to {}", self.rpc))?;
        let response = if https {
            let name = ServerName::try_from(host.clone())?;
            let tls = self.tls.connect(name, tcp).await?;
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
            tokio::spawn(conn);
            sender.send_request(request).await?
        } else {
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
            tokio::spawn(conn);
            sender.send_request(request).await?
        };
        let status = response.status();
        let bytes = response.into_body().collect().await?.to_bytes();
        ensure!(
            status.is_success(),
            "RPC {method} HTTP {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
        let v: Value = serde_json::from_slice(&bytes)?;
        if let Some(err) = v.get("error") {
            bail!("RPC {method} error: {err}");
        }
        v.get("result")
            .cloned()
            .context("RPC response without result")
    }

    /// Simulates a read-only call of the escrow and returns its value.
    pub async fn simulate(&self, function: &str, args: Vec<ScVal>) -> Result<ScVal> {
        self.simulate_at(&self.escrow, function, args).await
    }

    /// Simulates a read-only call of `contract` and returns its value.
    pub async fn simulate_at(
        &self,
        contract: &[u8; 32],
        function: &str,
        args: Vec<ScVal>,
    ) -> Result<ScVal> {
        let tx = invocation(contract, function, args)?.to_xdr_base64(Limits::none())?;
        let result = self
            .call("simulateTransaction", json!({ "transaction": tx }))
            .await?;
        if let Some(error) = result.get("error").and_then(Value::as_str) {
            bail!("simulating {function}: {error}");
        }
        let xdr = result
            .pointer("/results/0/xdr")
            .and_then(Value::as_str)
            .with_context(|| format!("simulating {function}: no return value in {result}"))?;
        Ok(ScVal::from_xdr_base64(xdr, Limits::none())?)
    }

    async fn read_hold(&self, call_id: &[u8; 32]) -> Result<HoldInfo> {
        decode_hold(&self.simulate("get_hold", vec![bytes32(call_id)]).await?)
    }

    /// Checks that `contract` is a session contract that reads this escrow (its `escrow` view).
    pub async fn check_session_contract(&self, contract: &[u8; 32]) -> Result<()> {
        match self.simulate_at(contract, "escrow", vec![]).await {
            Ok(ScVal::Address(ScAddress::Contract(ContractId(Hash(id))))) if id == self.escrow => {
                Ok(())
            }
            Ok(other) => bail!(
                "{} is not a session contract of the escrow {}: escrow() returned {other:?}",
                contract_address(contract),
                contract_address(&self.escrow)
            ),
            Err(e) => Err(e.context(format!(
                "no session contract at {} on {}",
                contract_address(contract),
                self.rpc
            ))),
        }
    }
}

impl ChainView for SorobanChain {
    /// A load-balanced RPC can answer from a node a ledger or two behind the hold the agent just
    /// submitted: a hold that reads as unknown (status 0) is read again for a few seconds before
    /// the binding check rejects it.
    async fn hold(&self, call_id: [u8; 32]) -> Result<HoldInfo> {
        let mut hold = self.read_hold(&call_id).await?;
        for _ in 0..6 {
            if hold.status != 0 {
                break;
            }
            sleep(Duration::from_secs(1)).await;
            hold = self.read_hold(&call_id).await?;
        }
        Ok(hold)
    }

    async fn service(&self, service_id: [u8; 32]) -> Result<ServiceInfo> {
        decode_service(
            &self
                .simulate("get_service", vec![bytes32(&service_id)])
                .await?,
        )
    }

    /// Like a hold, a session just opened may not be visible on every RPC node yet: one that
    /// reads as never opened is read again for a few seconds.
    async fn session(&self, contract: [u8; 32], session_id: [u8; 32]) -> Result<SessionInfo> {
        let read = || async {
            decode_session(
                &self
                    .simulate_at(&contract, "get_session", vec![bytes32(&session_id)])
                    .await?,
            )
        };
        let mut session = read().await?;
        for _ in 0..6 {
            if session.status != 0 {
                break;
            }
            sleep(Duration::from_secs(1)).await;
            session = read().await?;
        }
        Ok(session)
    }

    /// The close time of the latest ledger: what `env.ledger().timestamp()` was in it.
    async fn latest_timestamp(&self) -> Result<u64> {
        let ledger = self.call("getLatestLedger", Value::Null).await?;
        let time = ledger
            .get("closeTime")
            .context("getLatestLedger without closeTime (the RPC predates protocol 23)")?;
        match time {
            Value::String(s) => Ok(s.parse()?),
            Value::Number(n) => n.as_u64().context("closeTime out of range"),
            other => bail!("closeTime is {other}"),
        }
    }
}

/// Sessions of the mock chain, by (session contract, session id).
pub type MockSessions = HashMap<([u8; 32], [u8; 32]), SessionInfo>;

/// In-memory chain for tests and offline tooling.
#[derive(Default)]
pub struct MockChain {
    pub holds: Mutex<HashMap<[u8; 32], HoldInfo>>,
    pub services: Mutex<HashMap<[u8; 32], ServiceInfo>>,
    pub sessions: Mutex<MockSessions>,
    pub now: Mutex<u64>,
}

impl ChainView for MockChain {
    async fn hold(&self, call_id: [u8; 32]) -> Result<HoldInfo> {
        Ok(self
            .holds
            .lock()
            .await
            .get(&call_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn service(&self, service_id: [u8; 32]) -> Result<ServiceInfo> {
        Ok(self
            .services
            .lock()
            .await
            .get(&service_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn latest_timestamp(&self) -> Result<u64> {
        Ok(*self.now.lock().await)
    }

    async fn session(&self, contract: [u8; 32], session_id: [u8; 32]) -> Result<SessionInfo> {
        Ok(self
            .sessions
            .lock()
            .await
            .get(&(contract, session_id))
            .cloned()
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use stellar_xdr::{ScMap, ScMapEntry};

    use super::*;

    fn sym(s: &str) -> ScVal {
        ScVal::Symbol(ScSymbol(s.try_into().unwrap()))
    }

    fn map(entries: Vec<(&str, ScVal)>) -> ScVal {
        let entries: Vec<ScMapEntry> = entries
            .into_iter()
            .map(|(k, val)| ScMapEntry { key: sym(k), val })
            .collect();
        ScVal::Map(Some(ScMap(entries.try_into().unwrap())))
    }

    fn i128_val(x: i128) -> ScVal {
        ScVal::I128(Int128Parts {
            hi: (x >> 64) as i64,
            lo: x as u64,
        })
    }

    fn account(key: [u8; 32]) -> ScVal {
        ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(key)),
        )))
    }

    fn hold_view(status: u32) -> Vec<(&'static str, ScVal)> {
        vec![
            ("agent", account([0xa9; 32])),
            ("amount", i128_val(100_000)),
            ("deadline", ScVal::U64(1_700_000_120)),
            ("fee_bps", ScVal::U32(50)),
            ("held_at", ScVal::U64(1_700_000_000)),
            ("request_hash", bytes32(&[0x33; 32])),
            ("service_id", bytes32(&[0x22; 32])),
            ("status", ScVal::U32(status)),
        ]
    }

    #[test]
    fn the_simulated_transaction_reads_from_the_zero_account() {
        let tx = invocation(&[7; 32], "get_hold", vec![bytes32(&[1; 32])]).unwrap();
        let b64 = tx.to_xdr_base64(Limits::none()).unwrap();
        let back = TransactionEnvelope::from_xdr_base64(&b64, Limits::none()).unwrap();
        assert_eq!(back, tx);
        let TransactionEnvelope::Tx(env) = tx else {
            panic!("not a v1 envelope")
        };
        assert_eq!(
            env.tx.source_account,
            MuxedAccount::Ed25519(Uint256([0; 32]))
        );
        assert!(env.signatures.is_empty());
        let [op] = env.tx.operations.as_slice() else {
            panic!("one operation")
        };
        let OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(call),
            auth,
        }) = &op.body
        else {
            panic!("not an invocation")
        };
        assert!(auth.is_empty());
        assert_eq!(
            call.contract_address,
            ScAddress::Contract(ContractId(Hash([7; 32])))
        );
        assert_eq!(call.function_name.0.to_utf8_string_lossy(), "get_hold");
        assert_eq!(call.args.as_slice(), &[bytes32(&[1; 32])]);
    }

    #[test]
    fn decodes_a_hold_view() {
        let h = decode_hold(&map(hold_view(STATUS_HELD))).unwrap();
        assert_eq!(h.agent, account_address(&[0xa9; 32]));
        assert!(h.agent.starts_with('G'));
        assert_eq!(
            (h.service_id, h.request_hash, h.amount),
            ([0x22; 32], [0x33; 32], 100_000)
        );
        assert_eq!(
            (h.held_at, h.deadline, h.fee_bps, h.status),
            (1_700_000_000, 1_700_000_120, 50, STATUS_HELD)
        );
        // never held
        assert_eq!(decode_hold(&ScVal::Void).unwrap(), HoldInfo::default());
    }

    fn session_view(status: u32) -> Vec<(&'static str, ScVal)> {
        vec![
            ("agent", account([0xa9; 32])),
            ("batch_size", ScVal::U32(8)),
            ("chain", bytes32(&[0x5a; 32])),
            ("deadline", ScVal::U64(1_700_086_520)),
            ("fee_bps", ScVal::U32(50)),
            ("max_calls", ScVal::U32(100)),
            ("opened_at", ScVal::U64(1_700_000_000)),
            ("payout", account([0xbe; 32])),
            ("predicate_hash", bytes32(&[0x44; 32])),
            ("price", i128_val(100_000)),
            ("sample_k", ScVal::U32(1)),
            ("seed", bytes32(&[0; 32])),
            ("service_id", bytes32(&[0x22; 32])),
            ("settled", ScVal::U32(3)),
            ("status", ScVal::U32(status)),
            ("ticket_key", bytes32(&[0x7c; 32])),
            (
                "token",
                ScVal::Address(ScAddress::Contract(ContractId(Hash([0x70; 32])))),
            ),
            ("verifier", bytes32(&[0x0b; 32])),
        ]
    }

    #[test]
    fn decodes_a_session() {
        let s = decode_session(&map(session_view(SESSION_OPEN))).unwrap();
        assert_eq!(s.agent, account_address(&[0xa9; 32]));
        assert_eq!(s.token, contract_address(&[0x70; 32]));
        assert_eq!(
            (s.service_id, s.chain, s.ticket_key, s.verifier),
            ([0x22; 32], [0x5a; 32], [0x7c; 32], [0x0b; 32])
        );
        assert_eq!(
            (s.max_calls, s.sample_k, s.batch_size, s.settled, s.status),
            (100, 1, 8, 3, SESSION_OPEN)
        );
        assert_eq!(
            (s.price, s.fee_bps, s.opened_at, s.deadline),
            (100_000, 50, 1_700_000_000, 1_700_086_520)
        );
        // never opened
        assert_eq!(
            decode_session(&ScVal::Void).unwrap(),
            SessionInfo::default()
        );
        // a missing field, an extra one, a wrong type, status 0
        let mut missing = session_view(1);
        missing.pop();
        assert!(decode_session(&map(missing)).is_err());
        let mut extra = session_view(1);
        extra.push(("zeta", ScVal::U32(0)));
        assert!(decode_session(&map(extra)).is_err());
        let mut wrong = session_view(1);
        wrong[13].1 = ScVal::U64(3);
        assert!(decode_session(&map(wrong)).is_err());
        assert!(decode_session(&map(session_view(0))).is_err());
    }

    #[test]
    fn rejects_malformed_hold_views() {
        // a missing field, an extra field, a wrong type, a short hash, status 0, not a map
        let mut missing = hold_view(1);
        missing.pop();
        assert!(decode_hold(&map(missing)).is_err());
        let mut extra = hold_view(1);
        extra.push(("zeta", ScVal::U32(0)));
        assert!(decode_hold(&map(extra)).is_err());
        let mut wrong = hold_view(1);
        wrong[3].1 = ScVal::U64(50);
        assert!(decode_hold(&map(wrong)).is_err());
        let mut short = hold_view(1);
        short[5].1 = ScVal::Bytes(ScBytes(vec![0x33; 31].try_into().unwrap()));
        assert!(decode_hold(&map(short)).is_err());
        assert!(decode_hold(&map(hold_view(0))).is_err());
        assert!(decode_hold(&ScVal::U32(1)).is_err());
    }

    #[test]
    fn decodes_a_service_and_contract_addresses() {
        let token = ScVal::Address(ScAddress::Contract(ContractId(Hash([0x20; 32]))));
        let service = map(vec![
            (
                "label",
                ScVal::Bytes(ScBytes(b"quote\0\0\0\0\0\0\0".to_vec().try_into().unwrap())),
            ),
            ("notary_key_hash", bytes32(&[0x66; 32])),
            ("origin_hash", bytes32(&[0x55; 32])),
            ("owner", account([0xbe; 32])),
            ("payout", account([0xbe; 32])),
            ("predicate_hash", bytes32(&[0x44; 32])),
            ("price_per_call", i128_val(100_000)),
            ("settlement_window", ScVal::U32(120)),
            ("token", token),
            ("verifier", bytes32(&[0x0b; 32])),
        ]);
        let s = decode_service(&service).unwrap();
        assert_eq!(&s.label[..5], b"quote");
        assert_eq!(s.token, contract_address(&[0x20; 32]));
        assert!(s.token.starts_with('C'));
        assert_eq!(
            (s.settlement_window, s.price_per_call, s.verifier),
            (120, 100_000, [0x0b; 32])
        );
        assert_eq!(
            (s.predicate_hash, s.origin_hash, s.notary_key_hash),
            ([0x44; 32], [0x55; 32], [0x66; 32])
        );
        assert_eq!(
            decode_service(&ScVal::Void).unwrap(),
            ServiceInfo::default()
        );
    }

    #[test]
    fn i128_parts_round_trip() {
        for x in [0, 1, -1, 100_000, i128::MAX / 10_000, i128::MAX, i128::MIN] {
            let v = i128_val(x);
            let f = HashMap::from([("x".to_string(), &v)]);
            assert_eq!(i128_field(&f, "x").unwrap(), x);
        }
    }
}
