//! `fermata-attest serve`: the attestor's HTTP API (for the gateway, Milestone 2).
//!
//!   GET  /healthz                     → { ok, network, escrow, signer, signerKey, notary, predicates }
//!   POST /v1/prove   ProveBody        → prove only; stores storage/presentations/<callId>.tlsn
//!   POST /v1/verify  { callId }       → verify the stored presentation → signed verdict
//!   POST /v1/attest  ProveBody        → prove, then verify → { prove, verdict, response }
//!   POST /v1/reverify { callId, serviceId?, predicateHash? } → offline re-check (no key, no chain)
//!   GET  /v1/presentations/<callId>   → the presentation bytes (for anyone to re-verify offline)
//!
//! Sessions (with `--session-contract`; `session.rs`, docs/session-escrow.md):
//!
//!   POST /v1/session/attest     SessionCallBody → check the ticket, prove, check → the call's entry
//!   POST /v1/session/unanswered SessionCallBody → check the ticket, record the call UNANSWERED
//!   POST /v1/session/statement  { sessionId, to } → the signed batch statement for settle_batch
//!   GET  /v1/session/<sessionId>               → the calls this attestor recorded
//!
//! Errors: 400 bad input; 422 { check, detail } when a binding check fails (no verdict);
//! 502 { error: "no-transcript" } when proving failed — never a verdict without a presentation.
//! For sessions also 409 { error: "out-of-order" } for a call that is not the next one, or a
//! statement over calls the book does not have; a session call that was admitted but not proved
//! (502 or 422) is recorded UNANSWERED. Proving is serialised: concurrent MPC sessions deadlock on
//! small machines.
//!
//! Copied from Fermata `apps/attestor/src/serve.rs` @ d7cc642 (github.com/bilgin-kocak/fermata,
//! Apache-2.0). The routes, the error codes and proving in a child process are unchanged. Changed:
//! the chain is the Soroban escrow, the verdict key is an Ed25519 key, `/healthz` names the network,
//! the escrow (`C…`) and the verifier (`G…`), and hex in JSON has no `0x` prefix.

use std::{
    collections::HashMap, convert::Infallible, net::SocketAddr, path::PathBuf, sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode, body::Bytes, service::service_fn};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::{Value, json};
use tlsn::webpki::CertificateDer;
use tokio::{net::TcpListener, sync::Mutex};
use tracing::{error, info};

use ed25519_dalek::SigningKey;
use fermata_verdict::{
    Domain,
    keys::{account_address, contract_address},
};

use crate::{
    chain::{ChainView, SorobanChain},
    config::PredicateStore,
    hashes::{Origin, hex0x, keccak256, parse_hex32, to_hex},
    session::{self, Books, CallRequest, Refusal, SessionTarget},
    verify::{self, Check, VerifyError},
};

pub struct State {
    pub chain: SorobanChain,
    pub roots: Vec<CertificateDer>,
    /// PEM files and Mozilla flag behind `roots` (passed to the per-attempt `prove` child).
    pub ca_paths: Vec<PathBuf>,
    pub mozilla_roots: bool,
    /// HTTP CONNECT proxy for vendors not pinned with `resolve` (passed to the `prove` child).
    pub upstream_proxy: Option<String>,
    pub notary: String,
    pub predicates: PredicateStore,
    /// The verdict key; its public half is the `verifier` the services pin.
    pub key: SigningKey,
    pub storage: PathBuf,
    /// `host:port` → address to dial (like curl --resolve).
    pub resolve: HashMap<String, String>,
    pub attempts: u32,
    pub attempt_timeout: Duration,
    pub max_sent: usize,
    pub max_recv: usize,
    pub prove_lock: Mutex<()>,
    /// The session contract, when sessions are enabled.
    pub session: Option<SessionTarget>,
    /// The calls of each session this attestor recorded.
    pub books: Books,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionCallBody {
    session_id: String,
    n: u32,
    /// The agent's ticket for call `n` (hex).
    ticket: String,
    url: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatementBody {
    session_id: String,
    to: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProveBody {
    call_id: String,
    /// Full upstream URL, e.g. https://vendor.fermata.test:8443/v1/quote?symbol=BTC-USD
    url: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body: String,
}

fn default_method() -> String {
    "GET".into()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyBody {
    call_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReverifyBody {
    call_id: String,
    service_id: Option<String>,
    /// Recompute the outcome with the predicate registered under this hash (content-addressed store).
    predicate_hash: Option<String>,
}

/// Splits `https://host[:port]/path?query` into the origin and the origin-form target.
pub fn split_url(url: &str) -> Result<(Origin, String)> {
    let rest = url
        .strip_prefix("https://")
        .context("upstream url must be https://")?;
    let (authority, target) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    Ok((Origin::parse(&format!("https://{authority}"))?, target))
}

impl State {
    fn presentation_path(&self, call_id: &[u8; 32]) -> PathBuf {
        self.storage.join(format!("{}.tlsn", hex0x(call_id)))
    }

    /// Proves one call. Each attempt runs `fermata-attest prove` as a fresh child process: in a
    /// long-lived process MPC setup stalls far more often (FACTS §15.2/§15.4), and killing a child
    /// also frees whatever a stalled session holds. The vendor is contacted only after setup.
    async fn prove(&self, body: &ProveBody) -> Result<(Value, [u8; 32]), (StatusCode, Value)> {
        let bad = |e: anyhow::Error| {
            (
                StatusCode::BAD_REQUEST,
                json!({ "error": format!("{e:#}") }),
            )
        };
        let call_id = parse_hex32(&body.call_id).map_err(bad)?;
        let (origin, _) = split_url(&body.url).map_err(bad)?;
        let authority = format!("{}:{}", origin.host, origin.port);
        tokio::fs::create_dir_all(&self.storage)
            .await
            .map_err(|e| internal(e.into()))?;
        let path = self.presentation_path(&call_id);
        let tmp = self.storage.join(format!(".{}.tmp", hex0x(&call_id)));
        let body_file = self.storage.join(format!(".{}.body", hex0x(&call_id)));
        tokio::fs::write(&body_file, body.body.as_bytes())
            .await
            .map_err(|e| internal(e.into()))?;
        let exe = std::env::current_exe().map_err(|e| internal(e.into()))?;

        let _guard = self.prove_lock.lock().await;
        let started = std::time::Instant::now();
        let mut last = String::from("no attempt made");
        let mut result = None;
        for attempt in 1..=self.attempts.max(1) {
            let mut cmd = tokio::process::Command::new(&exe);
            cmd.arg("prove").args(["--notary", &self.notary]);
            for ca in &self.ca_paths {
                cmd.arg("--ca").arg(ca);
            }
            if self.mozilla_roots {
                cmd.args(["--roots", "mozilla"]);
            }
            match &self.upstream_proxy {
                Some(proxy) => cmd.env("FERMATA_UPSTREAM_PROXY", proxy),
                None => cmd.env_remove("FERMATA_UPSTREAM_PROXY"),
            };
            cmd.args([
                "--url",
                &body.url,
                "--method",
                &body.method,
                "--call-id",
                &body.call_id,
            ])
            .arg("--body")
            .arg(format!("@{}", body_file.display()))
            .arg("--out")
            .arg(&tmp)
            .args(["--attempts", "1"])
            .args([
                "--attempt-timeout-secs",
                &self.attempt_timeout.as_secs().to_string(),
            ])
            .args([
                "--max-sent",
                &self.max_sent.to_string(),
                "--max-recv",
                &self.max_recv.to_string(),
            ])
            .env("RUST_LOG", "error")
            .env("RUST_BACKTRACE", "0")
            .env("RUST_LIB_BACKTRACE", "0")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
            if let Some(connect) = self.resolve.get(&authority) {
                cmd.arg("--resolve").arg(format!("{authority}={connect}"));
            }
            for (k, v) in &body.headers {
                cmd.arg("-H").arg(format!("{k}: {v}"));
            }
            let child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => return Err(internal(e.into())),
            };
            match tokio::time::timeout(
                self.attempt_timeout + Duration::from_secs(5),
                child.wait_with_output(),
            )
            .await
            {
                Ok(Ok(out)) if out.status.success() => {
                    match serde_json::from_slice::<Value>(&out.stdout) {
                        Ok(mut v) => {
                            v["attempts"] = json!(attempt);
                            v["proveMs"] = json!(started.elapsed().as_millis() as u64);
                            result = Some(v);
                            break;
                        }
                        Err(e) => last = format!("prove attempt {attempt}: unreadable output: {e}"),
                    }
                }
                Ok(Ok(out)) => {
                    let err = String::from_utf8_lossy(&out.stderr);
                    let line = err
                        .lines()
                        .find(|l| l.starts_with("Error:"))
                        .unwrap_or(err.trim());
                    last = format!(
                        "prove attempt {attempt}: {}",
                        line.trim_start_matches("Error: ")
                            .replace("prove attempt 1 ", "")
                            .replace("prove attempt 1: ", "")
                    );
                }
                Ok(Err(e)) => last = format!("prove attempt {attempt}: {e}"),
                Err(_) => {
                    last = format!(
                        "prove attempt {attempt}: no result after {:?}",
                        self.attempt_timeout
                    )
                }
            }
            tracing::warn!("callId {}: {last}", body.call_id);
        }
        let _ = tokio::fs::remove_file(&body_file).await;
        let Some(out) = result else {
            error!("callId {}: no transcript: {last}", body.call_id);
            return Err((
                StatusCode::BAD_GATEWAY,
                json!({ "error": "no-transcript", "detail": last }),
            ));
        };
        tokio::fs::rename(&tmp, &path)
            .await
            .map_err(|e| internal(e.into()))?;
        info!(
            "callId {}: proved in {} ms ({} attempt(s)) → {}",
            body.call_id,
            out["proveMs"],
            out["attempts"],
            path.display()
        );
        Ok((out, call_id))
    }

    async fn verify(&self, call_id: [u8; 32]) -> Result<Value, (StatusCode, Value)> {
        let bytes = tokio::fs::read(self.presentation_path(&call_id))
            .await
            .map_err(|_| {
                (
                    StatusCode::NOT_FOUND,
                    json!({ "error": "no presentation stored for this callId" }),
                )
            })?;
        let domain = Domain::new(&self.chain.network_passphrase, self.chain.escrow);
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        match verify::attest(
            &bytes,
            call_id,
            &self.roots,
            &self.chain,
            |h| self.predicates.get(h),
            &domain,
            &self.key,
            issued_at,
        )
        .await
        {
            Ok(signed) => Ok(json!({
                "presentationHash": to_hex(&keccak256(&bytes)),
                "verdict": signed,
                "response": proved_response(&bytes, &self.roots),
            })),
            Err(e) => match e.downcast_ref::<VerifyError>() {
                Some(v) => Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    json!({ "error": "binding-check-failed", "check": v.check, "detail": v.detail }),
                )),
                None => Err(internal(e)),
            },
        }
    }
}

/// The vendor's response exactly as proved (so a gateway returns the bytes the verdict is about):
/// status, headers and body (base64) when it parses as HTTP, plus the raw received bytes.
fn proved_response(presentation: &[u8], roots: &[CertificateDer]) -> Value {
    use base64::Engine as _;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    match verify::verify_presentation(presentation, roots) {
        Ok(call) => match &call.response {
            Ok(res) => json!({
                "status": res.status,
                "headers": res.headers,
                "bodyBase64": b64(&res.body),
                "rawBase64": b64(&call.received),
            }),
            Err(e) => json!({ "status": null, "error": e, "rawBase64": b64(&call.received) }),
        },
        Err(e) => json!({ "status": null, "error": e.to_string() }),
    }
}

impl State {
    /// Offline re-verification of a stored presentation (no chain, no key), for anyone re-checking a
    /// verdict: recomputed hashes, transcript, outcome.
    async fn reverify(&self, body: &ReverifyBody) -> Result<Value, (StatusCode, Value)> {
        let bad = |e: anyhow::Error| {
            (
                StatusCode::BAD_REQUEST,
                json!({ "error": format!("{e:#}") }),
            )
        };
        let call_id = parse_hex32(&body.call_id).map_err(bad)?;
        let service_id = body
            .service_id
            .as_deref()
            .map(parse_hex32)
            .transpose()
            .map_err(bad)?;
        let predicate = match &body.predicate_hash {
            Some(h) => Some(
                self.predicates
                    .get(&parse_hex32(h).map_err(bad)?)
                    .ok_or_else(|| {
                        (
                            StatusCode::NOT_FOUND,
                            json!({ "error": format!("no predicate for {h}") }),
                        )
                    })?,
            ),
            None => None,
        };
        let bytes = tokio::fs::read(self.presentation_path(&call_id))
            .await
            .map_err(|_| {
                (
                    StatusCode::NOT_FOUND,
                    json!({ "error": "no presentation stored for this callId" }),
                )
            })?;
        verify::reverify(
            &bytes,
            &self.roots,
            call_id,
            service_id,
            predicate.as_deref(),
        )
        .map_err(|v| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({ "error": "presentation-invalid", "check": v.check, "detail": v.detail }),
            )
        })
    }
}

impl State {
    fn sessions(&self) -> Result<&SessionTarget, (StatusCode, Value)> {
        self.session.as_ref().ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                json!({ "error": "sessions are not enabled (start with --session-contract)" }),
            )
        })
    }

    /// Parses a session call and runs the checks before proving (`session::admit`).
    async fn admit(
        &self,
        body: &SessionCallBody,
        for_proving: bool,
    ) -> Result<session::Admitted, (StatusCode, Value)> {
        let bad = |e: anyhow::Error| {
            (
                StatusCode::BAD_REQUEST,
                json!({ "error": format!("{e:#}") }),
            )
        };
        let target = self.sessions()?;
        parse_hex32(&body.session_id).map_err(bad)?;
        fermata_verdict::parse_hex::<64>(&body.ticket).map_err(|e| bad(anyhow!("ticket: {e}")))?;
        let (_, request_target) = split_url(&body.url).map_err(bad)?;
        let req = CallRequest {
            session_id: body.session_id.clone(),
            n: body.n,
            ticket: body.ticket.clone(),
            method: body.method.clone(),
            target: request_target,
            body: body.body.as_bytes().to_vec(),
        };
        let verifier = self.key.verifying_key().to_bytes();
        let admitted = session::admit(
            &self.chain,
            target,
            &verifier,
            &self.books,
            &req,
            for_proving,
        )
        .await
        .map_err(refusal)?;
        match self
            .books
            .reserve(&admitted.session_id, &admitted.session, admitted.record())
            .await
        {
            Ok(Ok(())) => Ok(admitted),
            Ok(Err(e)) => Err(refusal(Refusal::Book(e))),
            Err(e) => Err(internal(e)),
        }
    }

    /// Records an admitted call's result and answers with it.
    async fn record(
        &self,
        a: &session::Admitted,
        entry: fermata_verdict::session::Entry,
    ) -> Result<Value, (StatusCode, Value)> {
        let r = self
            .books
            .complete(&a.session_id, a.n, entry)
            .await
            .map_err(internal)?;
        Ok(json!({
            "sessionId": to_hex(&a.session_id),
            "n": r.n,
            "callId": to_hex(&r.call_id),
            "requestHash": to_hex(&r.request_hash),
            "chain": to_hex(&r.chain),
            "entry": r.entry,
        }))
    }

    /// Proves a session call and records its entry; a call that is not proved is UNANSWERED.
    async fn session_attest(&self, body: &SessionCallBody) -> Result<Value, (StatusCode, Value)> {
        let a = self.admit(body, true).await?;
        let admitted = &a;
        let unanswered = |status: StatusCode, mut detail: Value| async move {
            let recorded = self
                .record(admitted, fermata_verdict::session::Entry::unanswered())
                .await?;
            detail["recorded"] = recorded;
            Err::<Value, _>((status, detail))
        };
        let prove_body = ProveBody {
            call_id: to_hex(&a.call_id),
            url: body.url.clone(),
            method: body.method.clone(),
            headers: body.headers.clone(),
            body: body.body.clone(),
        };
        let (out, _) = match self.prove(&prove_body).await {
            Ok(proved) => proved,
            Err((status, detail)) => return unanswered(status, detail).await,
        };
        let bytes = match tokio::fs::read(self.presentation_path(&a.call_id)).await {
            Ok(b) => b,
            Err(e) => {
                return unanswered(
                    internal(e.into()).0,
                    json!({ "error": "presentation lost" }),
                )
                .await;
            }
        };
        let checked = async {
            let v = verify::verify_presentation(&bytes, &self.roots)?;
            let predicate = self
                .predicates
                .get(&a.session.predicate_hash)
                .ok_or_else(|| VerifyError {
                    check: Check::Predicate,
                    detail: format!(
                        "no predicate on file for predicateHash {}",
                        to_hex(&a.session.predicate_hash)
                    ),
                })?;
            let now = self
                .chain
                .latest_timestamp()
                .await
                .map_err(|e| VerifyError {
                    check: Check::Session,
                    detail: format!("chain time: {e:#}"),
                })?;
            session::decide_call(&v, &a, &predicate, now)
        };
        let (entry, failures) = match checked.await {
            Ok(decided) => decided,
            Err(v) => {
                return unanswered(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    json!({ "error": "binding-check-failed", "check": v.check, "detail": v.detail }),
                )
                .await;
            }
        };
        let mut recorded = self.record(&a, entry).await?;
        recorded["outcome"] = json!(verify::outcome_name(
            if entry.result == fermata_verdict::session::RESULT_DELIVERED {
                fermata_verdict::OUTCOME_DELIVERED
            } else {
                fermata_verdict::OUTCOME_FAILED
            }
        ));
        recorded["failures"] = json!(failures);
        recorded["presentationHash"] = json!(to_hex(&keccak256(&bytes)));
        recorded["response"] = proved_response(&bytes, &self.roots);
        recorded["prove"] = out;
        Ok(recorded)
    }

    async fn session_unanswered(
        &self,
        body: &SessionCallBody,
    ) -> Result<Value, (StatusCode, Value)> {
        let a = self.admit(body, false).await?;
        self.record(&a, fermata_verdict::session::Entry::unanswered())
            .await
    }

    async fn session_statement(&self, body: &StatementBody) -> Result<Value, (StatusCode, Value)> {
        let target = self.sessions()?;
        let session_id = parse_hex32(&body.session_id).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                json!({ "error": format!("{e:#}") }),
            )
        })?;
        let signed = session::sign_statement(
            &self.chain,
            target,
            &self.key,
            &self.books,
            session_id,
            body.to,
        )
        .await
        .map_err(refusal)?;
        serde_json::to_value(signed).map_err(|e| internal(e.into()))
    }

    async fn session_calls(&self, id: &str) -> Result<Value, (StatusCode, Value)> {
        self.sessions()?;
        let session_id = parse_hex32(id).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                json!({ "error": format!("{e:#}") }),
            )
        })?;
        let calls = self.books.calls(&session_id).await.map_err(internal)?;
        Ok(json!({ "sessionId": to_hex(&session_id), "calls": calls }))
    }
}

fn refusal(r: Refusal) -> (StatusCode, Value) {
    match r {
        Refusal::Check(v) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            json!({ "error": "binding-check-failed", "check": v.check, "detail": v.detail }),
        ),
        Refusal::Book(b) => (
            StatusCode::CONFLICT,
            json!({ "error": "out-of-order", "detail": b.0 }),
        ),
        Refusal::Other(e) => internal(e),
    }
}

fn internal(e: anyhow::Error) -> (StatusCode, Value) {
    error!("{e:#}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({ "error": format!("{e:#}") }),
    )
}

fn reply(status: StatusCode, body: Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
        .unwrap()
}

async fn parse<T: for<'de> Deserialize<'de>>(
    req: Request<hyper::body::Incoming>,
) -> Result<T, (StatusCode, Value)> {
    let bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|e| internal(e.into()))?
        .to_bytes();
    serde_json::from_slice(&bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            json!({ "error": format!("bad JSON body: {e}") }),
        )
    })
}

async fn route(
    state: Arc<State>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path().to_string();
    let result: Result<Value, (StatusCode, Value)> = match (req.method().clone(), path.as_str()) {
        (Method::GET, "/healthz") => {
            let signer = state.key.verifying_key().to_bytes();
            Ok(json!({
                "ok": true,
                "network": state.chain.network_passphrase,
                "escrow": contract_address(&state.chain.escrow),
                "sessionContract": state.session.as_ref().map(|t| contract_address(&t.contract)),
                "signer": account_address(&signer),
                "signerKey": to_hex(&signer),
                "notary": state.notary,
                "predicates": state.predicates.len(),
            }))
        }
        (Method::POST, "/v1/session/attest") => match parse::<SessionCallBody>(req).await {
            Ok(body) => state.session_attest(&body).await,
            Err(e) => Err(e),
        },
        (Method::POST, "/v1/session/unanswered") => match parse::<SessionCallBody>(req).await {
            Ok(body) => state.session_unanswered(&body).await,
            Err(e) => Err(e),
        },
        (Method::POST, "/v1/session/statement") => match parse::<StatementBody>(req).await {
            Ok(body) => state.session_statement(&body).await,
            Err(e) => Err(e),
        },
        (Method::GET, p) if p.starts_with("/v1/session/") => {
            state
                .session_calls(p.trim_start_matches("/v1/session/"))
                .await
        }
        (Method::POST, "/v1/prove") => match parse::<ProveBody>(req).await {
            Ok(body) => state.prove(&body).await.map(|(out, call_id)| {
                json!({ "presentationHash": out["presentationHash"], "prove": out, "callId": to_hex(&call_id) })
            }),
            Err(e) => Err(e),
        },
        (Method::POST, "/v1/verify") => match parse::<VerifyBody>(req).await {
            Ok(body) => match parse_hex32(&body.call_id) {
                Ok(call_id) => state.verify(call_id).await,
                Err(e) => Err((StatusCode::BAD_REQUEST, json!({ "error": format!("{e:#}") }))),
            },
            Err(e) => Err(e),
        },
        (Method::POST, "/v1/reverify") => match parse::<ReverifyBody>(req).await {
            Ok(body) => state.reverify(&body).await,
            Err(e) => Err(e),
        },
        (Method::POST, "/v1/attest") => match parse::<ProveBody>(req).await {
            Ok(body) => match state.prove(&body).await {
                Ok((out, call_id)) => state.verify(call_id).await.map(|mut v| {
                    v["prove"] = out;
                    v
                }),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        (Method::GET, p) if p.starts_with("/v1/presentations/") => {
            let id = p.trim_start_matches("/v1/presentations/").trim_end_matches(".tlsn");
            return Ok(match parse_hex32(id) {
                Ok(call_id) => match tokio::fs::read(state.presentation_path(&call_id)).await {
                    Ok(bytes) => Response::builder()
                        .header("content-type", "application/octet-stream")
                        .body(Full::new(Bytes::from(bytes)))
                        .unwrap(),
                    Err(_) => reply(StatusCode::NOT_FOUND, json!({ "error": "not found" })),
                },
                Err(e) => reply(StatusCode::BAD_REQUEST, json!({ "error": format!("{e:#}") })),
            });
        }
        _ => Err((StatusCode::NOT_FOUND, json!({ "error": "not found" }))),
    };
    Ok(match result {
        Ok(v) => reply(StatusCode::OK, v),
        Err((status, v)) => reply(status, v),
    })
}

pub async fn run(addr: SocketAddr, state: State) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    info!("attestor listening on http://{addr}");
    let state = Arc::new(state);
    loop {
        let (socket, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| route(state.clone(), req));
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(socket), service)
                .await
            {
                error!("connection error: {e}");
            }
        });
    }
    #[allow(unreachable_code)]
    Err(anyhow!("listener closed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_urls() {
        let (o, t) = split_url("https://Vendor.Fermata.Test:8443/v1/quote?symbol=BTC-USD").unwrap();
        assert_eq!(
            (o.canonical().as_str(), t.as_str()),
            (
                "https://vendor.fermata.test:8443",
                "/v1/quote?symbol=BTC-USD"
            )
        );
        let (o, t) = split_url("https://api.example.com?x=1").unwrap();
        assert_eq!((o.port, t.as_str()), (443, "/?x=1"));
        assert_eq!(split_url("https://a.b").unwrap().1, "/");
        assert!(split_url("http://a.b/").is_err());
    }
}
