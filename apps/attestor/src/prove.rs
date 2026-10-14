//! Prover: one MPC-TLS session to the vendor through our notary, producing a presentation.
//!
//! Ported from the Milestone S spike (itself from WebProof `notarize.rs`/`present.rs`, Apache-2.0,
//! and the upstream `attestation` example at tlsn v0.1.0-alpha.15). Fermata specifics:
//! * the request carries `Host` (from the origin) and `X-Fermata-Call: <callId>`;
//! * commitments are raw byte ranges (no tlsn-formats), so a malformed response is still provable;
//! * disclosure: everything is revealed except the *values* of `Authorization`, `Cookie` and
//!   `Proxy-Authorization` (only hash commitments exist at this tag, and a revealed range must be
//!   covered by committed ranges, so the sent transcript is committed in pieces around them);
//! * attestations are signed with SECP256K1ETH;
//! * each attempt has a timeout (an MPC session occasionally deadlocks) and is retried.
//!
//! Copied from Fermata `apps/attestor/src/prove.rs` @ d7cc642
//! (github.com/bilgin-kocak/fermata, Apache-2.0). Two changes: the `User-Agent`
//! names this repository, and the JSON output gives hex without the `0x` prefix (the Stellar CLI's
//! form). The `X-Fermata-Call` header keeps its `0x` form.

use std::{future::IntoFuture, ops::Range, time::Duration, time::Instant};

use anyhow::{Context, Result, anyhow, bail};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::net::TcpStream;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{info, warn};

use tlsn::{
    Session,
    attestation::{
        Attestation, CryptoProvider,
        presentation::Presentation,
        request::{Request as AttestationRequest, RequestConfig},
        signing::SignatureAlgId,
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig,
    },
    connection::{HandshakeData, ServerName},
    prover::ProverOutput,
    transcript::TranscriptCommitConfig,
    webpki::{CertificateDer, RootCertStore},
};

use crate::hashes::{Origin, hex0x, to_hex};

/// Request headers whose values are never revealed in a presentation.
pub const REDACTED_HEADERS: [&str; 3] = ["authorization", "cookie", "proxy-authorization"];
/// Headers the prover sets itself; caller-supplied copies are dropped.
const RESERVED_HEADERS: [&str; 6] = [
    "host",
    "x-fermata-call",
    "connection",
    "content-length",
    "accept-encoding",
    "user-agent",
];

/// Sent on every proved request (some APIs refuse requests without one). The gateway's onboarding
/// check sends the same, so an API that passes the check answers the prover the same way.
pub const USER_AGENT: &str =
    "fermata-attest/0.1 (+https://github.com/bilgin-kocak/fermata-stellar)";

#[derive(Clone, Debug)]
pub struct ProveRequest {
    /// Notary TCP address, `host:port`.
    pub notary: String,
    /// Vendor TCP address to dial, `host:port` (lets `vendor.fermata.test` resolve to 127.0.0.1).
    pub connect: String,
    /// Registered origin; gives the TLS server name and the `Host` header.
    pub origin: Origin,
    /// Trust roots for the vendor's certificate.
    pub roots: Vec<CertificateDer>,
    pub method: String,
    /// Origin-form request target, e.g. `/v1/quote?symbol=BTC-USD`.
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub call_id: [u8; 32],
    pub max_sent: usize,
    pub max_recv: usize,
    /// Headers whose values stay hidden; `REDACTED_HEADERS` in production. (The verifier rejects any
    /// hiding outside `REDACTED_HEADERS`; tests use this to prove that.)
    pub redact: Vec<String>,
    /// Bound on MPC setup (healthy: < 1 s here).
    pub setup_timeout: Duration,
    /// Reach the vendor through this HTTP CONNECT proxy (the notary connection never is).
    pub proxy: Option<crate::tunnel::Proxy>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProveOutput {
    #[serde(skip)]
    pub presentation: Vec<u8>,
    /// HTTP status as the prover's client saw it (None if the response head never arrived).
    pub status: Option<u16>,
    pub len_sent: usize,
    pub len_received: usize,
    pub redacted_ranges: Vec<(usize, usize)>,
    pub notary_key: String,
    /// MPC-TLS traffic between prover and notary for this session.
    pub notary_bytes: NotaryBytes,
    pub presentation_bytes: usize,
    pub attempts: u32,
    /// Wall-clock time including failed attempts.
    pub prove_ms: u128,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct NotaryBytes {
    pub sent: u64,
    pub received: u64,
}

/// Runs `prove_once` up to `attempts` times, each bounded by `timeout`. Every failure means there
/// is no transcript, and therefore no verdict: the hold can only end by timeout.
pub async fn prove(req: &ProveRequest, attempts: u32, timeout: Duration) -> Result<ProveOutput> {
    let mut last = anyhow!("no attempt made");
    let t0 = Instant::now();
    for attempt in 1..=attempts.max(1) {
        match tokio::time::timeout(timeout, prove_once(req)).await {
            Ok(Ok(mut out)) => {
                out.attempts = attempt;
                out.prove_ms = t0.elapsed().as_millis();
                return Ok(out);
            }
            Ok(Err(e)) => last = e.context(format!("prove attempt {attempt}")),
            Err(_) => last = anyhow!("prove attempt {attempt} timed out after {timeout:?}"),
        }
        warn!("{last:#}");
    }
    Err(last)
}

pub fn default_redactions() -> Vec<String> {
    REDACTED_HEADERS.iter().map(|h| h.to_string()).collect()
}

/// Byte ranges of the values of the `names` headers in a raw HTTP request head.
pub fn redaction_ranges(sent: &[u8], names: &[impl AsRef<str>]) -> Result<Vec<Range<usize>>> {
    let mut hdrs = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut hdrs);
    req.parse(sent)
        .context("sent transcript is not an HTTP request")?;
    let base = sent.as_ptr() as usize;
    let mut out = Vec::new();
    for h in req.headers.iter() {
        if names
            .iter()
            .any(|n| h.name.eq_ignore_ascii_case(n.as_ref()))
            && !h.value.is_empty()
        {
            let start = h.value.as_ptr() as usize - base;
            out.push(start..start + h.value.len());
        }
    }
    out.sort_by_key(|r| r.start);
    Ok(out)
}

/// `0..len` minus `holes` (sorted, non-overlapping).
pub fn complement(len: usize, holes: &[Range<usize>]) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut at = 0;
    for h in holes {
        if h.start > at {
            out.push(at..h.start);
        }
        at = at.max(h.end);
    }
    if at < len {
        out.push(at..len);
    }
    out
}

/// Counts the bytes a socket reads and writes (the MPC traffic between prover and notary).
struct Counting<T> {
    inner: T,
    read: std::sync::Arc<std::sync::atomic::AtomicU64>,
    written: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Counting<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = (buf.filled().len() - before) as u64;
        self.read.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        r
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Counting<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let r = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &r {
            self.written
                .fetch_add(*n as u64, std::sync::atomic::Ordering::Relaxed);
        }
        r
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Aborts a spawned task when dropped, so a timed-out attempt stops its MPC work instead of
/// competing with the retry for CPU.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn prove_once(req: &ProveRequest) -> Result<ProveOutput> {
    let server_name = ServerName::Dns(req.origin.host.as_str().try_into()?);

    let notary_socket = TcpStream::connect(&req.notary)
        .await
        .with_context(|| format!("connecting to notary {}", req.notary))?;
    notary_socket.set_nodelay(true)?;
    let (bytes_read, bytes_written) = (std::sync::Arc::default(), std::sync::Arc::default());
    let counted = Counting {
        inner: notary_socket,
        read: std::sync::Arc::clone(&bytes_read),
        written: std::sync::Arc::clone(&bytes_written),
    };
    let (driver, mut handle) = Session::new(counted.compat()).split();
    let mut driver_task = AbortOnDrop(tokio::spawn(driver));

    let tls_config = TlsClientConfig::builder()
        .server_name(server_name.clone())
        .root_store(RootCertStore {
            roots: req.roots.clone(),
        })
        .build()?;
    // MPC setup occasionally stalls (≈ 5 % of sessions on a 4-vCPU box, inside tlsn/mpz). It happens
    // before the vendor is contacted, so the caller can retry without side effects; a separate,
    // shorter bound keeps the cost of a stall low.
    let setup = handle.new_prover(ProverConfig::builder().build()?)?.commit(
        MpcTlsConfig::builder()
            .max_sent_data(req.max_sent)
            .max_recv_data(req.max_recv)
            .build()?,
    );
    let prover = tokio::time::timeout(req.setup_timeout, setup)
        .await
        .map_err(|_| {
            anyhow!(
                "MPC setup stalled for {:?} (vendor not contacted)",
                req.setup_timeout
            )
        })??;
    let server_socket = match &req.proxy {
        Some(proxy) => crate::tunnel::connect(proxy, &req.connect).await?,
        None => TcpStream::connect(&req.connect)
            .await
            .with_context(|| format!("connecting to vendor {}", req.connect))?,
    };
    server_socket.set_nodelay(true)?;
    let (tls_connection, prover) = prover.connect(tls_config, server_socket.compat())?;
    let mut prover_task = AbortOnDrop(tokio::spawn(prover.into_future()));

    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat())).await?;
    let _connection = AbortOnDrop(tokio::spawn(connection));

    let mut builder = Request::builder()
        .method(req.method.to_ascii_uppercase().as_str())
        .uri(&req.target)
        .header("host", req.origin.host_header())
        .header("x-fermata-call", hex0x(&req.call_id))
        .header("accept-encoding", "identity")
        .header("user-agent", USER_AGENT)
        .header("connection", "close");
    for (k, v) in &req.headers {
        if !RESERVED_HEADERS.iter().any(|r| k.eq_ignore_ascii_case(r)) {
            builder = builder.header(k.as_str(), v.as_str());
        }
    }
    let response = sender
        .send_request(builder.body(Full::new(Bytes::from(req.body.clone())))?)
        .await;
    let status = match response {
        Ok(response) => {
            let status = response.status().as_u16();
            // A body read error (server cut the connection) is fine: the bytes that did arrive
            // are in the transcript and the predicate judges them.
            if let Err(e) = response.into_body().collect().await {
                warn!("response body read error: {e}");
            }
            Some(status)
        }
        Err(e) => {
            warn!("no parseable response head: {e}");
            None
        }
    };

    let mut prover = (&mut prover_task.0).await??;
    let len_sent = prover.transcript().sent().len();
    let len_recv = prover.transcript().received().len();
    if len_recv == 0 {
        bail!("vendor sent no application data: nothing to prove");
    }
    let holes = redaction_ranges(prover.transcript().sent(), &req.redact)?;
    let sent_pieces = complement(len_sent, &holes);

    let mut builder = TranscriptCommitConfig::builder(prover.transcript());
    for r in &sent_pieces {
        builder.commit_sent(r.clone())?;
    }
    builder.commit_recv(0..len_recv)?;
    let transcript_commit = builder.build()?;

    let mut builder = RequestConfig::builder();
    builder.signature_alg(SignatureAlgId::SECP256K1ETH);
    builder.transcript_commit(transcript_commit);
    let request_config = builder.build()?;

    let mut builder = ProveConfig::builder(prover.transcript());
    if let Some(config) = request_config.transcript_commit() {
        builder.transcript_commit(config.clone());
    }
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&builder.build()?).await?;

    let transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    let mut builder = AttestationRequest::builder(&request_config);
    builder
        .server_name(server_name)
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .context("server cert chain")?
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .context("server signature")?
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);
    let (attestation_request, secrets) = builder.build(&CryptoProvider::default())?;

    handle.close();
    let mut socket = (&mut driver_task.0).await??;
    socket
        .write_all(&bincode::serialize(&attestation_request)?)
        .await?;
    socket.close().await?;
    let mut attestation_bytes = Vec::new();
    socket.read_to_end(&mut attestation_bytes).await?;
    let attestation: Attestation =
        bincode::deserialize(&attestation_bytes).context("notary returned no attestation")?;
    attestation_request.validate(&attestation, &CryptoProvider::default())?;

    let mut builder = secrets.transcript_proof_builder();
    for r in &sent_pieces {
        builder.reveal_sent(r.clone())?;
    }
    builder.reveal_recv(0..len_recv)?;
    let transcript_proof = builder.build()?;
    let provider = CryptoProvider::default();
    let mut builder = attestation.presentation_builder(&provider);
    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    let presentation: Presentation = builder.build()?;
    let bytes = bincode::serialize(&presentation)?;
    info!(
        "presentation {} bytes (sent {len_sent}, received {len_recv}, {} redacted ranges)",
        bytes.len(),
        holes.len()
    );

    Ok(ProveOutput {
        presentation_bytes: bytes.len(),
        presentation: bytes,
        status,
        len_sent,
        len_received: len_recv,
        redacted_ranges: holes.iter().map(|r| (r.start, r.end)).collect(),
        notary_key: to_hex(&attestation.body.verifying_key().data),
        notary_bytes: NotaryBytes {
            sent: bytes_written.load(std::sync::atomic::Ordering::Relaxed),
            received: bytes_read.load(std::sync::atomic::Ordering::Relaxed),
        },
        attempts: 1,
        prove_ms: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_auth_values_and_complement() {
        let req = b"GET /v1/quote HTTP/1.1\r\nhost: v.test\r\nAuthorization: Bearer abc\r\ncookie: a=1\r\nx: y\r\n\r\n";
        let holes = redaction_ranges(req, &default_redactions()).unwrap();
        assert_eq!(
            holes.iter().map(|r| &req[r.clone()]).collect::<Vec<_>>(),
            vec![&b"Bearer abc"[..], &b"a=1"[..]]
        );
        let pieces = complement(req.len(), &holes);
        let joined: Vec<u8> = pieces
            .iter()
            .flat_map(|r| req[r.clone()].to_vec())
            .collect();
        assert_eq!(joined.len() + 10 + 3, req.len());
        assert_eq!(complement(5, &[]), vec![0..5]);
        let everything = vec![Range { start: 0, end: 5 }];
        assert_eq!(complement(5, &everything), Vec::<Range<usize>>::new());
    }
}
