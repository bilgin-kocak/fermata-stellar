//! Notary: a stand-alone TLSNotary notary over plain TCP, one MPC session per connection.
//!
//! tlsn v0.1.0-alpha.15 ships no notary server, so this wraps the upstream `attestation`
//! example's `notary()` (the same logic WebProof uses, Apache-2.0) behind a `TcpListener`, as the
//! Milestone S spike did. Attestations are signed with SECP256K1ETH. The notary is blind: it never
//! sees plaintext, only commitments.
//!
//! Copied unchanged from Fermata `apps/attestor/src/notary.rs` @ d7cc642
//! (github.com/bilgin-kocak/fermata, Apache-2.0).

use std::time::Duration;

use anyhow::{Result, anyhow};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{error, info};

use tlsn::{
    Session,
    attestation::{
        Attestation, AttestationConfig, CryptoProvider, request::Request as AttestationRequest,
    },
    config::verifier::VerifierConfig,
    connection::{CertBinding, ConnectionInfo, TranscriptLength},
    transcript::ContentType,
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::{CertificateDer, RootCertStore},
};

/// The notary's verifying key: compressed SEC1 (33 bytes). `notaryKeyHash` is its keccak256.
pub fn public_key(key: &[u8; 32]) -> Result<Vec<u8>> {
    Ok(k256::ecdsa::SigningKey::from_slice(key)?
        .verifying_key()
        .to_sec1_bytes()
        .to_vec())
}

/// Accepts sessions forever. `roots` must include the CA of every vendor it will notarize.
pub async fn run(
    listener: TcpListener,
    roots: Vec<CertificateDer>,
    key: [u8; 32],
    timeout: Duration,
) -> Result<()> {
    loop {
        let (socket, peer) = listener.accept().await?;
        socket.set_nodelay(true)?;
        let roots = roots.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(timeout, session(socket, roots, key)).await {
                Ok(Ok(())) => info!("notary session {peer}: attestation issued"),
                Ok(Err(e)) => error!("notary session {peer} failed: {e:#}"),
                Err(_) => error!("notary session {peer}: timed out after {timeout:?}"),
            }
        });
    }
}

async fn session(socket: TcpStream, roots: Vec<CertificateDer>, key: [u8; 32]) -> Result<()> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore { roots })
        .build()?;

    let verifier = match handle.new_verifier(verifier_config)?.commit().await? {
        VerifierCommitStart::Mpc(verifier) => verifier.accept().await?.run().await?,
        VerifierCommitStart::Proxy(verifier) => {
            verifier
                .reject(Some("this notary only runs MPC sessions"))
                .await?;
            return Err(anyhow!("proxy-mode session rejected"));
        }
    };

    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;

    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    let count = |records: &[tlsn::transcript::Record]| -> usize {
        records
            .iter()
            .filter_map(|r| match r.typ {
                ContentType::ApplicationData => Some(r.ciphertext.len()),
                _ => None,
            })
            .sum()
    };
    let sent_len = count(tls_transcript.sent());
    let recv_len = count(tls_transcript.recv());

    handle.close();
    let mut socket = driver_task.await??;

    let mut request_bytes = Vec::new();
    socket.read_to_end(&mut request_bytes).await?;
    let request: AttestationRequest = bincode::deserialize(&request_bytes)?;

    let mut provider = CryptoProvider::default();
    provider.signer.set_secp256k1eth(&key)?;

    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    let att_config = att_config_builder.build()?;

    let CertBinding::V1_2(binding) = tls_transcript.certificate_binding() else {
        return Err(anyhow!("unsupported cert binding version"));
    };
    let mut builder = Attestation::builder(&att_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(binding.server_ephemeral_key.clone())
        .transcript_commitments(transcript_commitments);
    let attestation = builder.build(&provider)?;

    socket.write_all(&bincode::serialize(&attestation)?).await?;
    socket.close().await?;
    Ok(())
}
