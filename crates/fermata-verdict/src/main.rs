//! `fermata-verdict`: signs and checks Fermata verdicts for Stellar and computes the hashes a
//! service registers.
//!
//! The verifier's secret is read only from the `FERMATA_VERIFIER_SECRET` environment variable (a
//! Stellar secret seed `S…`, as `stellar keys secret` prints it, or 64 hex characters), never from
//! a flag, so it stays out of shell history and process listings.

use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use fermata_verdict::{
    hashes, keys, parse_hex,
    service::{self, Owner},
    to_hex, vectors,
    verdict::{self, Domain, Verdict},
    OUTCOME_DELIVERED, OUTCOME_FAILED,
};
use serde::Serialize;

const SECRET_ENV: &str = "FERMATA_VERIFIER_SECRET";

#[derive(Parser)]
#[command(
    name = "fermata-verdict",
    version,
    about = "Sign and check Fermata verdicts for Stellar; compute service ids and registration hashes"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the verifier's public key (hex and G… address) from FERMATA_VERIFIER_SECRET.
    Pubkey,
    /// Print the 294-byte message a verifier signs for a verdict, as hex. Needs no key.
    Message(MessageArgs),
    /// Sign a verdict with FERMATA_VERIFIER_SECRET and print JSON: verdict, message, signature.
    Sign(MessageArgs),
    /// Check a signature over a verdict as the escrow does (strict Ed25519). Fails if invalid.
    Verify {
        #[command(flatten)]
        message: MessageArgs,
        /// The verifier's public key: G… address or 64 hex characters.
        #[arg(long)]
        public_key: String,
        /// 64-byte signature, hex.
        #[arg(long)]
        signature: String,
    },
    /// Derive a service id from its owner (G… or C…) and label (up to 12 ASCII bytes, or 0x + 24 hex).
    ServiceId {
        #[arg(long)]
        owner: String,
        #[arg(long)]
        label: String,
    },
    /// requestHash = sha256(serviceId ‖ METHOD ‖ request-target ‖ sha256(body)).
    RequestHash {
        #[arg(long)]
        service_id: String,
        #[arg(long)]
        method: String,
        /// The request target as sent, e.g. /v1/quote?symbol=BTC-USD.
        #[arg(long)]
        target: String,
        /// Request body text, or @path to read the body from a file.
        #[arg(long, default_value = "")]
        body: String,
    },
    /// predicateHash = sha256(the predicate file's bytes, exactly as registered).
    PredicateHash { file: PathBuf },
    /// originHash = keccak256(canonical https origin), e.g. https://vendor.example:8443.
    OriginHash { origin: String },
    /// notaryKeyHash = keccak256(33-byte compressed SEC1 notary key, given as hex).
    NotaryKeyHash { key: String },
    /// Print the golden vectors (the content of test-vectors/verdict-v1.json).
    Vectors,
}

#[derive(Args)]
struct MessageArgs {
    /// Network passphrase, e.g. "Test SDF Network ; September 2015".
    #[arg(long)]
    network_passphrase: String,
    /// The escrow contract: C… address or its 32-byte id in hex.
    #[arg(long)]
    contract: String,
    #[command(flatten)]
    verdict: VerdictArgs,
}

#[derive(Args)]
struct VerdictArgs {
    #[arg(long)]
    call_id: String,
    #[arg(long)]
    service_id: String,
    #[arg(long)]
    request_hash: String,
    #[arg(long)]
    predicate_hash: String,
    /// delivered | failed (or 1 | 2).
    #[arg(long)]
    outcome: String,
    #[arg(long)]
    presentation_hash: String,
    #[arg(long)]
    response_hash: String,
    /// Unix seconds; defaults to the current time.
    #[arg(long)]
    issued_at: Option<u64>,
}

/// What `sign` prints. `verdict` is in the JSON form `stellar contract invoke` takes for the
/// escrow's `Verdict` argument.
#[derive(Serialize)]
struct Signed {
    verdict: Verdict,
    network_passphrase: String,
    network_id: String,
    contract: String,
    message: String,
    signature: String,
    public_key: String,
    signer: String,
}

#[derive(Serialize)]
struct PublicKey {
    public_key: String,
    address: String,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Pubkey => {
            let key = signing_key_from_env()?;
            let public_key = key.verifying_key().to_bytes();
            print_json(&PublicKey {
                public_key: to_hex(&public_key),
                address: keys::account_address(&public_key),
            })
        }
        Command::Message(args) => {
            let (domain, verdict) = args.parse()?;
            println!("{}", to_hex(&verdict::message(&domain, &verdict)));
            Ok(())
        }
        Command::Sign(args) => {
            let key = signing_key_from_env()?;
            let (domain, verdict) = args.parse()?;
            let public_key = key.verifying_key().to_bytes();
            print_json(&Signed {
                network_passphrase: args.network_passphrase.clone(),
                network_id: to_hex(&domain.network_id),
                contract: keys::contract_address(&domain.contract_id),
                message: to_hex(&verdict::message(&domain, &verdict)),
                signature: to_hex(&verdict::sign(&key, &domain, &verdict)),
                public_key: to_hex(&public_key),
                signer: keys::account_address(&public_key),
                verdict,
            })
        }
        Command::Verify {
            message,
            public_key,
            signature,
        } => {
            let (domain, verdict) = message.parse()?;
            let public_key = keys::public_key(&public_key)?;
            let signature = parse_hex::<64>(&signature).context("--signature")?;
            verdict::verify(&public_key, &domain, &verdict, &signature)?;
            println!("valid");
            Ok(())
        }
        Command::ServiceId { owner, label } => {
            let owner = Owner::parse(&owner)?;
            let label = service::label(&label)?;
            println!("{}", to_hex(&service::service_id(&owner, &label)));
            Ok(())
        }
        Command::RequestHash {
            service_id,
            method,
            target,
            body,
        } => {
            let service_id = parse_hex::<32>(&service_id).context("--service-id")?;
            let body = match body.strip_prefix('@') {
                Some(path) => std::fs::read(path).with_context(|| format!("reading {path}"))?,
                None => body.into_bytes(),
            };
            println!(
                "{}",
                to_hex(&hashes::request_hash(&service_id, &method, &target, &body))
            );
            Ok(())
        }
        Command::PredicateHash { file } => {
            let bytes =
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            println!("{}", to_hex(&hashes::predicate_hash(&bytes)));
            Ok(())
        }
        Command::OriginHash { origin } => {
            println!("{}", to_hex(&hashes::Origin::parse(&origin)?.hash()));
            Ok(())
        }
        Command::NotaryKeyHash { key } => {
            let key = hex::decode(key.trim().trim_start_matches("0x")).context("notary key hex")?;
            if key.len() != 33 {
                bail!(
                    "expected a 33-byte compressed SEC1 key, got {} bytes",
                    key.len()
                );
            }
            println!("{}", to_hex(&hashes::notary_key_hash(&key)));
            Ok(())
        }
        Command::Vectors => {
            print!("{}", vectors::document_json());
            Ok(())
        }
    }
}

impl MessageArgs {
    fn parse(&self) -> Result<(Domain, Verdict)> {
        let contract_id = keys::contract_id(&self.contract).context("--contract")?;
        let domain = Domain::new(&self.network_passphrase, contract_id);
        Ok((domain, self.verdict.parse()?))
    }
}

impl VerdictArgs {
    fn parse(&self) -> Result<Verdict> {
        let hash =
            |name: &str, value: &str| parse_hex::<32>(value).with_context(|| format!("--{name}"));
        let outcome = match self.outcome.to_ascii_lowercase().as_str() {
            "delivered" | "1" => OUTCOME_DELIVERED,
            "failed" | "2" => OUTCOME_FAILED,
            other => bail!("--outcome must be delivered or failed, got {other:?}"),
        };
        let issued_at = match self.issued_at {
            Some(t) => t,
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| anyhow!("system clock: {e}"))?
                .as_secs(),
        };
        Ok(Verdict {
            call_id: hash("call-id", &self.call_id)?,
            service_id: hash("service-id", &self.service_id)?,
            request_hash: hash("request-hash", &self.request_hash)?,
            predicate_hash: hash("predicate-hash", &self.predicate_hash)?,
            outcome,
            presentation_hash: hash("presentation-hash", &self.presentation_hash)?,
            response_hash: hash("response-hash", &self.response_hash)?,
            issued_at,
        })
    }
}

fn signing_key_from_env() -> Result<ed25519_dalek::SigningKey> {
    let secret = std::env::var(SECRET_ENV).map_err(|_| {
        anyhow!("{SECRET_ENV} is not set (a Stellar secret seed S… or 64 hex characters)")
    })?;
    Ok(keys::signing_key(&secret)?)
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
