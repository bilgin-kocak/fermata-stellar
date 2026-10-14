//! Drives the session subcommands of `fermata-verdict` the way `scripts/session-cases.sh` does and
//! checks them against `test-vectors/session-v1.json`.

use std::process::{Command, Output};

use fermata_verdict::session_vectors::{self, Document};

const BIN: &str = env!("CARGO_BIN_EXE_fermata-verdict");

fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .env_remove("FERMATA_VERIFIER_SECRET")
        .env_remove("FERMATA_TICKET_SECRET");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("binary runs")
}

fn stdout(out: &Output) -> String {
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_str(&stdout(out)).expect("JSON output")
}

fn doc() -> Document {
    session_vectors::document()
}

#[test]
fn session_vectors_print_the_committed_file() {
    let out = run(&["session-vectors"], &[]);
    assert_eq!(
        stdout(&out),
        include_str!("../../../test-vectors/session-v1.json")
    );
}

#[test]
fn chain_extends_over_request_hashes() {
    let doc = doc();
    let s = &doc.sessions[0];
    let mut args = vec!["chain", "--from", s.session_id.as_str(), "--request-hash"];
    args.extend(s.calls[..3].iter().map(|c| c.request_hash.as_str()));
    assert_eq!(stdout(&run(&args, &[])).trim(), s.calls[2].chain);
    // From a stored chain value: chain(3) extended over call 4's request hash is chain(4).
    let out = run(
        &[
            "chain",
            "--from",
            &s.calls[2].chain,
            "--request-hash",
            &s.calls[3].request_hash,
        ],
        &[],
    );
    assert_eq!(stdout(&out).trim(), s.calls[3].chain);
}

#[test]
fn ticket_signs_the_vector_message() {
    let doc = doc();
    let s = &doc.sessions[0];
    let c = &s.calls[2];
    let n = c.n.to_string();
    let args = [
        "ticket",
        "--network-passphrase",
        &doc.network_passphrase,
        "--contract",
        &doc.contract,
        "--session-id",
        &s.session_id,
        "--n",
        &n,
        "--chain",
        &c.chain,
    ];
    let v = json(&run(
        &args,
        &[("FERMATA_TICKET_SECRET", &doc.ticket_key.seed)],
    ));
    assert_eq!(v["message"], c.ticket_message);
    assert_eq!(v["signature"], c.ticket_signature);
    assert_eq!(v["public_key"], doc.ticket_key.public_key);
    // Without the key in its environment variable, nothing is signed.
    assert!(!run(&args, &[]).status.success());

    let pk = json(&run(
        &["ticket-pubkey"],
        &[("FERMATA_TICKET_SECRET", &doc.ticket_key.seed)],
    ));
    assert_eq!(pk["public_key"], doc.ticket_key.public_key);
}

#[test]
fn statement_signs_the_vector_message() {
    let doc = doc();
    for s in &doc.sessions {
        for b in &s.batches {
            let entries = serde_json::to_string(&b.entries).unwrap();
            let (from, to) = (b.from.to_string(), b.to.to_string());
            let args = [
                "statement",
                "--network-passphrase",
                &doc.network_passphrase,
                "--contract",
                &doc.contract,
                "--session-id",
                &s.session_id,
                "--service-id",
                &doc.service_id,
                "--predicate-hash",
                &doc.predicate_hash,
                "--from",
                &from,
                "--to",
                &to,
                "--chain",
                &s.calls[b.to as usize - 1].chain,
                "--seed",
                &b.seed,
                "--entries",
                &entries,
            ];
            let v = json(&run(
                &args,
                &[("FERMATA_VERIFIER_SECRET", &doc.verifier.seed)],
            ));
            assert_eq!(v["message"], b.statement_message);
            assert_eq!(v["signature"], b.statement_signature);
            assert_eq!(v["statement"]["entries_hash"], b.entries_hash);
        }
    }
}

#[test]
fn session_call_id_matches() {
    let doc = doc();
    let s = &doc.sessions[1];
    let c = &s.calls[4];
    let n = c.n.to_string();
    let out = run(
        &[
            "session-call-id",
            "--contract",
            &doc.contract,
            "--session-id",
            &s.session_id,
            "--n",
            &n,
        ],
        &[],
    );
    assert_eq!(stdout(&out).trim(), c.call_id);
}
