//! Drives the `fermata-verdict` binary the way the scripts do and checks it against the vectors.

use std::process::{Command, Output};

use fermata_verdict::vectors::{self, Document};

const BIN: &str = env!("CARGO_BIN_EXE_fermata-verdict");

fn run(args: &[&str], secret: Option<&str>) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args).env_remove("FERMATA_VERIFIER_SECRET");
    if let Some(secret) = secret {
        cmd.env("FERMATA_VERIFIER_SECRET", secret);
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

fn doc() -> Document {
    vectors::document()
}

fn verdict_args(doc: &Document, i: usize) -> Vec<String> {
    let v = &doc.verdicts[i];
    let outcome = if v.verdict.outcome == 1 {
        "delivered"
    } else {
        "failed"
    };
    vec![
        "--network-passphrase".into(),
        v.network_passphrase.clone(),
        "--contract".into(),
        v.contract.clone(),
        "--call-id".into(),
        hex::encode(v.verdict.call_id),
        "--service-id".into(),
        hex::encode(v.verdict.service_id),
        "--request-hash".into(),
        hex::encode(v.verdict.request_hash),
        "--predicate-hash".into(),
        hex::encode(v.verdict.predicate_hash),
        "--outcome".into(),
        outcome.into(),
        "--presentation-hash".into(),
        hex::encode(v.verdict.presentation_hash),
        "--response-hash".into(),
        hex::encode(v.verdict.response_hash),
        "--issued-at".into(),
        v.verdict.issued_at.to_string(),
    ]
}

fn with(cmd: &str, rest: &[String]) -> Vec<String> {
    let mut args = vec![cmd.to_string()];
    args.extend_from_slice(rest);
    args
}

fn strs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

#[test]
fn vectors_command_prints_the_committed_file() {
    let committed = include_str!("../../../test-vectors/verdict-v1.json");
    assert_eq!(stdout(&run(&["vectors"], None)), committed);
}

#[test]
fn sign_reproduces_every_vector_and_verify_accepts_it() {
    let doc = doc();
    for i in 0..doc.verdicts.len() {
        let args = verdict_args(&doc, i);
        let out = stdout(&run(&strs(&with("sign", &args)), Some(&doc.signer.seed)));
        let signed: serde_json::Value = serde_json::from_str(&out).unwrap();
        let v = &doc.verdicts[i];
        assert_eq!(signed["signature"], v.signature);
        assert_eq!(signed["message"], v.message);
        assert_eq!(signed["signer"], doc.signer.address);
        assert_eq!(signed["verdict"], serde_json::to_value(&v.verdict).unwrap());

        let message = stdout(&run(&strs(&with("message", &args)), None));
        assert_eq!(message.trim(), v.message);

        let mut verify = with("verify", &args);
        verify.extend([
            "--public-key".into(),
            doc.signer.address.clone(),
            "--signature".into(),
            v.signature.clone(),
        ]);
        assert_eq!(stdout(&run(&strs(&verify), None)).trim(), "valid");
    }
}

#[test]
fn verify_rejects_a_signature_from_another_domain() {
    let doc = doc();
    // vector 2 is the same verdict signed for mainnet; check it against the testnet domain
    let mut verify = with("verify", &verdict_args(&doc, 0));
    verify.extend([
        "--public-key".into(),
        doc.signer.public_key.clone(),
        "--signature".into(),
        doc.verdicts[2].signature.clone(),
    ]);
    assert!(!run(&strs(&verify), None).status.success());
}

#[test]
fn a_stellar_secret_seed_works_like_hex() {
    let doc = doc();
    let seed: [u8; 32] = hex::decode(&doc.signer.seed).unwrap().try_into().unwrap();
    let s_key = stellar_strkey::ed25519::PrivateKey(seed)
        .to_string()
        .as_str()
        .to_owned();
    let out = stdout(&run(&["pubkey"], Some(&s_key)));
    let pk: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(pk["public_key"], doc.signer.public_key);
    assert_eq!(pk["address"], doc.signer.address);
}

#[test]
fn sign_without_a_secret_fails() {
    let args = with("sign", &verdict_args(&doc(), 0));
    let out = run(&strs(&args), None);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("FERMATA_VERIFIER_SECRET"));
}

#[test]
fn sign_refuses_other_outcomes() {
    let mut args = verdict_args(&doc(), 0);
    let at = args.iter().position(|a| a == "--outcome").unwrap();
    args[at + 1] = "3".into();
    let out = run(&strs(&with("sign", &args)), Some(&doc().signer.seed));
    assert!(!out.status.success());
}

#[test]
fn service_id_and_hash_commands_match_the_vectors() {
    let doc = doc();
    let id = stdout(&run(
        &[
            "service-id",
            "--owner",
            &doc.service.owner,
            "--label",
            &doc.service.label_text,
        ],
        None,
    ));
    assert_eq!(id.trim(), doc.service.service_id);
    let label = stdout(&run(&["label", &doc.service.label_text], None));
    assert_eq!(label.trim(), doc.service.label);

    let h = &doc.hashes.request_hash;
    let rh = stdout(&run(
        &[
            "request-hash",
            "--service-id",
            &h.service_id,
            "--method",
            "post",
            "--target",
            &h.target,
            "--body",
            &h.body,
        ],
        None,
    ));
    assert_eq!(rh.trim(), h.value);

    let origin = stdout(&run(&["origin-hash", &doc.hashes.origin_hash.origin], None));
    assert_eq!(origin.trim(), doc.hashes.origin_hash.value);

    let notary = stdout(&run(
        &["notary-key-hash", &doc.hashes.notary_key_hash.key],
        None,
    ));
    assert_eq!(notary.trim(), doc.hashes.notary_key_hash.value);

    let predicate_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../predicates/quote-v1.json"
    );
    let predicate = stdout(&run(&["predicate-hash", predicate_path], None));
    assert_eq!(predicate.trim(), doc.hashes.predicate_hash.value);
}
