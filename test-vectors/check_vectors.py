#!/usr/bin/env python3
"""Independent check of test-vectors/verdict-v1.json and test-vectors/attest-v1.json.

Rebuilds every verdict message and service id from the vectors' fields with plain Python and
checks the signatures with OpenSSL's Ed25519 (the `cryptography` package), so the encoding is
confirmed by an implementation that shares no code with the Rust crates or the contract.

- verdict-v1.json: the golden vectors; the fixed seed must reproduce every signature.
- attest-v1.json: verdicts the attestor signed for real TLSNotary presentations; each signature
  must verify under the recorded public key.

    python3 test-vectors/check_vectors.py [path/to/vector.json ...]
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

VERDICT_TAG = b"FERMATA_STELLAR_VERDICT_V1"
SERVICE_TAG = b"FERMATA_STELLAR_SERVICE_V1"
HASH_FIELDS_BEFORE = ("call_id", "service_id", "request_hash", "predicate_hash")
HASH_FIELDS_AFTER = ("presentation_hash", "response_hash")


def canonical(verdict: dict) -> bytes:
    out = b"".join(bytes.fromhex(verdict[f]) for f in HASH_FIELDS_BEFORE)
    out += struct.pack(">I", verdict["outcome"])
    out += b"".join(bytes.fromhex(verdict[f]) for f in HASH_FIELDS_AFTER)
    out += struct.pack(">Q", verdict["issued_at"])
    assert len(out) == 204
    return out


def service_id(owner_xdr: bytes, label: bytes) -> str:
    # XDR of ScVal::Address(account): SCV_ADDRESS (18), SC_ADDRESS_TYPE_ACCOUNT (0),
    # PUBLIC_KEY_TYPE_ED25519 (0), then the 32-byte key.
    assert owner_xdr[:12] == struct.pack(">III", 18, 0, 0) and len(owner_xdr) == 44, "owner xdr"
    assert len(label) == 12, "label"
    return hashlib.sha256(SERVICE_TAG + owner_xdr + label).hexdigest()


def request_hash(service_id_hex: str, method: str, target: str, body: bytes) -> str:
    body_hash = hashlib.sha256(body).digest()
    return hashlib.sha256(
        bytes.fromhex(service_id_hex) + method.upper().encode() + target.encode() + body_hash
    ).hexdigest()


def check_verdict_vectors(path: Path, doc: dict) -> str:
    assert doc["verdict_tag"].encode() == VERDICT_TAG
    assert doc["service_tag"].encode() == SERVICE_TAG

    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(doc["signer"]["seed"]))
    public_key = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert public_key.hex() == doc["signer"]["public_key"], "public key"

    svc = doc["service"]
    label = bytes.fromhex(svc["label"])
    assert label.rstrip(b"\0").decode() == svc["label_text"], "label"
    assert service_id(bytes.fromhex(svc["owner_xdr"]), label) == svc["service_id"], "service id"

    for v in doc["verdicts"]:
        network_id = hashlib.sha256(v["network_passphrase"].encode()).digest()
        assert network_id.hex() == v["network_id"], v["name"]
        body = canonical(v["verdict"])
        assert body.hex() == v["canonical"], v["name"]
        message = VERDICT_TAG + network_id + bytes.fromhex(v["contract_id"]) + body
        assert len(message) == 294 and message.hex() == v["message"], v["name"]
        signature = key.sign(message)
        assert signature.hex() == v["signature"], v["name"]
        key.public_key().verify(signature, message)

    h = doc["hashes"]["request_hash"]
    assert request_hash(h["service_id"], h["method"], h["target"], h["body"].encode()) == h["value"], "request hash"

    predicate = doc["hashes"]["predicate_hash"]
    predicate_bytes = (path.parent.parent / predicate["file"]).read_bytes()
    assert hashlib.sha256(predicate_bytes).hexdigest() == predicate["value"], "predicate hash"

    return f"{len(doc['verdicts'])} verdict vectors, service id, request and predicate hashes"


def check_attest_vector(path: Path, doc: dict) -> str:
    network_id = hashlib.sha256(doc["network_passphrase"].encode()).digest()
    assert network_id.hex() == doc["network_id"], "network id"
    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(doc["signer"]["public_key"]))
    owner_xdr = bytes.fromhex(doc["owner_xdr"])
    predicate_bytes = (path.parent.parent / "predicates" / "quote-v1.json").read_bytes()
    assert hashlib.sha256(predicate_bytes).hexdigest() == doc["predicate_hash"], "predicate hash"
    for name, outcome in (("delivered", 1), ("failed", 2)):
        case = doc[name]
        v = case["verdict"]
        assert v["outcome"] == outcome, name
        label = bytes.fromhex(case["label"])
        assert label.rstrip(b"\0").decode() == case["label_text"], name
        sid = service_id(owner_xdr, label)
        assert sid == case["service_id"] == v["service_id"], name
        assert v["request_hash"] == request_hash(sid, "GET", doc["target"], b""), name
        assert v["predicate_hash"] == doc["predicate_hash"], name
        message = VERDICT_TAG + network_id + bytes.fromhex(doc["contract_id"]) + canonical(v)
        assert len(message) == 294 and message.hex() == case["message"], name
        public_key.verify(bytes.fromhex(case["signature"]), message)
    return "2 attestor verdicts (DELIVERED, FAILED): messages, signatures, service ids, request hashes"


def main(paths: list[Path]) -> None:
    for path in paths:
        doc = json.loads(path.read_text())
        check = check_attest_vector if "delivered" in doc else check_verdict_vectors
        print(f"ok: {path.name}: {check(path, doc)}")


if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    main([Path(a) for a in sys.argv[1:]] or [here / "verdict-v1.json", here / "attest-v1.json"])
