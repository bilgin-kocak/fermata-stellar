#!/usr/bin/env python3
"""Independent check of test-vectors/verdict-v1.json.

Rebuilds every verdict message and service id from the vector's fields with plain Python and
signs with OpenSSL's Ed25519 (the `cryptography` package), so the encoding is confirmed by an
implementation that shares no code with the Rust crate or the contract.

    python3 test-vectors/check_vectors.py [path/to/verdict-v1.json]
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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


def main(path: Path) -> None:
    doc = json.loads(path.read_text())
    assert doc["verdict_tag"].encode() == VERDICT_TAG
    assert doc["service_tag"].encode() == SERVICE_TAG

    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(doc["signer"]["seed"]))
    public_key = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert public_key.hex() == doc["signer"]["public_key"], "public key"

    svc = doc["service"]
    owner_xdr = bytes.fromhex(svc["owner_xdr"])
    # XDR of ScVal::Address(account): SCV_ADDRESS (18), SC_ADDRESS_TYPE_ACCOUNT (0),
    # PUBLIC_KEY_TYPE_ED25519 (0), then the 32-byte key.
    assert owner_xdr[:12] == struct.pack(">III", 18, 0, 0) and len(owner_xdr) == 44, "owner xdr"
    label = bytes.fromhex(svc["label"])
    assert label.rstrip(b"\0").decode() == svc["label_text"] and len(label) == 12, "label"
    service_id = hashlib.sha256(SERVICE_TAG + owner_xdr + label).hexdigest()
    assert service_id == svc["service_id"], "service id"

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
    body_hash = hashlib.sha256(h["body"].encode()).digest()
    request_hash = hashlib.sha256(
        bytes.fromhex(h["service_id"]) + h["method"].upper().encode() + h["target"].encode() + body_hash
    ).hexdigest()
    assert request_hash == h["value"], "request hash"

    predicate = doc["hashes"]["predicate_hash"]
    predicate_bytes = (path.parent.parent / predicate["file"]).read_bytes()
    assert hashlib.sha256(predicate_bytes).hexdigest() == predicate["value"], "predicate hash"

    print(f"ok: {len(doc['verdicts'])} verdict vectors, service id, request and predicate hashes")


if __name__ == "__main__":
    default = Path(__file__).resolve().parent / "verdict-v1.json"
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else default)
