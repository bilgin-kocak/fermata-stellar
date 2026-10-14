#!/usr/bin/env python3
"""Independent check of the golden vectors in test-vectors/.

Rebuilds every message, hash and id from the vectors' fields with plain Python and checks the
signatures with OpenSSL's Ed25519 (the `cryptography` package), so the encodings are confirmed by
an implementation that shares no code with the Rust crates, the contracts or the SDK.

- verdict-v1.json: the golden vectors; the fixed seed must reproduce every signature.
- attest-v1.json: verdicts the attestor signed for real TLSNotary presentations; each signature
  must verify under the recorded public key.
- session-v1.json: session tickets, batch statements, call ids, the sample and the seed chain
  (docs/session-escrow.md, section 10); the fixed seeds must reproduce every signature.

    python3 test-vectors/check_vectors.py [path/to/vector.json ...]
"""

import base64
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


TICKET_TAG = b"FERMATA_STELLAR_TICKET_V1"
BATCH_TAG = b"FERMATA_STELLAR_BATCH_V1"
CALL_TAG = b"FERMATA_STELLAR_SESSION_CALL_V1"
DELIVERED, FAILED, ANSWERED, UNANSWERED = 1, 2, 3, 4
ZERO = bytes(32)


def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return crc


def strkey(kind: str, payload: bytes) -> str:
    """A Stellar strkey: base32 of version byte, payload and CRC16-XModem (little-endian)."""
    version = {"G": 6 << 3, "C": 2 << 3}[kind]
    body = bytes([version]) + payload
    return base64.b32encode(body + struct.pack("<H", crc16_xmodem(body))).decode()


def be32(n: int) -> bytes:
    return struct.pack(">I", n)


def sampled(seed: bytes, n: int, k: int) -> bool:
    if k == 1:
        return True
    return struct.unpack(">I", hashlib.sha256(seed + be32(n)).digest()[:4])[0] % k == 0


def check_signer(signer: dict) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signer["seed"]))
    public_key = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert public_key.hex() == signer["public_key"], "public key"
    assert strkey("G", public_key) == signer["address"], "address"
    return key


def check_session_vectors(path: Path, doc: dict) -> str:
    assert (doc["ticket_tag"].encode(), doc["batch_tag"].encode()) == (TICKET_TAG, BATCH_TAG)
    assert doc["call_tag"].encode() == CALL_TAG
    network = hashlib.sha256(doc["network_passphrase"].encode()).digest()
    assert network.hex() == doc["network_id"], "network id"
    contract = bytes.fromhex(doc["contract_id"])
    assert strkey("C", contract) == doc["contract"], "contract address"
    # The service is verdict-v1.json's vector service.
    vectors = json.loads((path.parent / "verdict-v1.json").read_text())
    svc = vectors["service"]
    assert service_id(bytes.fromhex(svc["owner_xdr"]), bytes.fromhex(svc["label"])) == doc["service_id"]
    service, predicate = bytes.fromhex(doc["service_id"]), bytes.fromhex(doc["predicate_hash"])
    verifier, ticket_key = check_signer(doc["verifier"]), check_signer(doc["ticket_key"])

    tickets = statements = 0
    for s in doc["sessions"]:
        name, k, size = s["name"], s["sample_k"], s["batch_size"]
        session = bytes.fromhex(s["session_id"])
        seeds = [bytes.fromhex(x) for x in s["seeds"]]
        if k == 1:
            assert seeds == [ZERO], name
        else:
            for j in range(1, len(seeds)):
                assert hashlib.sha256(seeds[j]).digest() == seeds[j - 1], f"{name}: seed chain"

        chains = [session]
        for i, c in enumerate(s["calls"]):
            n = i + 1
            assert c["n"] == n, name
            chains.append(hashlib.sha256(chains[-1] + bytes.fromhex(c["request_hash"])).digest())
            assert chains[n].hex() == c["chain"], f"{name}: chain({n})"
            call_id = hashlib.sha256(CALL_TAG + contract + session + be32(n)).hexdigest()
            assert call_id == c["call_id"], f"{name}: call id {n}"
            message = TICKET_TAG + network + contract + session + be32(n) + chains[n]
            assert len(message) == 157 and message.hex() == c["ticket_message"], f"{name}: ticket {n}"
            signature = ticket_key.sign(message)
            assert signature.hex() == c["ticket_signature"], f"{name}: ticket signature {n}"
            ticket_key.public_key().verify(signature, message)
            tickets += 1

        at = 0
        for j, b in enumerate(s["batches"]):
            lo, hi = b["from"], b["to"]
            assert lo == at and lo < hi <= len(s["calls"]), f"{name}: batch bounds"
            last = j == len(s["batches"]) - 1
            assert hi - lo <= size and (k == 1 or last or hi - lo == size), f"{name}: batch size"
            at = hi
            seed = bytes.fromhex(b["seed"])
            assert seed == (ZERO if k == 1 else seeds[j + 1]), f"{name}: seed of batch {j + 1}"
            body, counts = b"", {DELIVERED: 0, FAILED: 0, ANSWERED: 0, UNANSWERED: 0}
            for i, e in enumerate(b["entries"]):
                n = lo + 1 + i
                proved_call = sampled(seed, n, k)
                assert b["sampled"][i] == proved_call, f"{name}: sampled({n})"
                r = e["result"]
                presentation, response = bytes.fromhex(e["presentation_hash"]), bytes.fromhex(e["response_hash"])
                blank = presentation == ZERO and response == ZERO
                allowed = {
                    DELIVERED: proved_call and presentation != ZERO,
                    FAILED: proved_call and presentation != ZERO,
                    ANSWERED: not proved_call and blank,
                    UNANSWERED: blank,
                }
                assert allowed.get(r, False), f"{name}: entry {n}"
                counts[r] += 1
                body += be32(r) + presentation + response
            assert len(body) == 68 * (hi - lo), name
            entries_hash = hashlib.sha256(body).digest()
            assert entries_hash.hex() == b["entries_hash"], f"{name}: entries hash"
            st = b["statement"]
            fields = (st["session_id"], st["service_id"], st["predicate_hash"], st["chain"], st["seed"])
            assert fields == (session.hex(), service.hex(), predicate.hex(), chains[hi].hex(), seed.hex())
            assert (st["from"], st["to"], st["entries_hash"]) == (lo, hi, entries_hash.hex()), name
            message = (BATCH_TAG + network + contract + session + service + predicate
                       + be32(lo) + be32(hi) + chains[hi] + seed + entries_hash)
            assert len(message) == 288 and message.hex() == b["statement_message"], f"{name}: statement"
            signature = verifier.sign(message)
            assert signature.hex() == b["statement_signature"], f"{name}: statement signature"
            verifier.public_key().verify(signature, message)
            paid = max(0, counts[ANSWERED] + counts[DELIVERED] - (k - 1) * counts[FAILED])
            assert paid == b["paid_calls"], f"{name}: paid calls"
            statements += 1
    return f"{len(doc['sessions'])} sessions: {tickets} tickets, {statements} batch statements, seed chains and samples"


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
        if "sessions" in doc:
            check = check_session_vectors
        elif "delivered" in doc:
            check = check_attest_vector
        else:
            check = check_verdict_vectors
        print(f"ok: {path.name}: {check(path, doc)}")


if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    default = [here / "verdict-v1.json", here / "attest-v1.json", here / "session-v1.json"]
    main([Path(a) for a in sys.argv[1:]] or default)
