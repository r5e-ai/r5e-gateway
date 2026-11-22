#!/usr/bin/env python3
"""Independent check of the R5ES1 spool format and sealed-epoch vectors.

Written from the format described in Recurse.Gateway.Provenance.Spool's
moduledoc only, using the `cryptography` package, so the Elixir vectors are
checked by a second implementation.
"""
import hashlib, hmac, sys, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

def hkdf(ikm, salt, info):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

CHUNK = 65536

def seal(plain, epoch_id, dek, file_id):
    header = b"R5ES1" + epoch_id + file_id
    key = AESGCM(hkdf(dek, file_id, b"r5e spool file v1" + epoch_id))
    pieces = [plain[i:i + CHUNK] for i in range(0, len(plain), CHUNK)] or [b""]
    if len(plain) > 0 and len(plain) % CHUNK == 0:
        pass  # last piece is a full chunk, sealed as last
    out = [header]
    for i, p in enumerate(pieces):
        last = 1 if i == len(pieces) - 1 else 0
        nonce = i.to_bytes(8, "big") + bytes([last]) + b"\x00\x00\x00"
        aad = header + i.to_bytes(8, "big") + bytes([last])
        out.append(key.encrypt(nonce, p, aad))
    return b"".join(out)

def raw(priv):
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def seal_epoch(dek, epoch_id, deployment, id_pub, e_priv_bytes):
    e = X25519PrivateKey.from_private_bytes(e_priv_bytes)
    e_pub = raw(e)
    shared = e.exchange(X25519PublicKey.from_public_bytes(id_pub))
    epoch_hex = epoch_id.hex().encode()
    kek = hkdf(shared, e_pub + id_pub, b"r5e spool epoch v1|" + deployment + b"|" + epoch_hex)
    aad = b"r5e-spool-epoch-v1|" + deployment + b"|" + epoch_hex
    return e_pub, kek, AESGCM(kek).encrypt(b"\x00" * 12, dek, aad)

vec = json.load(open(sys.argv[1]))
epoch_id = bytes(range(0, 16)); dek = bytes(range(32, 64)); file_id = bytes(range(64, 80))
ok = True
for name, plain in [("empty", b""), ("short", b"hello spool"),
                    ("chunk_plus_5", bytes((i * 7) % 251 for i in range(CHUNK + 5))),
                    ("exact_chunk", bytes((i * 3) % 251 for i in range(CHUNK))),
                    ("two_full_chunks", bytes((i * 5) % 251 for i in range(2 * CHUNK)))]:
    got = hashlib.sha256(seal(plain, epoch_id, dek, file_id)).hexdigest()
    want = vec["files"][name]
    print(name, got == want, got)
    ok &= got == want
id_priv = bytes(range(80, 112)); e_priv = bytes(range(112, 144))
id_pub = raw(X25519PrivateKey.from_private_bytes(id_priv))
e_pub, kek, sealed = seal_epoch(dek, epoch_id, b"dep-vector", id_pub, e_priv)
print("kek", kek.hex() == vec["epoch"]["kek"])
ok &= kek.hex() == vec["epoch"]["kek"]
print("identity_pub", id_pub.hex() == vec["epoch"]["identity_pub"])
print("ephemeral_pub", e_pub.hex() == vec["epoch"]["ephemeral_pub"])
print("sealed", sealed.hex() == vec["epoch"]["sealed"], sealed.hex())
ok &= id_pub.hex() == vec["epoch"]["identity_pub"] and e_pub.hex() == vec["epoch"]["ephemeral_pub"] and sealed.hex() == vec["epoch"]["sealed"]
print("ALL_MATCH" if ok else "MISMATCH")
sys.exit(0 if ok else 1)
