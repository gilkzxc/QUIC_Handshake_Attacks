"""
    QUIC crypto helpers
"""
from typing import Tuple

from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from scapy.all import IP, UDP, Raw
from scapy.utils import strxor


"""
    QUIC Initial secert, HKDF Labels, Keys constants by RFC 9001 § 5.2 & RFC 9369 § 3.3.1.
    
"""
INITIAL_SALT = {"V1":bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), 
                "V2":bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")}
HKDF_LABELS = {"key":{"V1":b"quic key", "V2":b"quicv2 key"}, 
               "iv":{"V1":b"quic iv", "V2":b"quicv2 iv"},
               "hp":{"V1":b"quic hp", "V2":b"quicv2 hp"}} 

MAX_PN = (1 << 62) - 1        # RFC-9000 §12.3

def derive_initial_keys(dcid: bytes, is_server: bool, version: str = "V1"
                        ) -> Tuple[bytes, bytes, bytes]:
    """
    HKDF-extract/expand for QUIC v1 Initial (RFC 9001 § 5.2).

    Returns   (key, iv, hp_key).
    """
    hk     = TLS13_HKDF()
    secret = hk.extract(INITIAL_SALT[version], dcid)
    role   = b"server in" if is_server else b"client in"
    init   = hk.expand_label(secret, role, b"", 32)
    key    = hk.expand_label(init,   HKDF_LABELS["key"][version], b"", 16)
    iv     = hk.expand_label(init,   HKDF_LABELS["iv"][version],  b"", 12)
    hp_key = hk.expand_label(init,   HKDF_LABELS["hp"][version],  b"", 16)
    return key, iv, hp_key




def protect_header(hdr: bytearray, pn_offset: int,
                           hp_key: bytes, sample: bytes) -> None:
    """
    Mutates *hdr* in place (first byte + PN bytes) per RFC 9001 § 5.4.1
    """
    mask = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor().update(sample)
    
    pn_length = (hdr[0] & 0x03) + 1
    assert pn_length == len(hdr) - pn_offset, "PN-length mismatch"
    if (hdr[0] & 0x80) == 0x80:
        # Long header: 4 bits masked
        hdr[0] ^= mask[0] & 0x0f
    else:
        # Short header: 5 bits masked
        hdr[0] ^= mask[0] & 0x1f

    
    hdr[pn_offset:pn_offset+pn_length] = strxor(hdr[pn_offset:pn_offset+pn_length], mask[1:1+pn_length])


def encrypt_quic(plaintext_payload: bytes, aad: bytes, key: bytes,
                  iv: bytes, pn: int, aead_cls = AESGCM) -> Tuple[bytes, bytes]:
    """
    RFC 9001-compliant plaintext payload AEAD encryption with the chosen ciphersuit
      aead_cls(Defualt value AES-128-GCM as required for Initial) and PN-derived nonce.
    Returns (ciphertext||tag, nonce) so the caller can reuse nonce
    for header protection.
    """
    assert 0 <= pn <= MAX_PN, "packet number out of range [0,2**61 - 1] as should by RFC9001."
    assert len(iv) == 12, "IV must be 12 bytes for QUIC and ciphersuits in use as by RFC9001"

    nonce = strxor(iv, pn.to_bytes(12, "big")) # .to_bytes() Pads on the left with zeros in default. 
    aead = aead_cls(key)
    ciphertext_tag = aead.encrypt(nonce, plaintext_payload, aad)
    return ciphertext_tag, nonce 


def encode_varint(v: int) -> bytes:
    """
    Encode *v* (0 ≤ v < 2**62) into QUIC’s 1/2/4/8-byte var-int form
    (RFC 9000 §16).  Raises ValueError on overflow.
    """
    if v < 0x40:
        return bytes([v])
    if v < 0x4000:
        return bytes([(0x40 | (v >> 8)), v & 0xFF])
    if v < 0x40000000:
        return bytes([
            0x80 | (v >> 24),
            (v >> 16) & 0xFF,
            (v >>  8) & 0xFF,
            v & 0xFF,
        ])
    if v < 0x4000000000000000:
        hi = 0xC0 | (v >> 56)
        return hi.to_bytes(1, "big") + v.to_bytes(8, "big")[1:]
    raise ValueError("varint out of range (0 ≤ v < 2**62)")