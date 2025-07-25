"""
    QUIC crypto helpers
"""
from typing import Tuple

from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from scapy.all import IP, UDP, Raw
from scapy.utils import strxor
from aioquic.quic.packet import pull_quic_header
from aioquic.buffer import Buffer
from aioquic.quic.crypto import CryptoPair
from connection_close import QUIC_CONNECTION_CLOSE
from quic_protected import *
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




def protect_header(hdr: bytearray, pn_offset: int, pn_length: int,
                           hp_key: bytes, sample: bytes) -> None:
    """
    Mutates *hdr* in place (first byte + PN bytes) per RFC 9001 § 5.4.1
    """
    mask = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor().update(sample)
    
    """pn_length = (hdr[0] & 0x03) + 1
    assert pn_length == len(hdr) - pn_offset, "PN-length mismatch" """
    #pn_length = len(hdr) - pn_offset
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


if __name__ == "__main__":
    dcid_example = bytes.fromhex("8394c8f03e515708")
    """payload = "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    payload = bytes.fromhex(payload)
    payload += b'\x00'*316
    print(f"Payload size is {len(payload)} bytes.")"""
    cc = QUIC_CONNECTION_CLOSE(
        type          = 0x1C,
        error_code    = 0x10,         # arbitrary error
        frame_type    = 0,            # e.g. PADDING triggered it
        reason_phrase = b"oops!"
    )
    payload  = bytes(cc)
    key, iv, hp = derive_initial_keys(dcid=dcid_example, is_server=True, version="V2")
    print(f"key: {key.hex()} , iv: {iv.hex()} , hp: {hp.hex()}")
    #hdr = bytearray([0xc3])
    hdr = bytearray([0xd3])
    #hdr += b'\x00\x00\x00\x01'
    hdr += VERSION_CONSTANTS["bytes"]["V2"]
    hdr += bytes([len(dcid_example)]) + dcid_example
    pn_length = 4
    body_len  = len(payload) + 16
    length_v  = encode_varint(pn_length + body_len)
    hdr += b"\x00\x00"
    hdr += length_v
    #pn = 2
    pn = 0
    hdr += pn.to_bytes(pn_length, "big")

    #print(f"Current unprotected hdr: {hdr.hex()} and it's equal to unprotected example: {hdr.hex() == 'c300000001088394c8f03e5157080000449e00000002'}")
    full_packet = bytes(hdr) + payload + (b"\x00" * 16)  # dummy tag ok for parsing
    buf = Buffer(data=full_packet)

    quic_hdr = pull_quic_header(buf)
    print(f"Testing aioquic parsing unprotected header (Should raise ValueError in case of exception: {quic_hdr}")
    ciphertext, _ = encrypt_quic(plaintext_payload=payload, aad=hdr, key=key, iv=iv, pn=pn)
    assert len(ciphertext) == len(payload) + 16  # GCM tag
    pn_offset = len(hdr) - pn_length # start of PN
    full_pkt = bytes(hdr) + ciphertext
    sample_start, sample_end = pn_offset+pn_length, pn_offset+pn_length+16
    hdr_unprotected = bytes(hdr)
    protect_header(hdr=hdr, pn_offset=pn_offset, pn_length=pn_length, hp_key=hp, sample=full_pkt[sample_start:sample_end])
    #print(f"Current protected header: {hdr.hex()} and it's equal to protected example: {hdr.hex() == 'c000000001088394c8f03e5157080000449e7b9aec34'}")

    protected_pkt = bytes(hdr) + ciphertext
    #print(f"Current protected packet: {protected_pkt.hex()} and it's equal to protected example: {protected_pkt.hex() == 'c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934'}")
    cp = CryptoPair()
    cp.setup_initial(cid=dcid_example,                # DCID that is *on the wire*
                    is_client=True,                # we are forging a server→client Initial
                    version=VERSION_CONSTANTS["int"]["V2"])
    try:
        plain_hdr, plain_payload, pn_out = cp.decrypt_packet(protected_pkt,             # removes HP *and* checks the GCM tag
                        pn_offset,
                        expected_packet_number=pn)
        assert plain_payload == payload
        assert pn_out == pn
        assert plain_hdr == bytes(hdr_unprotected)
    except Exception as exc:
        raise ValueError(f"Crypto validation failed: {exc}") from exc
    
    
