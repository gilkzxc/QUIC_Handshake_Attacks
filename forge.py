# forge2.py  –– drop-in replacement
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from scapy.layers.inet import IP, UDP
from scapy.all import Raw
from typing import Tuple
_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

def _encode_varint_2(value: int) -> bytes:        # 2-byte QUIC varint
    # 0b01xxxxxx in the first byte (RFC 8999 §2) :contentReference[oaicite:4]{index=4}
    return bytes([(0x40 | (value >> 8) & 0x3F), value & 0xFF])

def forge_cc_scapy(
        dcid_secret: bytes,          # for HKDF
        dcid_header: bytes,          # will appear in header
        tpl: Tuple[str,int,str,int],
        frame: bytes,
        pn: int = 0) -> Raw:

    hk   = TLS13_HKDF()
    init = hk.extract(_SALT_V1, dcid_secret)                                # RFC 9001 §5.2 :contentReference[oaicite:5]{index=5}
    ssec = hk.expand_label(init, b"server in", b"", 32)
    key  = hk.expand_label(ssec, b"quic key", b"", 16)
    iv   = hk.expand_label(ssec, b"quic iv",  b"", 12)
    hp   = hk.expand_label(ssec, b"quic hp",  b"", 16)

    aead = AESGCM(key)

    # --- build header up to PN ------------------------------------
    hdr  = bytearray(b"\xc3\x00\x00\x00\x01")          # flags + version
    hdr += bytes([len(dcid_header)]) + dcid_header     # DCID
    hdr += b"\x00"                                     # SCID length = 0
    hdr += b"\x00"                                    # Token length  = 0  ← NEW
    hdr += b"\x00\x00"                                 # placeholder Length
    hdr += pn.to_bytes(4, "big")

    # --- AEAD ------------------------------------------------------
    nonce = iv[:8] + (int.from_bytes(iv[8:], "big") ^ pn).to_bytes(4,"big")
    ciphertext = aead.encrypt(nonce, frame, hdr)           # payload+tag :contentReference[oaicite:7]{index=7}

    full_len = 4 + len(ciphertext)                         # PN + ciphertext
    hdr_len_idx = 1 + 4 + 1 + len(dcid_header) + 1 + 1 # flags(1)+version(4)+dcid_len(1)+dcid+scid_len(1)+token_len(1)
    hdr[hdr_len_idx : hdr_len_idx + 2] = _encode_varint_2(full_len)
    ciphertext = aead.encrypt(nonce, frame, hdr)

    # --- header protection ----------------------------------------
    pn_offset = len(hdr) - 4                               # start of PN
    full_pkt = bytes(hdr) + ciphertext
    sample_start = pn_offset + 4           # PN-offset + PN-len (4) + 0
    sample = full_pkt[sample_start : sample_start + 16]   # correct 16-byte sample
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)
    hdr[0] ^= mask[0] & 0x0F                               # low 4 bits only
    for i in range(4):
        hdr[pn_offset + i] ^= mask[1 + i]

    return (IP(src=tpl[2], dst=tpl[0]) /
            UDP(sport=tpl[3], dport=tpl[1]) /
            Raw(bytes(hdr) + ciphertext))
