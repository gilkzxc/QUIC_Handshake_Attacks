from scapy.all import *
load_contrib("quic")

from scapy.layers.quic import *
from quic_crypto import *

LONG_HEADER_TYPES = {"Initial":{"V1":0b00, "V2":0b01}, 
               "0-RTT":{"V1":0b01, "V2":0b10},
               "Handshake":{"V1":0b10, "V2":0b11},
               "Retry":{"V1":0b11, "V2":0b00}} 

VERSION = {"int":{"V1":0x00000001, "V2":0x6b3343cf},
           "bytes":{"V1":b'\x00\x00\x00\x01', "V2":b'\x6b\x33\x43\xcf'}}

def _patch_length_in_initial(buf: bytearray,
                             token_len: int,
                             tok_vlen: int,
                             pn_len: int,
                             cipher_len: int) -> None:
    """
    Overwrite the Length field in-place after we know how long the Token
    and ciphertext are.

    Parameters
    ----------
    buf         : header bytes up to (but **not** including) Length
    token_len   : length of Token in bytes (0 for first flight)
    tok_vlen    : encoded length (1-8) of the varint Token-Length field
    pn_len      : 1-4 bytes of Packet Number
    cipher_len  : len(ciphertext || tag)
    """
    # The Length we need to write = PN + ciphertext/tag length
    new_len = pn_len + cipher_len
    len_encoded = encode_varint(new_len)             # varint (1-8 bytes)

    # Where to write?  After Destination-CID, Source-CID, Token-Length and Token
    len_off = 7 + buf[5] + 1 + buf[7 + buf[5]] + tok_vlen + token_len
    # overwrite previous placeholder (we reserved 2 bytes)
    buf[len_off : len_off + len(len_encoded)] = len_encoded

class QUIC_InitialProtected(QUIC_Initial):
    name = "QUIC Initial (protected)"

    def post_build(self, p, pay):


        key, iv, hp = derive_initial_keys(self.dcid, is_server=self.is_server)

        ciphertext_tag, nonce = encrypt_quic(pay, p, key, iv, self.packet_number)

        buf = bytearray(p) + ciphertext_tag

        if self.token:
            tok_len      = len(self.token)
            tok_vlen     = len(encode_varint(tok_len))
            _patch_length_in_initial(buf,
                                    token_len = tok_len,
                                    tok_vlen  = tok_vlen,
                                    pn_len    = self.pn_len,
                                    cipher_len= len(ciphertext_tag))

        pn_off = len(p) - self.pn_len      # first byte of Packet Number

        sample = buf[pn_off + 4 : pn_off + 20]          # RFC 9001 §5.4.2
        protect_header(buf, pn_off, hp, sample)

        return bytes(buf)