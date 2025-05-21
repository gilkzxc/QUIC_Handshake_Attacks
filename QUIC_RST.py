import os
from scapy.all import IP, UDP, send
from scapy.layers.quic import QUIC_PING, QUIC_PADDING,  QUIC_Initial
from connection_close import QUIC_CONNECTION_CLOSE

# random 8-byte Connection IDs
client_cid = os.urandom(8)
server_cid = os.urandom(8)

initial =  QUIC_Initial(
    Version      = 0x00000001,
    DstConnIDLen = len(server_cid), DstConnID=server_cid,
    SrcConnIDLen = len(client_cid), SrcConnID=client_cid,
    TokenLen     = 0,
    Token        = b'',
    PacketNumber = 1,
    # length = size of everything after the PacketNumber field
    # here: one CC frame only
    Length       = len(QUIC_CONNECTION_CLOSE())
)

# build a CONNECTION_CLOSE frame
cc = QUIC_CONNECTION_CLOSE(
    type          = 0x1C,
    error_code    = 0x10,         # arbitrary error
    frame_type    = 0,            # e.g. PADDING triggered it
    reason_phrase = b"oops!"
)

pkt = (
    IP(dst="192.168.1.101")/
    UDP(sport=12345, dport=443)/
    initial/
    cc
)

send(pkt)