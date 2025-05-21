from scapy.all import Packet, StrLenField, ConditionalField, bind_layers

from scapy.layers.quic import _quic_payloads, QuicVarIntField, QuicVarEnumField, QuicVarLenField

"""
    In latest scapy/layers/quic.py version, 0x1D is missing from payload table.
    From RFC 9000:
        "CONNECTION_CLOSE frame with a type of 0x1d is used to signal an error with the application that uses QUIC."
"""
_quic_payloads[0x1D] = "CONNECTION_CLOSE"




"""
    CONNECTION_CLOSE Frame class:
        
"""
class QUIC_CONNECTION_CLOSE(Packet):
    name = "QUIC CONNECTION_CLOSE"
    fields_desc = [
        QuicVarEnumField("type", 0x1C, {0x1C:"CONNECTION_CLOSE", 0x1D:"APPLICATION_CLOSE"}),
        QuicVarIntField ("error_code",0), ConditionalField(QuicVarIntField("frame_type", 0), lambda pkt: pkt.type == 0x1C),
        QuicVarLenField("reason_length", None, length_of="reason_phrase"),
        StrLenField("reason_phrase", b"", length_from=lambda pkt:pkt.reason_length),
    ]