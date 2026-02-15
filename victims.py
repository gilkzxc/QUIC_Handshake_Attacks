import sys
sys.stdout.reconfigure(encoding='utf-8')
import questionary
import os
from time import sleep
from scapy.all import IP, UDP
from ipaddress import IPv4Address


APPLAY_ON_VICTIM = "All destinations"
ATTACK_TYPES = ["DoS", "Session Hijack"]

def ipv4_to_3_zero_digits_padded_octets(ip_addr):
    return '.'.join(f"{int(o):03d}" for o in ip_addr.split('.'))


def bool_value_print(b):
    if b:
        return "X"
    return " "

def passive_status():
    return {"DoS":False, "Session Hijack":False, "Transparent":True }

class Victim:
    def __init__(self, src_ip):
        self.src = src_ip
        self.destinations = {}
        self.status = passive_status()

    def __contains__(self, dest_ip):
        return dest_ip in self.destinations
    
    def __getitem__(self, key):
        if key in self:
            return self.destinations[key]
        raise KeyError(f"Dest IP: {key} isn't in Victim.")
    
    def __iter__(self):
        # This allows direct iteration over the keys
        return iter(list(self.destinations.keys()))
    

    def add_destination(self, dest_ip, sport, dport):
        if dest_ip in self:
            return False
        self.destinations[dest_ip] = {"sport":sport, "dport":dport }
        self.destinations[dest_ip].update(passive_status())
        return True
    
    def __str__(self):
        result = f"║ {ipv4_to_3_zero_digits_padded_octets(self.src)}  ║                                                                           ║ [{bool_value_print(self.status['DoS'])}] ║      [{bool_value_print(self.status['Session Hijack'])}]       ║     [{bool_value_print(self.status['Transparent'])}]      ║\n"
        for dest_ip in self.destinations:
            result += f"║                  ║  • {ipv4_to_3_zero_digits_padded_octets(dest_ip)}                                                        ║ [{bool_value_print(self.destinations[dest_ip]['DoS'])}] ║      [{bool_value_print(self.destinations[dest_ip]['Session Hijack'])}]       ║     [{bool_value_print(self.destinations[dest_ip]['Transparent'])}]      ║\n"
        return result

    def attack(self, attack_type: str = "DoS", target_ip: str = APPLAY_ON_VICTIM):
        if target_ip == APPLAY_ON_VICTIM:
            #do attack to all Victim connection.
            self.status[attack_type] = True
            self.status["Transparent"] = False
            return True
        if target_ip in self:
            # Attack specific "route"
            self.destinations[target_ip][attack_type] = True
            self.destinations[target_ip]["Transparent"] = False
            return True
        return False
    
    def passive(self, target_ip: str = APPLAY_ON_VICTIM):
        if target_ip == APPLAY_ON_VICTIM:
            # Release Victim / be invisible to victim.
            self.status = passive_status()
            for dest_ip in self.destinations:
                self.destinations[dest_ip].update(passive_status())
            return True
        if target_ip in self:
            # Release specific "route".
            self.destinations[target_ip].update(passive_status())
            return True
        return False





class Victims:

    def __init__(self):
        self.victims = {}
        self.exit = False
        

    def __contains__(self, victim_ip):
        return victim_ip in self.victims
    
    def __getitem__(self, key):
        if key in self:
            return self.victims[key]
        raise KeyError(f"Src IP: {key} isn't in Victims.")
    
    

    def add(self, src_ip):
        if src_ip in self:
            return False
        self.victims[src_ip] = Victim(src_ip)
        return True
    
    def find_victim_from_wan_by_port(self, dport_from_wan):
        for src_ip in self.victims:
            for dest_ip in self.victims[src_ip]:
                #print(f"src_ip: {src_ip} , dest_ip: {dest_ip} , dport_from_wan: {dport_from_wan} , inside: {self.victims[src_ip][dest_ip]}")
                if self.victims[src_ip][dest_ip]["sport"] == dport_from_wan:
                    return src_ip
        return ""
    def find_victim_from_wan(self, dest_ip_from_wan, dport_from_wan):
        for src_ip in self.victims:
            if dest_ip_from_wan in self.victims[src_ip] and self.victims[src_ip][dest_ip_from_wan]["sport"] == dport_from_wan:
                return src_ip
        return ""


    def update(self, pkt):
        if pkt.haslayer(UDP) and pkt.haslayer(IP):
            if not pkt[IP].src in self:
                    self.add(pkt[IP].src)
            if not pkt[IP].dst in self[pkt[IP].src]:
                self[pkt[IP].src].add_destination(pkt[IP].dst,pkt[UDP].sport,pkt[UDP].dport)
            
            self[pkt[IP].src][pkt[IP].dst]["sport"] = pkt[UDP].sport
            self[pkt[IP].src][pkt[IP].dst]["dport"] = pkt[UDP].dport

    def run(self):
        self.victims = {}        # fresh start
        open_msg = f"""
#   ██████╗ ██╗   ██╗██╗ ██████╗    ██╗  ██╗ █████╗ ███╗   ██╗██████╗ ███████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗     █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
#  ██╔═══██╗██║   ██║██║██╔════╝    ██║  ██║██╔══██╗████╗  ██║██╔══██╗██╔════╝██║  ██║██╔══██╗██║ ██╔╝██╔════╝    ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
#  ██║   ██║██║   ██║██║██║         ███████║███████║██╔██╗ ██║██║  ██║███████╗███████║███████║█████╔╝ █████╗      ███████║   ██║      ██║   ███████║██║     █████╔╝ 
#  ██║▄▄ ██║██║   ██║██║██║         ██╔══██║██╔══██║██║╚██╗██║██║  ██║╚════██║██╔══██║██╔══██║██╔═██╗ ██╔══╝      ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ 
#  ╚██████╔╝╚██████╔╝██║╚██████╗    ██║  ██║██║  ██║██║ ╚████║██████╔╝███████║██║  ██║██║  ██║██║  ██╗███████╗    ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
#   ╚══▀▀═╝  ╚═════╝ ╚═╝ ╚═════╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
#                                                                                                                                                                   
""" 
        print(open_msg)
        sleep(2)
        print("\033[2J\033[1;1H")
        while True:
            print(self)
            if self.victims == {}:
                print("middlebox is offline, no victim was seen yet in the network. >")
                #input("Press any key to refresh....")
            else:
                cmd = questionary.select("middlebox is online, chose your action. > ",
                                        choices=["attack", "passive", "quit"]).ask()
                if cmd in ("q", "quit"):
                    os.system('sysctl -w net.ipv4.ip_forward=1')
                    os._exit(0)
                    #self.exit=True
                    #return
                chosen_victim = questionary.select("Choose victim for action change. >>", choices=self.victims.keys()).ask()

                if self.victims[chosen_victim].destinations == {}:
                    chosen_connection_target = APPLAY_ON_VICTIM
                    print("Applying on all victim's future connections on default.")
                else:
                    chosen_connection_target = questionary.select("Choose destination target. >>", choices=[APPLAY_ON_VICTIM]+
                                                                  list(self.victims[chosen_victim].destinations.keys())).ask()
                    
                if cmd in ("a", "attack"):
                    choose_attack_type = questionary.select("Choose attack type! >>>", choices=ATTACK_TYPES).ask()
                    self.victims[chosen_victim].attack(choose_attack_type, chosen_connection_target)
                    

                elif cmd in ("p", "passive"):
                    self.victims[chosen_victim].passive(chosen_connection_target)
                    

                
            sleep(0.05)
            print("\033[2J\033[1;1H")

    def __str__(self):
        result = """╔══════════════════╦═══════════════════════════════════════════════════════════════════════════╦═════╦════════════════╦══════════════╗
║  IP Source       ║  IP Destinations                                                          ║ DoS ║ Session Hijack ║ Transparent  ║\n"""
        for victim in self.victims:
            result += f"""╠══════════════════╬═══════════════════════════════════════════════════════════════════════════╬═════╬════════════════╬══════════════╣
{self.victims[victim]}"""
        result += "╚══════════════════╩═══════════════════════════════════════════════════════════════════════════╩═════╩════════════════╩══════════════╝"
        return result
    


if __name__ == "__main__":
    vs = Victims()
    vs.add("192.168.1.1")
    #vs.add("10.91.8.34")
    for v in vs.victims:
        for i in range(3):
            vs.victims[v].add_destination(f"81.12.48.{i}",f"23{i}","23")
    #vs.run()
    print(vs)
    print(vs.find_victim_from_wan_by_port("230"))
