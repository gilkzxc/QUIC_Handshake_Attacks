import os
os.environ['LANG'] = 'en_US.UTF-8'
os.environ['LC_ALL'] = 'en_US.UTF-8'


from mininet.cli import CLI
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import Node
from mininet.topo import Topo


# This type of host has routing capabilities

class LinuxRouter(Node):
    "A Node with IP forwarding enabled."

    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        # Enable forwarding on the router
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


class MBTopo(Topo):
    "Topology of private network and public network with middlebox in between"

    def build(self, **_opts):
        # Define Router
        router1 = self.addHost('rtr1', ip="10.69.0.1/24", mac="00:00:00:00:00:11", cls=LinuxRouter,
                               defaultRoute='via 10.69.0.2')  # Between networks 0 and 1

        # Define hosts with addresses and default routes
        private1 = self.addHost('private1', ip="192.168.1.101/24",
                                defaultRoute='via 192.168.1.1')

        middlebox = self.addHost('middlebox', ip="192.168.1.1/24")

        public1 = self.addHost('public1', ip="10.69.1.100/24",
                                  defaultRoute='via 10.69.1.1')

        # Switches for networks 0,1,2
        s0 = self.addSwitch('s0')
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # links between switches to hosts
        self.addLink(s0, private1, cls=TCLink)
        self.addLink(s0, middlebox, cls=TCLink)
        self.addLink(s2, public1, cls=TCLink)

        # Links between the switches and the routers
        self.addLink(middlebox, router1, intfName1='middlebox-eth1',
                     params1={'ip': '10.69.0.100/24'},
                     intfName2='r01-eth1',
                     params2={'ip': '10.69.0.1/24'})

        self.addLink(s2, router1, intfName2='r01-eth2',
                     params2={'ip': '10.69.1.1/24'})


topo = MBTopo()

net = Mininet(topo=topo)
net.start()

# in router 1, add route to private network
net['rtr1'].cmd('ip route add 192.168.1.0/24 via 10.69.0.100')

# In the middlebox host, add default route
net['middlebox'].cmd('ip route add default via 10.69.0.1')

# Set the NAT not to send RST
net['middlebox'].cmd('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')



CLI(net)
net.stop()
