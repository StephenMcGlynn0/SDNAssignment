#!/usr/bin/env python3
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info

class MyTopo(Topo):
    def build(self):
        # Core layer (redundant pair)
        s1 = self.addSwitch('s1', protocols='OpenFlow13')  # Core switch A
        s2 = self.addSwitch('s2', protocols='OpenFlow13')  # Core switch B (redundant link)

        # Distribution layer (departments)
        s3 = self.addSwitch('s3', protocols='OpenFlow13')  # Admin
        s4 = self.addSwitch('s4', protocols='OpenFlow13')  # Students
        s5 = self.addSwitch('s5', protocols='OpenFlow13')  # IoT
        s6 = self.addSwitch('s6', protocols='OpenFlow13')  # Shared Services / Backup

        # Hosts (auto-assigned IPs)
        h1 = self.addHost('h1')  # Admin
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')  # Students
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')  # IoT
        h6 = self.addHost('h6')

        # Connect hosts to their departmental switches
        self.addLink(h1, s3)
        self.addLink(h2, s3)
        self.addLink(h3, s4)
        self.addLink(h4, s4)
        self.addLink(h5, s5)
        self.addLink(h6, s5)

        # Core redundancy (dual core interlink)
        self.addLink(s1, s2)

        # Connect each department to both core switches (multiple paths)
        for dept in (s3, s4, s5):
            self.addLink(s1, dept)
            self.addLink(s2, dept)

        # Connect s6 as a shared backup/service network
        self.addLink(s1, s6)
        self.addLink(s2, s6)
        # Add one extra cross-link for extra redundancy
        self.addLink(s4, s5)

def run():
    setLogLevel('info')
    topo = MyTopo()
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch, link=TCLink)
    c0 = net.addController('c0', controller=RemoteController,
                           ip='127.0.0.1', port=6633)
    net.start()
    info('\n*** Testing connectivity (initial)\n')
    net.pingAll()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
