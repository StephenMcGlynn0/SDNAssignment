# Ryu OF1.3 Firewall: Allow ARP + ICMP, allow SSH only from Admins,
# block ICMP Students->Admin, and default deny all other traffic.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3

ADMIN = ["10.0.0.1", "10.0.0.2"]
STUDENTS = ["10.0.0.3", "10.0.0.4"]
IOT = ["10.0.0.5", "10.0.0.6"]

class FirewallICMPBlock(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def add_flow(self, dp, priority, match, actions=None):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = []
        if actions:
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp, ofp, parser = ev.msg.datapath, ev.msg.datapath.ofproto, ev.msg.datapath.ofproto_parser

        # Allow ARP globally (so network can resolve addresses)
        match_arp = parser.OFPMatch(eth_type=0x0806)
        actions_arp = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, priority=300, match=match_arp, actions=actions_arp)

        # Allow ICMP (pings) for everyone (general connectivity)
        match_icmp = parser.OFPMatch(eth_type=0x0800, ip_proto=1)
        actions_icmp = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, priority=250, match=match_icmp, actions=actions_icmp)

        # Allow SSH (TCP/22) only from Admins (to anywhere)
        for a in ADMIN:
            match_out = parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                                        ipv4_src=a, tcp_dst=22)
            match_in = parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                                       ipv4_dst=a, tcp_src=22)
            actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
            self.add_flow(dp, priority=240, match=match_out, actions=actions)
            self.add_flow(dp, priority=240, match=match_in, actions=actions)

        # Drop ICMP echo-request (type 8) from Students → Admin
        for s in STUDENTS:
            for a in ADMIN:
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=1,
                                        ipv4_src=s, ipv4_dst=a,
                                        icmpv4_type=8)
                self.add_flow(dp, priority=400, match=match, actions=[])

        # Default deny: drop all remaining IPv4 (unmatched traffic)
        match_drop = parser.OFPMatch(eth_type=0x0800)
        self.add_flow(dp, priority=10, match=match_drop, actions=[])
