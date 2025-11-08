# Simple ACL controller app (OpenFlow 1.3)
# Blocks Student -> IoT communication only

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3

class SimpleACL(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleACL, self).__init__(*args, **kwargs)
        self.STUDENTS = ['10.0.0.3', '10.0.0.4']
        self.IOT = ['10.0.0.5', '10.0.0.6']

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        self.logger.info("Installing ACL rules on switch %s", dp.id)

        # Deny Students -> IoT
        for s in self.STUDENTS:
            for i in self.IOT:
                match = parser.OFPMatch(
                    eth_type=0x0800,  # IPv4
                    ipv4_src=s,
                    ipv4_dst=i
                )
                # No actions = drop
                self.add_flow(dp, 2000, match, [], f"Block Student {s} -> IoT {i}")

    def add_flow(self, dp, priority, match, actions, note=""):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst
        )
        dp.send_msg(mod)
        if note:
            self.logger.info("[ACL] %s (prio=%s)", note, priority)
