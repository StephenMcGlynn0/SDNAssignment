# Dynamic reroute on port-down (OpenFlow 1.3)
# When a port goes DOWN on a switch, delete all flows that output to that port.
# This forces re-learning via the controller and traffic shifts to alternate paths.
#
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3

class DynamicRerouteOnPortDown(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        reason = msg.reason
        port_no = msg.desc.port_no

        # Reasons: OFPPR_ADD (0), OFPPR_DELETE (1), OFPPR_MODIFY (2)
        # We care when a port becomes unusable: DELETE or MODIFY->down
        is_delete = (reason == ofp.OFPPR_DELETE)
        is_down = bool(msg.desc.state & ofp.OFPPS_LINK_DOWN) or bool(msg.desc.state & ofp.OFPPS_BLOCKED)

        if is_delete or is_down:
            self.logger.warning("[REROUTE] Port down on dp=%s port=%s (reason=%s). Deleting flows using that output port.",
                                dp.id, port_no, reason)

            # Delete any flows in any table that OUTPUT to this port
            # In OF1.3 you can delete by specifying out_port
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofp.OFPFC_DELETE,
                out_port=port_no,
                out_group=ofp.OFPG_ANY,
                table_id=ofp.OFPTT_ALL
            )
            dp.send_msg(mod)

            # Barrier request (to ensure flow deletion is processed)
            barrier = parser.OFPBarrierRequest(dp)
            dp.send_msg(barrier)

            self.logger.info("[REROUTE] Requested deletion of flows with out_port=%s on dp=%s. Traffic will re-learn via alternate paths.", port_no, dp.id)
        else:
            # Port add/up/modify (not down) – no action required
            self.logger.info("[REROUTE] Port status on dp=%s port=%s (reason=%s). No reroute action.", dp.id, port_no, reason)
