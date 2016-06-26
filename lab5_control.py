"""
An OpenFlow 1.0 L2 learning switch implementation.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def _packet_in_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        nw = pkt.get_protocols(ipv4.ipv4)
        tp =pkt.get_protocol(tcp.tcp)
   
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid,{})

        self.logger.info("packet in %s %s %s %s",dpid, src, dst, in_port)

        if in_port==1:
            out_port=2
        elif in_port==2:
            out_port=1
            actions=[parser.OFPActionOutput(out_port)]

        if nw!=None and tp!=None:
            match = parser.OFPMatch(ip_proto=6,eth_type=0X800,tcp_dst=tp.dst_port,tcp_src=tp.src_port)
            self.add_flow(datapath,100,match,actions)
            data = None

        if msg.buffer_id ==ofproto.OFP_NO_BUFFER:
            data = msg.data
   
        out= parser.OFPPacketOut(datapath=datapath,buffer_id=msg.buffer_id, in_port=in_port,actions=actions,data=data)
        datapath.send_msg(out)
