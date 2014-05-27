from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser, ether, inet
from ryu.lib.packet import packet, ethernet, ipv6, icmpv6, vlan
from ryu.lib import hub
import threading


class SimpleMonitor(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # get_protocol(eth/ipv6)
    PROTPCOL = ['eth', 'ipv6']

    # message when connected switch
    msg = None

    # send interval(sec)
    WAIT_TIME = 10

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.logger.debug('__init__ : %s', self.PROTPCOL)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.monitor_thread = hub.spawn(self._send_regularly)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        self.logger.debug('add_flow STR : %s', self.PROTPCOL)

        actions = [
            ofproto_v1_3_parser.OFPActionOutput(
                ofproto_v1_3.OFPP_NORMAL)]
        instructions = [
            ofproto_v1_3_parser.OFPInstructionActions(
                ofproto_v1_3.OFPIT_APPLY_ACTIONS, actions)]
        # match
        #    match = ofproto_v1_3_parser.OFPMatch
        #           (eth_type=ether.ETH_TYPE_IPV6,
        #            ip_proto=inet.IPPROTO_ICMP6)
        # miss match
        match = ofproto_v1_3_parser.OFPMatch(
            eth_type=ether.ETH_TYPE_IPV6, ip_proto=inet.IPPROTO_ICMP)
        flow_mod_msg = ofproto_v1_3_parser.OFPFlowMod(
            datapath, match=match, instructions=instructions)
        datapath.send_msg(flow_mod_msg)

        self.logger.debug('add_flow END : %s', self.PROTPCOL)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        # get_protocols(ethernet)
        pkt_eth = pkt.get_protocols(ethernet.ethernet)[0]
        self.logger.debug('ethernet= %s ', str(pkt_eth))
        dst = pkt_eth.dst
        src = pkt_eth.src

        pkt_ipv6 = None
        pkt_icmpv6 = None
        if 'ipv6' in self.PROTPCOL:
            # get_protocols(pkt_ipv6)
            pkt_ipv6 = pkt.get_protocols(ipv6.ipv6)
            if 0 < len(pkt_ipv6):
                self.logger.debug('ipv6= %s', str(pkt_ipv6))

            # get_protocols(pkt_icmpv6)
            pkt_icmpv6 = pkt.get_protocols(icmpv6.icmpv6)
            if 0 < len(pkt_icmpv6):
                self.logger.debug(
                    'icmpv6= %s icmpv6.ND_NEIGHBOR_SOLICIT = %s',
                    str(pkt_icmpv6), icmpv6.ND_NEIGHBOR_SOLICIT)

                if pkt_icmpv6[0].type_ not in [
                        icmpv6.MLDV2_LISTENER_REPORT,
                        icmpv6.ICMPV6_MEMBERSHIP_QUERY]:
                    print "icmpv6.type is " + str(pkt_icmpv6[0].type_)
                    return

        dpid = datapath
        self.mac_to_port.setdefault(dpid, {})

        self.logger.debug(
            'packet in %s %s %s %s %s',
            dpid, src, dst, in_port, str(self.packet_in_cnt))

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        self.logger.debug(
            'in_port = %s, out_port = %s, OFPP_FLOOD = %s',
            str(in_port), str(out_port), str(ofproto.OFPP_FLOOD))

        if out_port != ofproto.OFPP_FLOOD:

            if 'eth' in self.PROTPCOL:
                # match
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                # miss match
                match = parser.OFPMatch(
                    in_port=in_port, eth_type=0, eth_dst=dst)
            elif 'ipv6' in self.PROTPCOL:
                match = parser.OFPMatch(
                    in_port=in_port, eth_type=ether.ETH_TYPE_IPV6,
                    ip_proto=inet.IPPROTO_ICMPV6, ipv6_dst=dst)

            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        sendpkt = self.createPacket(
            src, dst, pkt_ipv6[0].src, pkt_ipv6[0].dst)
        self.sendPacketOut(
            parser, datapath, in_port, actions, sendpkt.data)

    def createPacket(self, src, dst, srcip, dstip):
        # create send packet
        #   ether - vlan - ipv6 - icmpv6 ( - mldv2 )
        sendpkt = packet.Packet()
        sendpkt.add_protocol(ethernet.ethernet(
            ethertype=ether.ETH_TYPE_8021Q, dst=dst, src=src))
        sendpkt.add_protocol(vlan.vlan(
            pcp=0, cfi=0, vid=100, ethertype=ether.ETH_TYPE_IPV6))
        sendpkt.add_protocol(ipv6.ipv6(
            src=srcip, dst=dstip, nxt=inet.IPPROTO_ICMPV6))
        sendpkt.add_protocol(icmpv6.icmpv6(
            type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY,
            data=icmpv6.mldv2_query(address='::')))
        sendpkt.serialize()
        return sendpkt

    def sendPacketOut(self, parser, datapath, in_port, actions, data):
        # out = parser.OFPPacketOut(
        #    datapath=datapath, buffer_id=msg.buffer_id,
        #    in_port=in_port, actions=actions, data=data)
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=0xffffffff,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug(
                    'register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug(
                    'unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _send_regularly(self):
        datapath = self.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        src = "11:22:33:44:55:66"
        dst = "66:55:44:33:22:11"
        srcip = "11::"
        dstip = "::11"
        in_port = 1

        sendpkt = self.createPacket(src, dst, srcip, dstip)
        while True:
            # wait for regist datapath before send
            if datapath.id not in self.datapaths:
                hub.sleep(1)
            else:
                break

        while True:
            # stop send when delete datapath
            if datapath.id not in self.datapaths:
                break

            self.sendPacketOut(
                parser, datapath, in_port, actions, sendpkt.data)
            self.logger.debug(
                "******** send packet :\n %s\n" % (sendpkt,))
            hub.sleep(self.WAIT_TIME)
