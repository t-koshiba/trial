# coding: utf-8
# nose install
#  >sudo pip install nose
# coverage install
#  >sudo pip install coverage
#

import os
import logging
import sys
sys.path.append('../app')
import unittest
from nose.tools import *
from mld_process import mld_process


class test_mld_process():
    mld_proc = None
    logger = logging.getLogger("test_mld_process")

    BASEPATH = os.path.dirname(os.path.abspath(__file__))
    MULTICAST_SERVICE_INFO = os.path.normpath(
        os.path.join(BASEPATH, "./multicast_service_info.csv"))
    ADDRESS_INFO = os.path.normpath(
        os.path.join(BASEPATH, "./address_info.csv"))
    addressinfo = []
    mld_proc = None

    # このクラスのテストケースを実行する前に１度だけ実行する
    @classmethod
    def setup_class(clazz):
        clazz.logger.debug("setup")
        clazz.mld_proc = mld_process()
        for line in open(clazz.ADDRESS_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                columns = list(line[:-1].split(","))
                for column in columns:
                    clazz.addressinfo.append(column)
 
    # このクラスのテストケースをすべて実行した後に１度だけ実行する
    @classmethod
    def teardown_class(clazz):
        clazz.logger.debug("teardown")

    def test_init(self):
        self.logger.debug("test_init")
        self.logger.debug(self.addressinfo)
        eq_(self.mld_proc.addressinfo, self.addressinfo)
    
    def test_send_mldquey_regularly(self):
        """
        self.logger.debug("")
        mc_service_info_list = []
        for line in open(self.MULTICAST_SERVICE_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                # multicast_addr, srcip_addr
                column = list(line[:-1].split(","))
                mc_service_info_list.append(column)
        self.logger.debug(
            "send address(multicast_addr, srcip_addr) : %s",
            str(mc_service_info_list))

        while True:
            for mc_service_info in mc_service_info_list:
                ip_addr_list = []
                if not mc_service_info[1] == "":
                    ip_addr_list.append(mc_service_info[1])
                mld = self.create_mldquery(
                    mc_service_info[0], ip_addr_list)
                sendpkt = self.create_packet(
                    self.addressinfo[0], self.addressinfo[1],
                    self.addressinfo[2], self.addressinfo[3], mld)
                self.send_packet_to_sw(sendpkt)
                hub.sleep(self.WAIT_TIME)
        """
        pass

    def test_create_mldquery(self):
        """
        self.logger.debug("")
        return icmpv6.mldv2_query(address=mc_addr, srcs=ip_addr_list,
                                   maxresp=10000, qqic=15)
        """
        pass

    def test_create_mldreport(self):
        """
        self.logger.debug("")
        mc_service_info_list = []
        for line in open(self.MULTICAST_SERVICE_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                # mc_addr, ip_addr
                column = list(line[:-1].split(","))
                mc_service_info_list.append(column)

        for mc_service_info in mc_service_info_list:
            record_list = []

            src_list = []
            src_list.append(mc_service_info[1])

            record_list.append(icmpv6.mldv2_report_group(
                                        type_=icmpv6.MODE_IS_INCLUDE,
                                        num=1,
                                        address=mc_service_info[1],
                                        srcs=src_list))

            mld = icmpv6.mldv2_report(record_num=0,
                                      records=record_list)

            sendpkt = self.create_packet(self.addressinfo[0],
                                         self.addressinfo[1],
                                         self.addressinfo[2],
                                         self.addressinfo[3], mld)

            self.send_packet_to_ryu(sendpkt)
        """
        pass

    def create_packet(self, src, dst, srcip, dstip, mld):
        """
        self.logger.debug("")
        # ETHER
        eth = ethernet.ethernet(
            ethertype=ether.ETH_TYPE_IPV6, dst=dst, src=src)
        # IPV6 with Hop-By-Hop
        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                    data=[ipv6.option(type_=5, len_=2, data="\x00\x00"),
                          ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=srcip, dst=dstip, hop_limit=1,
                        nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=ext_headers)

        # MLDV2
        if type(mld) == icmpv6.mldv2_query:
            icmp6 = icmpv6_extend(
                type_=icmpv6.MLD_LISTENER_QUERY, data=mld)

        elif type(mld) == icmpv6.mldv2_report:
            icmp6 = icmpv6_extend(
                type_=icmpv6.MLDV2_LISTENER_REPORT, data=mld)

        # ether - vlan - ipv6 - icmpv6 ( - mldv2 )
        sendpkt = eth / ip6 / icmp6
        sendpkt.serialize()
        self.logger.debug("created packet(ryu) : %s", str(sendpkt))

        return sendpkt
        """
        pass

    def test_send_packet_to_sw(self):
        """
        self.logger.debug("")
        sendpkt = scapy_packet.Packet(ryu_packet.data)

        # send of scapy
        sendrecv.sendp(sendpkt)
        self.logger.info("sent 1 packet to switch.")
        """
        pass

    def test_send_packet_to_ryu(self):
        """
        self.logger.debug("")
        sendpkt = scapy_packet.Packet(ryu_packet.data)

        # send of zeromq
        self.send_sock.send(cPickle.dumps(sendpkt, protocol=0))
        self.logger.info("sent 1 packet to ryu.")
        """
        pass

    def test_listener_packet(self):
        """
        self.logger.debug("###packet=" + str(packet))
        pkt_eth = packet.get_protocols(ethernet.ethernet)
        pkt_ipv6 = packet.get_protocols(ipv6.ipv6)
        pkt_icmpv6_list = packet.get_protocols(icmpv6.icmpv6)
        print("pkt_eth" + str(pkt_eth))
        print("pkt_ipv6" + str(pkt_ipv6))
        print("pkt_icmpv6_list" + str(pkt_icmpv6_list))
        for pkt_icmpv6 in pkt_icmpv6_list:
            # MLDv2 Query
            if pkt_icmpv6.type_ == icmpv6.MLD_LISTENER_QUERY:
                self.logger.debug("MLDv2 Query : %s",
                                  str(pkt_icmpv6.data))
                self.create_mldreport()

            # MLDv2 Report
            if pkt_icmpv6.type_ == icmpv6.MLDV2_LISTENER_REPORT:
                self.logger.debug("MLDv2 Report : %s",
                                  str(pkt_icmpv6.data))
        """
        pass

    def test_receive_from_ryu(self):
        """
        self.logger.debug("")
        while True:
            # receive of zeromq
            recvpkt = self.recv_sock.recv()
            packet = cPickle.loads(recvpkt)
            self.logger.debug("packet : %s", str(packet))
            self.listener_packet(packet)

            self.org_thread_time.sleep(1)
        """
        pass


if __name__ == '__main__':
    unittest.main()
