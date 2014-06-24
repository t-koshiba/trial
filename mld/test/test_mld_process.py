# coding: utf-8
# nose install
#  >sudo pip install nose
# coverage install
#  >sudo pip install coverage
# mox install
#  >sudo pip install mox
#

import os
import logging
import sys
import unittest
import mox
from nose.tools import *
sys.path.append('../app')
from mld_process import mld_process
from icmpv6_extend import icmpv6_extend
from ryu.lib.packet import ethernet, ipv6, icmpv6, vlan
from ryu.ofproto import ether, inet
from scapy import sendrecv
from scapy import packet as scapy_packet

logger = logging.getLogger(__name__)


class test_mld_process():

    BASEPATH = os.path.dirname(os.path.abspath(__file__))
    MULTICAST_SERVICE_INFO = os.path.normpath(
        os.path.join(BASEPATH, "./multicast_service_info.csv"))
    ADDRESS_INFO = os.path.normpath(
        os.path.join(BASEPATH, "./address_info.csv"))
    addressinfo = []

    # このクラスのテストケースを実行する前に１度だけ実行する
    @classmethod
    def setup_class(clazz):
        clazz.mocker = mox.Mox()
        logger.debug("setup")
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
        logger.debug("teardown")

    def test_init(self):
        logger.debug("test_init")
        logger.debug(self.addressinfo)
        eq_(self.mld_proc.addressinfo, self.addressinfo)
    
    def test_send_mldquey_regularly(self):
        # TODO 無限ループをどうするか
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
        mc_addr = ""
        ip_addr_list = []
        expect = icmpv6.mldv2_query(address=mc_addr, srcs=ip_addr_list,
                                   maxresp=10000, qqic=15)
        actual = self.mld_proc.create_mldquery(mc_addr, ip_addr_list)
        ok_(expect, actual)

    def test_create_mldreport(self):
        """
        self.logger.debug("")

        src_list = []
        src_list.append(mc_service_info[1])

        record_list = []
        record_list.append(icmpv6.mldv2_report_group(
                                    type_=icmpv6.MODE_IS_INCLUDE,
                                    num=1,
                                    address=mc_service_info[0],
                                    srcs=src_list))

        return icmpv6.mldv2_report(records=record_list)
        """
        mc_service_info = ["", ""]
        expect = icmpv6.mldv2_report(record_num=0,
            records=[icmpv6.mldv2_report_group(
                                    type_=icmpv6.MODE_IS_INCLUDE,
                                    num=1,
                                    address=mc_service_info[0],
                                    srcs=[""])])
        actual = self.mld_proc.create_mldreport(mc_service_info)
        ok_(expect, actual)

    def test_create_packet(self):
        """
        self.logger.debug("")

        # ETHER
        eth = ethernet.ethernet(
            ethertype=ether.ETH_TYPE_IPV6, 
            src=addressinfo[0], dst=addressinfo[1])

        # IPV6 with Hop-By-Hop
        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                    data=[ipv6.option(type_=5, len_=2, data="\x00\x00"),
                          ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=addressinfo[2], dst=addressinfo[3],
                        hop_limit=1, nxt=inet.IPPROTO_HOPOPTS,
                        ext_hdrs=ext_headers)

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

        addressinfo = ["00:11:22:33:44:55", "66:55:44:33:22:11",
                       "11::22", "99::88"]
        
        eth = ethernet.ethernet(
            ethertype=ether.ETH_TYPE_IPV6, 
            src=addressinfo[0], dst=addressinfo[1])

        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                    data=[ipv6.option(type_=5, len_=2, data="\x00\x00"),
                          ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=addressinfo[2], dst=addressinfo[3],
                        hop_limit=1, nxt=inet.IPPROTO_HOPOPTS,
                        ext_hdrs=ext_headers)

        mld = icmpv6.mldv2_query(address="12::89", srcs=["98::21"])

        icmp6 = icmpv6_extend(
                type_=icmpv6.MLD_LISTENER_QUERY, data=mld)

        expect = eth / ip6 / icmp6
        expect.serialize()
        
        actual = self.mld_proc.create_packet(addressinfo, mld)
        
        ok_(expect, actual)

    def test_send_packet_to_sw(self):
        """
        self.logger.debug("")
        sendpkt = scapy_packet.Packet(ryu_packet.data)

        # send of scapy
        sendrecv.sendp(sendpkt)
        self.logger.info("sent 1 packet to switch.")
        """
        # TODO scapyのsendrecv.sendpのMock化
        """
        mock_sendrecv = self.mocker.CreateMock(sendrecv)
        mock_sendrecv.sendp.AndReturn(0)
        self.mocker.ReplayAll()
        eth = ethernet.ethernet()
        ip6 = ipv6.ipv6()
        icmp6 = icmpv6.icmpv6()
        packet = eth / ip6 / icmp6
        packet.serialize()
        self.mld_proc.send_packet_to_sw(packet)
        self.mocker.VerifyAll()
        """

    def test_send_packet_to_ryu(self):
        """
        self.logger.debug("")
        sendpkt = scapy_packet.Packet(ryu_packet.data)

        # send of zeromq
        self.send_sock.send(cPickle.dumps(sendpkt, protocol=0))
        self.logger.info("sent 1 packet to ryu.")
        """
        # TODO send_sock.send()のMock化
        pass

    def test_distribute_receive_packet(self):
        """
        pkt_eth = packet.get_protocols(ethernet.ethernet)
        pkt_ipv6 = packet.get_protocols(ipv6.ipv6)
        pkt_icmpv6_list = packet.get_protocols(icmpv6.icmpv6)
        for pkt_icmpv6 in pkt_icmpv6_list:
        for pkt_icmpv6 in pkt_icmpv6_list:
            # MLDv2 Query
            if pkt_icmpv6.type_ == icmpv6.MLD_LISTENER_QUERY:
                self.logger.debug("MLDv2 Query : %s",
                                  str(pkt_icmpv6.data))
                self.send_reply()

            # MLDv2 Report
            if pkt_icmpv6.type_ == icmpv6.MLDV2_LISTENER_REPORT:
                self.logger.debug("MLDv2 Report : %s",
                                  str(pkt_icmpv6.data))
                self.send_multicast_info(pkt_icmpv6)
        """
        self.mocker.StubOutWithMock(self.mld_proc, "send_reply")
        self.mld_proc.send_reply().AndReturn(0)
        
        addressinfo = ["00:11:22:33:44:55", "66:55:44:33:22:11",
                       "11::22", "99::88"]
        mld = icmpv6.mldv2_query(address="12::89", srcs=["98::21"])
        packet = self.mld_proc.create_packet(addressinfo, mld)
        self.mocker.ReplayAll()
        self.mld_proc.distribute_receive_packet(packet)
        self.mocker.UnsetStubs()
        self.mocker.VerifyAll()

    def test_send_reply(self):
        """
        self.logger.debug("")
        
        mc_info_list = self.load_multicast_info()
        for mc_info in mc_info_list:
            mld = self.create_mldreport(mc_info)
            sendpkt = self.create_packet(self.addressinfo, mld)
            self.send_packet_to_ryu(sendpkt)
        """
        pass

    def test_load_multicast_info(self):
        """
        self.logger.debug("")
# TODO p-inしたReportから保持した情報を返却する
#     （暫定でファイルからの読み込み）
        mc_service_info_list = []
        for line in open(self.MULTICAST_SERVICE_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                # mc_addr, ip_addr
                column = list(line[:-1].split(","))
                mc_service_info_list.append(column)
        return mc_service_info_list
        """
        pass

    def test_send_multicast_info(self):
        """
        self.logger.debug("")
        self.regist_multicast_info(pkt)
# TODO p-outの情報を設定したReportを生成する
#        sendpkt = self.create_mldreport(("", ""))
#        self.send_packet_to_ryu(sendpkt)
        """
        pass

    def test_regist_multicast_info(self):
        """
        self.logger.debug("")
# TODO p-inしたReportの情報をメモリ上に保持する
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
