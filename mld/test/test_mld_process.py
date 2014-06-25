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
import cPickle
import zmq
from nose.tools import *
sys.path.append('../app')
from mld_process import mld_process
from icmpv6_extend import icmpv6_extend
from ryu.lib.packet import ethernet, ipv6, icmpv6, vlan
from ryu.ofproto import ether, inet
from scapy import sendrecv
from scapy import packet as scapy_packet
from nose.plugins.attrib import attr

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

    def test_check_exists_tmp_exsist(self):
        """
        if os.path.exists(filename):
            return

        else:
            dirpath = os.path.dirname(filename)
            if os.path.isdir(dirpath):
                f = open(filename, "w")
                f.write("")
                f.close()
                self.logger.info("create file[%s]", filename)
            else:
                os.makedirs(dirpath)
                f = open(filename, "w")
                f.write("")
                f.close()
                self.logger.info("create dir[%s], file[%s]",
                                 dirpath, filename)
        """
        filepath = "/tmp"
        self.mld_proc.check_exists_tmp(filepath)

    def test_check_exists_tmp_nofile(self):
        filedir = "/tmp/tempdir"
        filepath = filedir + "/tempfile"
        os.makedirs(filedir)
        self.mld_proc.check_exists_tmp(filepath)
        os.remove(filepath)
        os.rmdir(filedir)

    def test_check_exists_tmp_nodir(self):
        filedir = "/tmp/tempdir"
        filepath = filedir + "/tempfile"
        self.mld_proc.check_exists_tmp(filepath)
        os.remove(filepath)
        os.rmdir(filedir)

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
        mc_addr = "::"
        ip_addr_list = []
        expect = icmpv6.mldv2_query(address=mc_addr, srcs=ip_addr_list,
                                   maxresp=10000, qqic=15)
        actual = self.mld_proc.create_mldquery(mc_addr, ip_addr_list)
        eq_(expect.address, actual.address)
        eq_(expect.srcs, actual.srcs)
        eq_(expect.maxresp, actual.maxresp)
        eq_(expect.qqic, actual.qqic)

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
        mc_service_info = ["::", "1111::9999"]
        expect = icmpv6.mldv2_report(record_num=0,
            records=[icmpv6.mldv2_report_group(
                                    type_=icmpv6.MODE_IS_INCLUDE,
                                    num=1,
                                    address=mc_service_info[0],
                                    srcs=[mc_service_info[1]])])
        actual = self.mld_proc.create_mldreport(mc_service_info)
        eq_(expect.record_num, actual.record_num)
#        eq_(expect.records, actual.records)

    @attr(do=True)
    def test_create_packet(self):
        addressinfo = ["00:11:22:33:44:55", "66:55:44:33:22:11",
                       "1111::2222", "9999::8888"]
        
        eth = ethernet.ethernet(
            ethertype=ether.ETH_TYPE_IPV6, 
            src=addressinfo[0], dst=addressinfo[1])

        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                    data=[ipv6.option(type_=5, len_=2, data="\x00\x00"),
                          ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=addressinfo[2], dst=addressinfo[3],
                        hop_limit=1, nxt=inet.IPPROTO_HOPOPTS,
                        ext_hdrs=ext_headers)

        mld = icmpv6.mldv2_query(address="1234::6789", 
                                 srcs=["9876::4321"])

        icmp6 = icmpv6_extend(
                type_=icmpv6.MLD_LISTENER_QUERY, data=mld)

        expect = eth / ip6 / icmp6
        expect.serialize()
        
        actual = self.mld_proc.create_packet(addressinfo, mld)
        
        exp_eth = expect.get_protocols(ethernet.ethernet)
        exp_ip6 = expect.get_protocols(ipv6.ipv6)
        exp_extend = exp_ip6[0]
        exp_icmp6 = expect.get_protocols(icmpv6.icmpv6)
        exp_mld = exp_icmp6[0].data
        
        act_eth = actual.get_protocols(ethernet.ethernet)
        act_ip6 = actual.get_protocols(ipv6.ipv6)
        act_extend = act_ip6[0].ext_hdrs
        act_icmp6 = actual.get_protocols(icmpv6.icmpv6)
        act_mld = act_icmp6[0].data

        # TODO 確認方法
        eq_(expect.data, actual.data)
        """
        eq_(len(act_eth[0]), 1)
        eq_(exp_eth[0].dst, act_eth[0].dst)
        eq_(exp_eth[0].ethertype, act_eth[0].ethertype)
        eq_(exp_eth[0].src, act_eth[0].src)
        
        eq_(len(act_ip6[0]), 1)
        eq_(exp_ip6[0].dst, act_ip6[0].dst)
        eq_(exp_ip6[0].flow_label, act_ip6[0].flow_label)
        """

    def test_send_packet_to_sw(self):
        eth = ethernet.ethernet()
        ip6 = ipv6.ipv6()
        icmp6 = icmpv6.icmpv6()
        packet = eth / ip6 / icmp6
        packet.serialize()

        # sendrecv.sendp()のMock化
        sendpkt = scapy_packet.Packet(packet.data)
        self.mocker.StubOutWithMock(sendrecv, "sendp")
        sendrecv.sendp(sendpkt).AndReturn(0)

        self.mocker.ReplayAll()
        self.mld_proc.send_packet_to_sw(packet)
        self.mocker.UnsetStubs()
        self.mocker.VerifyAll()

    def test_send_packet_to_ryu(self):
        logger.debug("test_send_packet_to_ryu")
        """
        # send of zeromq
        self.send_sock.send(cPickle.dumps(ryu_packet, protocol=0))
        """
        
        eth = ethernet.ethernet()
        ip6 = ipv6.ipv6()
        icmp6 = icmpv6.icmpv6()
        packet = eth / ip6 / icmp6
        packet.serialize()

        # TODO send_sock.send()のMock化
        """
        ctx = zmq.Context()
        send_sock = ctx.socket(zmq.PUB)
        self.mocker.StubOutWithMock(self.mld_proc.send_sock, "send")
        self.mld_proc.send_sock.send(
            cPickle.dumps(packet, protocol=0)).AndReturn(0)

        self.mocker.ReplayAll()
        self.mld_proc.send_packet_to_ryu(packet)
        self.mocker.UnsetStubs()
        self.mocker.VerifyAll()
        """

    def test_distribute_receive_packet_query(self):
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
        addressinfo = ["00:11:22:33:44:55", "66:55:44:33:22:11",
                       "1111::2222", "9999::8888"]
        mld = icmpv6.mldv2_query(address="1234::6789",
                                 srcs=["9876::4321"])
        packet = self.mld_proc.create_packet(addressinfo, mld)

        self.mocker.StubOutWithMock(self.mld_proc, "send_reply")
        self.mld_proc.send_reply().AndReturn(0)
        
        self.mocker.ReplayAll()
        self.mld_proc.distribute_receive_packet(packet)
        self.mocker.UnsetStubs()
        self.mocker.VerifyAll()

    def test_distribute_receive_packet_report(self):
        addressinfo = ["00:11:22:33:44:55", "66:55:44:33:22:11",
                       "1111::2222", "9999::8888"]
        mld = icmpv6.mldv2_report(records=[icmpv6.mldv2_report_group(
                                    type_=icmpv6.MODE_IS_INCLUDE,
                                    num=1,
                                    address="1234::5678",
                                    srcs=["8765::4321"])])
        packet = self.mld_proc.create_packet(addressinfo, mld)

        self.mocker.StubOutWithMock(self.mld_proc, "send_multicast_info")
        self.mld_proc.send_multicast_info(packet).AndReturn(0)
        
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
        
        mc_info_list = [["1234::5678", "9876::5432"]]
        mld = self.mld_proc.create_mldreport(mc_info_list[0])
        sendpkt = self.mld_proc.create_packet(self.addressinfo, mld)

        self.mocker.StubOutWithMock(self.mld_proc, "load_multicast_info")
        self.mld_proc.load_multicast_info().AndReturn(mc_info_list)
        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_ryu")
        self.mld_proc.send_packet_to_ryu(sendpkt).AndReturn("")

        self.mocker.ReplayAll()
        self.mld_proc.send_reply()
        self.mocker.UnsetStubs()
        self.mocker.VerifyAll()

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
        # TODO 実装待ち
        self.mld_proc.load_multicast_info()

    def test_send_multicast_info(self):
        """
        self.logger.debug("")
        self.regist_multicast_info(pkt)
# TODO p-outの情報を設定したReportを生成する
#        sendpkt = self.create_mldreport(("", ""))
#        self.send_packet_to_ryu(sendpkt)
        """
        # TODO 実装待ち
        self.mld_proc.send_multicast_info(ipv6.ipv6())

    def test_regist_multicast_info(self):
        """
        self.logger.debug("")
# TODO p-inしたReportの情報をメモリ上に保持する
        """
        # TODO 実装待ち
        self.mld_proc.regist_multicast_info(ipv6.ipv6())

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
        # TODO 無限ループ対応
        pass


if __name__ == '__main__':
    unittest.main()
