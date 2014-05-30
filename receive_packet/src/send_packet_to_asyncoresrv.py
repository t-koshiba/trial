# coding: utf-8
from ryu.ofproto import ether, inet
from ryu.lib.packet import packet, ethernet, ipv6, icmpv6, vlan
import time
import socket
import asyncore


class SimpleMonitor(asyncore.dispatcher):

    # send interval(sec)
    WAIT_TIME = 10

    def __init__(self):
        asyncore.dispatcher.__init__(self)
        self._send_regularly()

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
        '''
        sendpkt.add_protocol(icmpv6.icmpv6(
            type_=icmpv6.MLDV2_LISTENER_REPORT,
            data=icmpv6.mldv2_report(
                record_num=2, records=[
                    icmpv6.mldv2_report_group(type_=1, address='::'),
                    icmpv6.mldv2_report_group(type_=2, address='::')])))
        '''
        sendpkt.serialize()
        
        return sendpkt

    def _send_regularly(self):
        print "******** _send_regularly"
        
        src = "11:22:33:44:55:66"
        dst = "66:55:44:33:22:11"
        srcip = "11::"
        dstip= "::11"
        in_port = 1
        #sendaddress = ("::1", 0, 0, 0)
        sendaddress = ("fd0b:2fa4:a373:0:200:ff:fe00:2", 12345, 0, 0)
        
        while True:
            IPPROTO_ICMP = socket.getprotobyname('ipv6-icmp')
#            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, IPPROTO_ICMP)
#            self.create_socket(socket.AF_INET6, socket.SOCK_RAW, IPPROTO_ICMP)
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
#            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.connect(sendaddress)
            sendpkt = self.createPacket(src, dst, srcip, dstip)
            print '******** socket send to%s' %(str(sendaddress))
            
            while sendpkt.data:
                
                #sent_bytes = sock.sendto(sendpkt.data, ('ff38::1', 0, icmpv6.icmpv6(type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY, data=icmpv6.mldv2_query(address='::'))))
                sent_bytes = sock.sendto(sendpkt.data, sendaddress)
                #sent_bytes = sock.send(sendpkt.data)
                print "******** sended %d byts :\n %s\n" % (sent_bytes, sendpkt)
                sendpkt.data = sendpkt.data[sent_bytes:]

            for aa in sendpkt.data:
                print(hex(aa))

            time.sleep(self.WAIT_TIME)


if __name__ == '__main__':
    import socket

    sm = SimpleMonitor()
