# samplesend.py
from scapy.all import *
from scapy.layers.inet6 import *
import data 

if __name__ == '__main__':
    src = "11:22:33:44:55:66"
    dst = "66:55:44:33:22:11"
    srcip = "11::"
    dstip= "::11"

    conf.iface = "eth0"
    myMacAddr = "00:00:00:00:00:02"

    e = Ether()
    e.src = src
    e.dst = dst
    d = Dot1Q()
    d.prio = 0
    d.id = 0
    d.vlan = 100
    i = IPv6()
    i.src = srcip
    i.dst = dstip
    i.nh = data.IPPROTO_ICMPV6
    c = ICMPv6MLQuery()
    c.mladdr='ff38::1'
    
    sendpkt=e/d/i/c
#    sendpkt=Ether()/IPv6()/ICMPv6MLQuery_MLDv2()
    
    print ('sendpkt %s', sendpkt)
    sendp(sendpkt)

