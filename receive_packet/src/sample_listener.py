#!/usr/bin/env python
#  http://netbuffalo.doorblog.jp/archives/4278096.html

from scapy.all import *
from scapy.error import Scapy_Exception

#conf.iface = "eth0"
MESSAGE_TYPE_OFFER = 2

count = 0;
def callback(packet):
  global count
  print "****called 'callback'" 
  packet.show()
  print "\n"
  '''
  Eth/vlan/ipv6/icmpv6(mldv2 Query|Report)
  
  ****called 'callback'
    ###[ Ethernet ]###
    dst       = 00:00:00:00:00:00
    src       = 11:11:11:11:11:11
    type      = n_802_1Q
    ###[ 802.1Q ]###
        prio      = 0L
        id        = 0L
        vlan      = 100L
        type      = IPv6
    ###[ IPv6 ]###
            version   = 6L
            tc        = 0L
            fl        = 0L
            plen      = 28
            nh        = ICMPv6
            hlim      = 127
            src       = ::
            dst       = 1111::

    <<MLDv2 Query>>
    ###[ MLD - Multicast Listener Query ]###
            type      = MLD Query
            code      = 0
            cksum     = 0x6a1b
            mrd       = 0
            reserved  = 0
            mladdr    = ::
    ###[ Raw ]###
                load      = '\x02}\x00\x00'
    ###[ Padding ]###
                    load      = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    

    <<MLDv2 Report>>
    ###[ Raw ]###
            load      = '\x8f\x00\xa4N\x00\x00\x00\x01\x01\x00\x00\x01\xfe\x80\x00\x00\x00\x00\x00\x00\xd6=~\xff\xfeJF\x0c\x11\x11\x11\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
  '''
  
  if IPv6 in packet:# and packet[DHCP].options[0][1] == MESSAGE_TYPE_OFFER:
    count = count + 1
    
    if packet[IPv6].nh == 58:
        
        print "packet[IPv6].nh == ICMPv6 "
        
        
    
    '''dst_hwaddr =  packet.dst
    offered_addr = packet[BOOTP].yiaddr
    # debug
    #packet.show()
#    print '%s DHCP OFFER: %s for %s from %s' % (count, offered_addr, dst_hwaddr, packet[IP].src)
    print '%s ICMPv6: %s for %s from %s' % (count, offered_addr, dst_hwaddr, packet[IP].src)
    '''


print "Listening icmpv6 packet..."

#sniff(prn=callback, filter="udp and (port 67 or 68)", store=0)
sniff(prn=callback, iface="s1", filter="vlan and ip6 and icmp6")
