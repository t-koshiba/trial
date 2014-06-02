#!/usr/bin/env python
#  http://netbuffalo.doorblog.jp/archives/4278096.html

from scapy.all import *

conf.iface = "eth0"
MESSAGE_TYPE_OFFER = 2

count = 0;
def callback(packet):
  global count
  print "****called 'callback'" 
  packet.show()
  print "\n"
  '''
  ****called 'callback'
    ###[ Ethernet ]###
    dst       = ff:ff:ff:ff:ff:ff
    src       = 00:00:00:00:00:00
    type      = IPv6
    ###[ IPv6 ]###
        version   = 6L
        tc        = 0L
        fl        = 0L
        plen      = 8
        nh        = ICMPv6
        hlim      = 64
        src       = ::1
        dst       = ::1
    ###[ ICMPv6 Echo Request ]###
            type      = Echo Request
            code      = 0
            cksum     = 0x7fbb
            id        = 0x0
            seq       = 0x0
            data      = ''
    
    ###[ ICMPv6 Echo Reply ]###
            type      = Echo Reply
            code      = 0
            cksum     = 0x7ebb
            id        = 0x0
            seq       = 0x0
            data      = ''
  '''
  
  if DHCP in packet and packet[DHCP].options[0][1] == MESSAGE_TYPE_OFFER:
    count = count + 1
    dst_hwaddr =  packet.dst
    offered_addr = packet[BOOTP].yiaddr
    # debug
    #packet.show()
#    print '%s DHCP OFFER: %s for %s from %s' % (count, offered_addr, dst_hwaddr, packet[IP].src)
    print '%s ICMPv6: %s for %s from %s' % (count, offered_addr, dst_hwaddr, packet[IP].src)

#print "Listening dhcp packet..."
print "Listening icmpv6 packet..."

#sniff(prn=callback, filter="udp and (port 67 or 68)", store=0)
sniff(prn=callback, filter="icmp6", store=0)
