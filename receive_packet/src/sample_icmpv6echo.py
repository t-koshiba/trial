# sample_icmpv6echo.py
from scapy.all import *
from scapy.layers.inet6 import *

if __name__ == '__main__':
    icmpv6echorequest=Ether()/IPv6()/ICMPv6EchoRequest()
    sendp(icmpv6echorequest)
    icmpv6echorequest=Ether()/IPv6()/ICMPv6EchoReply()
    sendp(icmpv6echorequest)
