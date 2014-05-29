# coding: utf-8
# http://ja.pymotw.com/2/asyncore/
import asyncore
import logging
from datetime import datetime
import time

class EchoServer(asyncore.dispatcher):
    """Receives connections and establishes handlers for each client.
    """
    
    def __init__(self, address):
        self.logger = logging.getLogger('EchoServer')
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET6, socket.SOCK_STREAM)
#        self.create_socket(socket.AF_INET6, socket.SOCK_DGRAM)
#        self.create_socket(socket.AF_INET6, socket.SOCK_RAW)
        self.bind(address)
        self.address = self.socket.getsockname()
        self.logger.debug('%s binding to %s', self.returnNowTime(), self.address)
#        self.listen(1)
        return

    def handle_accept(self):
        try:
            # クライアントがソケットへ接続したときに呼び出される
            client_info = self.accept()
            self.logger.debug('%s handle_accept() -> %s', self.returnNowTime(), client_info[1])
            EchoHandler(sock=client_info[0])
            # 一度に一クライアントのみを扱うのでハンドラを設定したらクローズする
            # 普通はクローズせずにサーバは停止命令を受け取るか、永遠に実行される
            #self.handle_close()
            #return
        except KeyboardInterrupt:
            self.logger.debug('%s CAUSE KeyboardInterrupt', self.returnNowTime())
            self.handle_close()
            return
    
    def handle_close(self):
        self.logger.debug('%s handle_close()', self.rreturnNowTime())
        self.close()
        return

    def handle_error():
        self.logger.debug('%s handle_error()', self.rreturnNowTime())
        self.handle_close()
        return

    def returnNowTime(self):
        return str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100))


class EchoHandler(asyncore.dispatcher):
    """Handles echoing messages from a single client.
    """
    
    def __init__(self, sock, chunk_size=1024):
        self.chunk_size = chunk_size
        self.logger = logging.getLogger('EchoHandler%s' % str(sock.getsockname()))
        asyncore.dispatcher.__init__(self, sock=sock)
        self.data_to_write = []
        return
    
    def writable(self):
        """We want to write if we have received data."""
        response = bool(self.data_to_write)
        self.logger.debug('%s writable() -> %s', self.returnNowTime(), response)
        #time.sleep(5)
        return response
    
    def handle_write(self):
        """Write as much as possible of the most recent message we have received."""
        data = self.data_to_write.pop()
        sent = self.send(data[:self.chunk_size])
        if sent < len(data):
            remaining = data[sent:]
            self.data.to_write.append(remaining)
        self.logger.debug('%s handle_write() -> (%d) "%s"', self.returnNowTime(), sent, data[:sent])
        if not self.writable():
            self.handle_close()

    def handle_read(self):
        """Read an incoming message from the client and put it into our outgoing queue."""
        data = self.recv(self.chunk_size)
        self.logger.debug('%s handle_read() -> (%d) "%s"', self.returnNowTime(), len(data), data)
        self.data_to_write.insert(0, data)
    
    def handle_close(self):
        self.logger.debug('%s handle_close()', self.returnNowTime())
        self.close()

    def returnNowTime(self):
        return str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100))


class EchoClient(asyncore.dispatcher):
    """Sends messages to the server and receives responses.
    """
    
    def __init__(self, host, port, message, chunk_size=1024):
        self.message = message
        self.to_send = message
        self.received_data = []
        self.chunk_size = chunk_size
        self.logger = logging.getLogger('EchoClient')
        asyncore.dispatcher.__init__(self)
#        self.create_socket(socket.AF_INET6, socket.SOCK_STREAM)
#        self.create_socket(socket.AF_INET6, socket.SOCK_DGRAM)
        IPPROTO_ICMP = socket.getprotobyname('ipv6-icmp')
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, IPPROTO_ICMP)
#        socket.socket(socket.AF_INET6, socket.SOCK_RAW)
        EchoHandler(sock=sock)
        
        sendpkt = self.createPacket("11:22:33:44:55:66", "66:55:44:33:22:11", "1::", "::1")
        
        while sendpkt.data:
            
            #sent_bytes = sock.sendto(sendpkt.data, ('ff38::1', 0, icmpv6.icmpv6(type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY, data=icmpv6.mldv2_query(address='::'))))
            sent_bytes = sock.send(sendpkt.data)
            sendpkt.data = sendpkt.data[sent_bytes:]

        
        self.logger.debug('%s connecting to %s', self.returnNowTime(), (host, port))
#        self.connect((host, port))
        return
        
    def handle_connect(self):
        self.logger.debug('%s handle_connect()', self.returnNowTime())
    
    def handle_close(self):
        self.logger.debug('%s handle_close()', self.returnNowTime())
        self.close()
        received_message = ''.join(self.received_data)
        if received_message == self.message:
            self.logger.debug('%s RECEIVED COPY OF MESSAGE', self.returnNowTime())
        else:
            self.logger.debug('ERROR IN TRANSMISSION')
            self.logger.debug('EXPECTED "%s"', self.message)
            self.logger.debug('RECEIVED "%s"', received_message)
        return
    
    def writable(self):
        self.logger.debug('%s writable() -> %s', self.returnNowTime(), bool(self.to_send))
        return bool(self.to_send)

    def handle_write(self):
        sent = self.send(self.to_send[:self.chunk_size])
        self.logger.debug('%s handle_write() -> (%d) "%s"', self.returnNowTime(), sent, self.to_send[:sent])
        self.to_send = self.to_send[sent:]

    def handle_read(self):
        data = self.recv(self.chunk_size)
        self.logger.debug('%s handle_read() -> (%d) "%s"', self.returnNowTime(), len(data), data)
        self.received_data.append(data)
        
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
        '''
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
        sendpkt.serialize()
        return sendpkt

    def handle_error():
        self.handle_close()
        return

    def returnNowTime(self):
        return str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100))


if __name__ == '__main__':
    import socket

    logging.basicConfig(level=logging.DEBUG,
                        format='%(name)s: %(message)s',
                        )

    address = ('::1', 12345) # カーネルにポート番号を割り当てさせる
    server = EchoServer(address)
#    ip, port = server.address # 与えられたポート番号を調べる
    ip, port, flowinfo, scopeid = server.address # 与えられたポート番号を調べる

#    client = EchoClient(ip, port, message="********SEND MESSAGE********")

    asyncore.loop()


