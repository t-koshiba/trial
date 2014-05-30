# coding: utf-8
# http://ja.pymotw.com/2/asyncore/
import asyncore
import logging
from datetime import datetime
import time
import socket

class EchoServer(asyncore.dispatcher):
    """Receives connections and establishes handlers for each client.
    """
    
    def __init__(self, address, chunk_size=1024):
        self.logger = logging.getLogger('ReceiveServer')
        self.chunk_size = chunk_size
        asyncore.dispatcher.__init__(self)
        
        self.create_socket(socket.AF_INET6, socket.SOCK_STREAM)
#        self.create_socket(socket.AF_INET6, socket.SOCK_DGRAM)
#        IPPROTO_ICMP = socket.getprotobyname('ipv6-icmp')
#        self.create_socket(socket.AF_INET6, socket.SOCK_RAW, IPPROTO_ICMP)

        self.bind(address)
        self.address = self.socket.getsockname()
        self.logger.debug('%s binding to %s', self.returnNowTime(), self.address)
        self.listen(1)
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
    
    
    def handle_read(self):
        """Read an incoming message from the client and put it into our outgoing queue."""
        data = self.recv(self.chunk_size)
        self.logger.debug('%s handle_read() -> (%d) "%s"', self.returnNowTime(), len(data), data)
        self.data_to_write.insert(0, data)
    

    def handle_close(self):
        self.logger.debug('%s handle_close()', self.returnNowTime())
        self.close()
        return

    def handle_error(self):
        self.logger.debug('%s handle_error()', self.returnNowTime())
        self.handle_close()
        return

    def returnNowTime(self):
        return str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100))


class EchoHandler(asyncore.dispatcher):
    """Handles echoing messages from a single client.
    """
    
    def __init__(self, sock, chunk_size=1024):
        self.chunk_size = chunk_size
        self.logger = logging.getLogger('ReceiveHandler%s' % str(sock.getsockname()))
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


if __name__ == '__main__':
    import socket

    logging.basicConfig(level=logging.DEBUG,
                        format='%(name)s: %(message)s',
                        )

#    address = ('10.0.0.2', 12345) # ipv4
    address = ('fd0b:2fa4:a373:0:200:ff:fe00:2', 12345, 0, 0) # ipv6
    server = EchoServer(address)
#    ip, port = server.address # ipv4
    ip, port, flowinfo, scopeid = server.address # ipv6

#    client = EchoClient(ip, port, message="********SEND MESSAGE********")

    asyncore.loop()


