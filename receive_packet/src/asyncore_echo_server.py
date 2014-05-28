# coding: utf-8
# http://ja.pymotw.com/2/asyncore/
import asyncore
import logging
from datetime import datetime

class EchoServer(asyncore.dispatcher):
    """Receives connections and establishes handlers for each client.
    """
    
    def __init__(self, address):
        self.logger = logging.getLogger('EchoServer')
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.bind(address)
        self.address = self.socket.getsockname()
        self.logger.debug('%s binding to %s', str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100)), self.address)
        self.listen(1)
        return

    def handle_accept(self):
        # クライアントがソケットへ接続したときに呼び出される
        client_info = self.accept()
        self.logger.debug('%s handle_accept() -> %s', str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100)), client_info[1])
        EchoHandler(sock=client_info[0])
        # 一度に一クライアントのみを扱うのでハンドラを設定したらクローズする
        # 普通はクローズせずにサーバは停止命令を受け取るか、永遠に実行される
        self.handle_close()
        return
    
    def handle_close(self):
        self.logger.debug('%s handle_close()', str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100)))
        self.close()
        return

class EchoHandler(asyncore.dispatcher):
    """Handles echoing messages from a single client.
    """
    
    def __init__(self, sock, chunk_size=256):
        self.chunk_size = chunk_size
        self.logger = logging.getLogger('EchoHandler%s' % str(sock.getsockname()))
        asyncore.dispatcher.__init__(self, sock=sock)
        self.data_to_write = []
        return
    
    def writable(self):
        """We want to write if we have received data."""
        response = bool(self.data_to_write)
        self.logger.debug('%s writable() -> %s', str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100)), response)
        return response
    
    def handle_write(self):
        """Write as much as possible of the most recent message we have received."""
        data = self.data_to_write.pop()
        sent = self.send(data[:self.chunk_size])
        if sent < len(data):
            remaining = data[sent:]
            self.data.to_write.append(remaining)
        self.logger.debug('%s handle_write() -> (%d) "%s"', str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100)), sent, data[:sent])
        if not self.writable():
            self.handle_close()

    def handle_read(self):
        """Read an incoming message from the client and put it into our outgoing queue."""
        data = self.recv(self.chunk_size)
        self.logger.debug('%s handle_read() -> (%d) "%s"', str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100)), len(data), data)
        self.data_to_write.insert(0, data)
    
    def handle_close(self):
        self.logger.debug('%s handle_close()', str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100)))
        self.close()


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
        self.create_socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.logger.debug('%s connecting to %s', str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100)), (host, port))
        self.connect((host, port))
        return
        
    def handle_connect(self):
        self.logger.debug('%s handle_connect()', str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100)))
    
    def handle_close(self):
        self.logger.debug('%s handle_close()', str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100)))
        self.close()
        received_message = ''.join(self.received_data)
        if received_message == self.message:
            self.logger.debug('%s RECEIVED COPY OF MESSAGE', str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100)))
        else:
            self.logger.debug('ERROR IN TRANSMISSION')
            self.logger.debug('EXPECTED "%s"', self.message)
            self.logger.debug('RECEIVED "%s"', received_message)
        return
    
    def writable(self):
        self.logger.debug('%s writable() -> %s', str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100)), bool(self.to_send))
        return bool(self.to_send)

    def handle_write(self):
        sent = self.send(self.to_send[:self.chunk_size])
        self.logger.debug('%s handle_write() -> (%d) "%s"', str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100)), sent, self.to_send[:sent])
        self.to_send = self.to_send[sent:]

    def handle_read(self):
        data = self.recv(self.chunk_size)
        self.logger.debug('%s handle_read() -> (%d) "%s"', str(datetime.now().strftime('%H:%M:%S.') + '%04d' % (datetime.now().microsecond // 100)), len(data), data)
        self.received_data.append(data)
        

if __name__ == '__main__':
    import socket

    logging.basicConfig(level=logging.DEBUG,
                        format='%(name)s: %(message)s',
                        )

#    address = ('localhost', 0) # カーネルにポート番号を割り当てさせる
    address = ('::1', 0) # カーネルにポート番号を割り当てさせる
    server = EchoServer(address)
#    ip, port = server.address # 与えられたポート番号を調べる
    ip, port, flowinfo, scopeid = server.address # 与えられたポート番号を調べる

#    client = EchoClient(ip, port, message=open('lorem.txt', 'r').read())
    client = EchoClient(ip, port, message="********SEND MESSAGE********")

    asyncore.loop()
