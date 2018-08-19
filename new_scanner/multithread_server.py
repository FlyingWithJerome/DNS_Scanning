import os
import selectors
import socket
import threading

from tcp_request_sender import mainloop

class TCPMeasurementQueue(object):

    def __init__(self, threshold=50):
        self.__cache = []
        self.__threshold = threshold

    def insert(self, addr):
        self.__cache.append((addr,))
        if len(self.__cache) == self.__threshold:
            mainloop(self.__cache)

        self.__cache.clear()

    def __del__(self):
        if self.__cache:
            mainloop(self.__cache)

class MultithreadedUDPServer(object):

    def __init__(self, server_address=("", 0), handler_class=None):
        self.__is_dead     = False

        self.socket = socket.socket(
            socket.AF_INET,
            self.SOCK_DGRAM
        )
        self.socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_RCVBUF,
            212992
        )
        self.socket.bind(server_addresss)

        self.__thread_nest = []

        self.__backend = TCPMeasurementQueue()

    def mainloop(self):
        with selectors.PollSelector() as server_selector:
            server_selector.register(self.socket, selectors.EVENT_READ) 

            try:
                while not self.__is_dead:
                    status = server_selector.select(.5)
                    if status:
                        self.__handle_incoming_request()
            
            finally:
                self.commit_suicide()

    def __handle_incoming_request(self):
        incoming_data, addr = self.socket.recvfrom(4096)
        thread_worker = threading.Thread(
            target=self.__handle_request_atomic,
            args=(incoming_data, addr)
        )
        self.__thread_nest.append(thread_worker)
        thread_worker.start()

    def __handle_request_atomic(self, data, addr):
        self.handler_class(data, addr, self.__backend)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.commit_suicide()

    def commit_suicide(self):
        if not self.__is_dead:
            self.socket.close()
            if self.__thread_nest:
                for thread in self.__thread_nest:
                    thread.join()

            self.__is_dead = True

    def __del__(self):
        self.commit_suicide()

