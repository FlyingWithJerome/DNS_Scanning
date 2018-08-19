'''
Manager.py

Manager launches (and kills) the TCP and UDP Listener
'''

import multiprocessing
import os
import signal

from udp_listener import UDPListener
from tcp_listener import TCPListener

class Manager(object):

    def __init__(self):
        self.__udp_handler = UDPListener()
        self.__tcp_handler = TCPListener()

        self.__udp_process = multiprocessing.Process(target=self.__udp_handler.run)
        self.__tcp_process = multiprocessing.Process(target=self.__tcp_handler.run)

    
    def run(self):
        self.__udp_process.start()
        self.__tcp_process.start()

        self.__udp_process.join()
        self.__tcp_process.join()

    def __del__(self):
        try:
            if self.__udp_process.pid and self.__tcp_process.pid:
                os.kill(self.__udp_process.pid, signal.SIGINT)
                os.kill(self.__tcp_process.pid, signal.SIGINT)

        except OSError as oserror:
            print("Error when killing processes", oserror)

if __name__ == "__main__":
    m = Manager()
    m.run()
