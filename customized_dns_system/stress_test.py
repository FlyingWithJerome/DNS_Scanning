import random
import socket
import struct
import threading
import time

import scapy.all as network
import numpy.random

def dns_request_factory(id_num):
    packet = network.DNS(
        id=random.randrange(0, 65536, 1),
        rd=1,
        qdcount=1,
        qd=network.DNSQR(qname=str(id_num) + ".yumi.ipl.eecs.case.edu") 
    )
    return bytes(packet) 

class StressTest(object):

    def __init__(self, qps=1000, time_elapse=10):
        self.__qps  = qps
        self.__time = time_elapse

        self.__time_statistic = []
        self.__failed         = 0
        numpy.random.seed(12345)
        random.seed(12345)

    def start_test(self):
        workers = []
        for worker in range(self.__qps):
            t = threading.Thread(
                target=self.pressure_task,
                args=(worker,)
            )
            t.start()
            workers.append(t)

        for worker in workers:
            worker.join()

    def pressure_task(self, serial_num):
        time_consumed = 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            while time_consumed < self.__time:
                packet = dns_request_factory(serial_num)
                sock.sendto(packet, ("localhost", 53))
                start_time = time.time()

                response, (sip, sport) = sock.recvfrom(600)
                if sip == "127.0.0.1" and sport == 53:
                    try:
                        parsed_response = network.DNS(response)
                        if parsed_response[network.DNSRR].rrname.decode().split(".")[0] == str(serial_num):
                            self.__time_statistic.append(time.time()-start_time)
                    except:
                        self.__failed += 1
                sleep_time = numpy.random.ranf()
                time.sleep(sleep_time)
                time_consumed += sleep_time

    def __del__(self):
        if self.__time_statistic:
            print("Avg Time Consumed: {:.3f}s".format(sum(self.__time_statistic)/len(self.__time_statistic)))
            print("Total Packet Sent:", len(self.__time_statistic))
            print("Number of Response loss:", self.__failed)

if __name__ == "__main__":
    p = StressTest()
    p.start_test()
