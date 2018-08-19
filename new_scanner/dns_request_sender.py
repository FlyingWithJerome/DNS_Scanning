import functools
import ipaddress
import multiprocessing
import random
import socket
import struct
import time

import scapy.all as network

from numpy.random import randint

from bloom_filter       import IntegerBloomFilter
from dns_request_packet import make_dns_packet
from config             import *

def with_udp_header(*, listener_port):
    def mid_level(generator):
        def inner(*args, **kwargs):
            udp_payload = generator(*args, **kwargs)

            return struct.pack("!4H",
                listener_port, 53, len(udp_payload) + 8, 0
                ) + udp_payload
        return inner 
    return mid_level

def _test_address_filter():
    while True:
        address = input("Input An Address:")
        try:
            address = ipaddress.IPv4Address(address)
            print("It {} a valid address".format(
                "is" if _is_valid_address(int(address)) else "isn't"
                ))
        except:
            pass
        
def _is_valid_address(int_address):
    return (
        #0.0.0.0/8, current network
        not (0          <= int_address <= 16777215)   and\
        #10.0.0.0/8, local communication
        not (167772160  <= int_address <= 184549375)  and\
        #100.64.0.0/10, shared space
        not (1681915904 <= int_address <= 1686110207) and\
        #127.0.0.0/8, loopback
        not (2130706432 <= int_address <= 2147483647) and\
        #169.254.0.0/16, link-local
        not (2851995648 <= int_address <= 2852061183) and\
        #172.16.0.0/12, private
        not (2886729728 <= int_address <= 2887778303) and\
        #192.0.0.0/24, IETF protocol assignment
        not (3221225472 <= int_address <= 3221225727) and\
        #192.0.2.0/24, TEST-NET-1
        not (3221225984 <= int_address <= 3221226239) and\
        #192.88.99.0/24, v6 to v4 relay
        not (3227017984 <= int_address <= 3227018239) and\
        #192.168.0.0/16, local communication
        not (3232235520 <= int_address <= 3232301055) and\
        #198.18.0.0/15, benchmarking
        not (3323068416 <= int_address <= 3323199487) and\
        #198.51.100.0/24, TEST-NET-2
        not (3325256704 <= int_address <= 3325256959) and\
        #203.0.113.0/24, TEST-NET-3
        not (3405803776 <= int_address <= 3405804031) and\
        #224.0.0.0/4, multicast
        not (3758096384 <= int_address <= 4026531839) and\
        #240.0.0.0/4, reserved
        not (4026531840 <= int_address <= 4294967295) and\
        #255.255.255.255, broadcast
        not (int_address == 4294967295)
    ) 

# def _test_is_valid_address(ip_address):
#     return ip_address.is_global

def _test_is_valid_address(ip_address):
    return (
        not ip_address.is_multicast   and\
        not ip_address.is_private     and\
        not ip_address.is_unspecified and\
        not ip_address.is_reserved    and\
        not ip_address.is_loopback    and\
        not ip_address.is_link_local
    )

def shuffle_ip_addresses(start_address:int, end_address:int) -> int:
    bloom_filter    = IntegerBloomFilter(end_address-start_address)
    number_launched = 0

    while number_launched < end_address-start_address:
        raw_num = randint(start_address, end_address)
        if not raw_num in bloom_filter:
            number_launched += 1
            bloom_filter.append(raw_num)

            yield raw_num


class DNSRequestSender(object):
    def __init__(self, start_address, end_address, serial_num):
        self.__start_address = start_address
        self.__end_address   = end_address
        self.__serial_num    = serial_num
        self.__address_range = range(start_address, end_address)

        self.__master_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_UDP
        )
        self.__master_socket.setblocking(0)

    def run(self):
        print("Sender #{} start.".format(self.__serial_num))
        for address in self.__address_range:
            if _is_valid_address(address):
                hostname = hex(address) + QUESTION_ZONE
                
                self.__master_socket.sendto(
                    DNSRequestSender.make_dns_request(hostname),
                    (socket.inet_ntoa(struct.pack("!I", address)), 53)
                )
        print("Sender #{} done.".format(self.__serial_num))

    
    @staticmethod
    @functools.lru_cache(maxsize=2560)
    @with_udp_header(listener_port=LISTENER_PORT)
    def make_dns_request(question_name):
        packet = make_dns_packet(question_name)
        return packet

    def __str__(self):
        real_start = ipaddress.IPv4Address(self.__start_address)
        real_end   = ipaddress.IPv4Address(self.__end_address - 1)

        return "Sender #{serial} Range From {start} to {end}".format(
            serial = self.__serial_num,
            start  = str(real_start),
            end    = str(real_end) 
        )

    def __del__(self):
        self.__master_socket.close()
        print("Sender #{serial} Exits.".format(
            serial=self.__serial_num
        )) 

if __name__ == "__main__":
    # start = time.time()
    # for i in range(100):
    #     pack = DNSRequestSender.make_dns_request(str(i) + QUESTION_ZONE)
    # print("Time Consumed: {:.4f}".format((time.time()-start)))

    # # iterate through all multicast address, should be all false
    # for address in ipaddress.IPv4Network("224.0.0.0/4"):
    #     assert not _is_valid_address(int(address)), "is a multicast address"

    # print("Successfully Shielded All Class D Addresses")


    # p = network.DNS(pack)
    # p.show()

    # start = time.time()
    # pack  = DNSRequestSender.make_dns_request("0xabcd.yumi.ipl.eecs.case.edu")
    # # print(len(pack))
    # print("Time Consumed: {:.4f}".format((time.time()-start)*1000))

    _test_address_filter()

    # start = time.time()
    # test = 2130706442
    # ip = ipaddress.IPv4Address(test)
    # _test_is_valid_address(ip)
    # str(ip)
    # print(time.time()-start)

    # start = time.time()
    # _is_valid_address(2130706442)
    # socket.inet_ntoa(struct.pack("!I", 2130706442))

    # print(time.time()-start)
