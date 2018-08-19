'''
UDPListener.py

The UDPListener module captures all the UDP inbound traffic 
from port 53
'''
import asyncio
import select
import socket
import struct
import sys

import scapy.all as network
from twisted.python import log

from Listener import DNSListener
from config   import *

log.startLogging(sys.stdout)

class UDPListener(DNSListener):

    def __init__(self):

        DNSListener.__init__(self)

        self.__prepare_all_sockets()

        print(socket.gethostname())
        # self.__master_socket = socket.socket(
        #     socket.AF_INET,
        #     socket.SOCK_DGRAM,
        # )
        # self.__master_socket.setblocking(0)
        # self.__master_socket.bind((HOSTNAME, DNS_PORT))

        # self.__backup_socket

    def __prepare_all_sockets(self):
        self.__socket_group = []
        
        for hostnames in HOSTNAME:
            socket_member = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_UDP
            )
            socket_member.setblocking(0)
            socket_member.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            if hostnames["Device"]:
                socket_member.setsockopt(socket.SOL_SOCKET, 
                socket.SO_BINDTODEVICE, 
                str(hostnames["Device"] + "\0").encode("utf-8"))

            try:
                socket_member.bind((hostnames["IP"], DNS_PORT))
            except:
                print("Problem binding to", (hostnames["IP"], DNS_PORT))

            self.__socket_group.append(socket_member)

    @asyncio.coroutine
    def handling_process(self):
        while True:
            try:
                read, *_         = select.select(self.__socket_group, [], [])
                if not read:
                    raise ValueError
                data               = read[0].recv(600)
                ip_header          = struct.unpack("!BBHHHBBHII", data[:20])

                sip = socket.inet_ntoa(struct.pack("!I", ip_header[8]))
                dip = socket.inet_ntoa(struct.pack("!I", ip_header[9]))

                udp_header = struct.unpack("!4H", data[20:28])
                sport      = udp_header[0]
                dport      = udp_header[1]

                if dport == 53:
                    print(sip, "--->", dip)
                    source_metadata    = UDPListener.read_packet_info(data[28:])

                    if source_metadata:
                        response = UDPListener.make_response(
                            source_metadata["Transaction ID"],
                            source_metadata["Question"],
                            size=SHORT_RESPONSE_SIZE
                        )

                        response[network.DNS].tc = int(TRUNCATE_TRICKING)
                        # print("======================= Response =======================")
                        if "yumi" in source_metadata["Question"].decode():
                            print("Transcation ID:", source_metadata["Transaction ID"])
                        # print("======================= Response ENDS =======================")

                        udp_payload         = bytes(response)
                        udp_response_header = struct.pack("!4H",
                        53, 
                        sport, 
                        len(udp_payload) , 
                        0)

                        print("sending to", sip, sport)
                        
                        for members in self.__socket_group:
                            try:
                                members.sendto(udp_response_header + udp_payload, (sip, sport))
                                print("Packets to", sip, "sent")
                            except OSError as oserr:
                                print(oserr)
                                

            except ValueError:
                pass

            except KeyboardInterrupt:
                break

    def run(self):
        job_loop = asyncio.get_event_loop()
        job_loop.run_until_complete(self.handling_process())

        try:
            job_loop.run_forever()
        except KeyboardInterrupt:
            pass

        job_loop.close() 

    def __del__(self):
        print("UDP Listener Exiting")
        for members in self.__socket_group:
            members.close()


if __name__ == "__main__":

    listener = UDPListener()
    listener.run()


