import asyncio
import socket
import socketserver
import struct
import sys
import time

import MySQLdb
import _mysql_exceptions
import scapy.all as network

from DBUtils.PooledDB import PooledDB
from twisted.python import log

from config import *
from multithread_server import MultithreadedUDPServer

log.startLogging(sys.stdout)

_STATUS_CODE = {
    0: "ok", 
    1: "format-error", 
    2: "server-failure", 
    3: "name-error", 
    4: "not-implemented", 
    5: "refused"
    }

# class DNSResponseListenerHandler(object):

#     def __init__(self, data, addr, backend):
#         self.data = data
#         self.client_address = addr
#         self.backend        = backend

class DNSResponseListenerHandler(socketserver.BaseRequestHandler):
    
    def __write_to_database(self, info:{
        "session_id"    : str,
        "ip_address"    : str,
        "status"        : str,
        "response_time" : float
    }) -> None:

        connection = MySQLdb.connect(
                "localhost", 
                "root", 
                "", 
                "dns_scan_records"
            )
        cursor  = connection.cursor()
        command = '''
        INSERT INTO scanner_side_record
        (session_id,  response_ip, response_status, response_time)
        VALUES
        (
            "{session_id}",
            "{ip_address}",
            "{status}",
            {response_time}
        )
        '''.format(**info)
        try:
            cursor.execute(command)
            connection.commit()
        except _mysql_exceptions.IntegrityError:
            pass
        finally:
            cursor.close()
            connection.close()            

    def handle(self) -> None:
        try:  
            # packet_content = network.DNS(self.data.strip())
            packet_content = network.DNS(self.request[0].strip())
            question_name  = packet_content[network.DNSQR].qname.decode()

            status_code = _STATUS_CODE.get(packet_content.rcode, "unknown status")

            question_id = question_name.split(".")[0]
            response_ip = self.client_address[0]

            if status_code == "ok" and packet_content.ancount > 0:
                answer     = packet_content[network.DNSRR].rdata == CORRECT_ANSWER
                statistics = {
                    "session_id"    : question_id,
                    "ip_address"    : response_ip,
                    "status"        : status_code if answer else "answer error",
                    "response_time" : time.time()
                }
                # if answer:
                #     self.backend.insert(response_ip)
            else:
                statistics = {
                    "session_id"    : question_id,
                    "ip_address"    : response_ip,
                    "status"        : status_code,
                    "response_time" : time.time()
                }
            self.__write_to_database(statistics)

        except:
            print("Has an Error (IP: {}) but handled".format(self.client_address[0]))

class DNSResponseListener(object):

    def run(self):
        print("Scanner Listener is Running")
        # with MultithreadedUDPServer(
        #     server_address=("0.0.0.0", LISTENER_PORT), 
        #     handler_class=DNSResponseListenerHandler) as server:

        #     server.mainloop()

        server = socketserver.ThreadingUDPServer(
            ("0.0.0.0", LISTENER_PORT), 
            DNSResponseListenerHandler,
            bind_and_activate=False)

        server.server_bind()
        server.server_activate()
        
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass

        server.server_close()
