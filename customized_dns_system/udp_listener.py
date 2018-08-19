import socket
import socketserver
import struct
import sys
import threading

import MySQLdb
import _mysql_exceptions
import scapy.all as network

from twisted.python   import log

from listener import DNSListener
from config   import *

log.startLogging(sys.stdout)

class UDPBasedDNSHandler(socketserver.BaseRequestHandler):

    def __write_to_database(self, info:{
        "session_id"   : str,
        "ipaddress"    : str,
        "does_support" : str,
        "bufsize"      : int
    }) -> None:

        connection = MySQLdb.connect(
                "localhost", 
                "root", 
                "", 
                "dns_scan_records"
            )
        cursor = connection.cursor()

        command = '''
        INSERT INTO udp_server_side_record
        (session_id, questioner_ip,  declare_support_edns0, edns0_bufsize)
        VALUES
        ("{session_id}", "{ipaddress}", {does_support}, {bufsize})
        '''.format(**info)

        ######################
        # Think Carefully!!! #
        ######################
        update_op = '''
        UPDATE udp_server_side_record
        SET  
        session_id="{session_id}", 
        questioner_ip="{ipaddress}",
        declare_support_edns0={does_support},
        edns0_bufsize={bufsize}
        WHERE
        session_id="{session_id}"
        '''.format(**info)

        try:
            cursor.execute(command)
        except _mysql_exceptions.IntegrityError:
            cursor.execute(update_op)
        finally:
            connection.commit()
            cursor.close()
            connection.close()

    def handle(self) -> None:
        data = self.request[0].strip()
        sock = self.request[1]

        source_metadata = DNSListener.read_packet_info(data)

        if source_metadata:
            response = DNSListener.make_response(
                source_metadata["Transaction ID"],
                source_metadata["Question"],
                size=SHORT_RESPONSE_SIZE
            )

            str_question = source_metadata["Question"].decode()

            if str_question.startswith("0x"):
                session_id = str_question.split(".")[0]
                self.__write_to_database(
                    {
                        "session_id"  : session_id,
                        "ipaddress"   : self.client_address[0],
                        "does_support": source_metadata["Support EDNS0"],
                        "bufsize"     : source_metadata["EDNS0 Bufsize"]
                    }
                )

            if str_question.startswith("jumbo"):
                response[network.DNS].tc = int(TRUNCATE_TRICKING)
        
            print(
                "Send (ID:{id}) Response of <{question}> to {dest}".format(
                    id=source_metadata["Transaction ID"],
                    question=source_metadata["Question"],
                    dest=self.client_address[0]
                )
            )
            sock.sendto(bytes(response), self.client_address)

    
class UDPListener(object):

    def run(self):
        print("Starting DNS server (with UDP) @ {}:{}".format(HOSTNAME, DNS_PORT))

        server = socketserver.ThreadingUDPServer(
            (HOSTNAME, DNS_PORT), 
            UDPBasedDNSHandler,
            bind_and_activate=False)

        server.socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_RCVBUF,
            212992
        )
        server.server_bind()
        # server.server_activate()

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass

        server.server_close()
        print("DNS server (with UDP) @ {}:{} Exits".format(HOSTNAME, DNS_PORT))