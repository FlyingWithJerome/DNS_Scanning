'''
TCPListener.py

The TCPListener module captures all the TCP inbound traffic 
from port 53
'''
import socket
import socketserver
import struct
import sys

import MySQLdb
import _mysql_exceptions
import scapy.all as network

from DBUtils.PooledDB import PooledDB

from listener import DNSListener
from config   import *

def save_recv(sock:socket.socket) -> bytes:
    tcp_payload      = sock.recv(2000)
    if not tcp_payload:
        return None

    full_packet_size = struct.unpack("!H", tcp_payload[:2])[0]

    while len(tcp_payload) != full_packet_size + 2:
        new_payload = sock.recv(2000)

        if not new_payload:
            return None

        tcp_payload += new_payload

    return tcp_payload


class TCPBasedDNSHandler(socketserver.BaseRequestHandler):

    def __write_to_database(self, info:{
        "session_id"    : str,
        "questioner_ip" : str,
        "response_sent" : int
    }) -> None:

        connection = MySQLdb.connect(
                "localhost", 
                "root", 
                "", 
                "dns_scan_records"
            )
        cursor = connection.cursor()

        command = '''
        INSERT INTO tcp_server_side_record
        (session_id, questioner_ip, response_sent)
        VALUES
        ("{session_id}", "{questioner_ip}", {response_sent})
        '''.format(**info)

        ######################
        # Think Carefully!!! #
        ######################
        update_op = '''
        UPDATE tcp_server_side_record
        SET  
        session_id="{session_id}",
        questioner_ip="{questioner_ip}",
        response_sent={response_sent}
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

    def handle(self):
        question = save_recv(self.request)
        packet   = DNSListener.read_packet_info(question[2:])

        if "cname" in packet["Question"].decode() or not CNAME_TRICKING:
            response = DNSListener.make_response(
                packet["Transaction ID"],
                packet["Question"],
                size=LONG_RESPONSE_SIZE
            )

            source_ip     = self.client_address[0]
            question_name = packet["Question"].decode()

            if question_name.startswith("jumbo-"):
                session_id = question_name.split(".")[0].strip("jumbo-")

                self.__write_to_database(
                    {
                        "session_id"    : session_id,
                        "questioner_ip" : source_ip,
                        "response_sent" : 1
                    }
                )

        else:
            response = DNSListener.make_response(
                packet["Transaction ID"],
                packet["Question"],
                cname=True
            )

        self.request.send(struct.pack("!H", len(response)) + bytes(response))
        self.request.close()


class TCPListener(DNSListener):

    def run(self):
        print("Starting DNS server (with TCP) @ {}:{}".format(HOSTNAME, DNS_PORT))

        server = socketserver.ThreadingTCPServer(
            (HOSTNAME, DNS_PORT), 
            TCPBasedDNSHandler
        )

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass

        server.server_close()
        print("DNS server (with TCP) @ {}:{} Exits".format(HOSTNAME, DNS_PORT))


if __name__ == "__main__":
    t = TCPListener()
    t.run()
