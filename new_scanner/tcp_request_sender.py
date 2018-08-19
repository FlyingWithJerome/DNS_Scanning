import concurrent.futures
import socket
import struct
import sys

import MySQLdb
import _mysql_exceptions
import scapy.all as network

from twisted.python import log

from config import *

ip_2_int = lambda ip: socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip)))[0])

class SQLInserter(object):

    def __init__(self):
        self.connection = MySQLdb.connect(
            "localhost", 
            "root", 
            "", 
            "dns_scan_records"
        )
        self.cursor = self.connection.cursor()
        self.connection.autocommit(True)

    def insert(self, data:{
        "session_id"   : str,
        "response_ip" : str,
        "TCP_status"  : str
    }) -> None:

        command = '''
        INSERT INTO tcp_scan_record
        (session_id, response_ip, TCP_status)
        VALUES
        ("{session_id}", "{response_ip}", "{TCP_status}")
        '''.format(**data)
        
        update = '''
        UPDATE tcp_scan_record SET
        session_id="{session_id}",
        response_ip="{response_ip}",
        TCP_status="{TCP_status}"
        WHERE
        session_id="{session_id}"
        '''.format(**data)

        try:
            self.cursor.execute(command)
        except _mysql_exceptions.IntegrityError:
            self.cursor.execute(update)

    def __del__(self):
        self.connection.close()


def mainloop(target):
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        # target    = get_target_from_SQL()
        SQL_agent = SQLInserter()

        job_queue = {
            executor.submit(process_one_ip_address, ip) : ip for (ip,) in target
        }

        for future in concurrent.futures.as_completed(job_queue):
            ip_address = job_queue[future]
            try:
                res = future.result()
                SQL_agent.insert(res)

            except Exception as exc:
                print('%r generated an exception: %s' % (ip_address, exc))
            else:
                print("{} had been done".format(ip_address))

    # process_one_ip_address("8.8.8.8")

def get_target_from_SQL(table_name="scanner_side_record") -> [str,]:
    connection = MySQLdb.connect(
        "localhost", 
        "root", 
        "", 
        "dns_scan_records"
    )
    cursor = connection.cursor()

    try:
        cursor.execute(
            ("SELECT response_ip FROM {} "
            "WHERE response_status='ok'".format(table_name))
        )
        data = cursor.fetchall()
        connection.close()
        return data

    except Exception as e:
        print(e)
        return None

def save_recv(sock:socket.socket) -> bytes:
    tcp_payload      = sock.recv(2000)
    if not tcp_payload:
        return None

    try:
        full_packet_size = struct.unpack("!H", tcp_payload[:2])[0]
    except struct.error:
        return None

    while len(tcp_payload) != full_packet_size + 2:
        new_payload = sock.recv(2000)

        if not new_payload:
            return None

        tcp_payload += new_payload

    return tcp_payload

def process_one_ip_address(ip_address:str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        try:
            sock.connect((ip_address, 53))
            raw_request = make_DNS_request(ip_address)

            sock.send(
                struct.pack("!H", len(raw_request)) + bytes(raw_request)
            )

            data = save_recv(sock)
            if data and len(data) > 0:
                status = check_DNS_response(
                    data[2:],
                    ip_address
                )
                return {
                    "session_id"  : hex(ip_2_int(ip_address)),
                    "response_ip" : ip_address,
                    "TCP_status"  : status
                }
            else:
                return {
                    "session_id"  : hex(ip_2_int(ip_address)),
                    "response_ip" : ip_address,
                    "TCP_status"  : "no legal data transfered"
                }

        except socket.timeout:
            return {
                "session_id"   : hex(ip_2_int(ip_address)),
                "response_ip" : ip_address,
                "TCP_status"  : "socket timeout"
            }
        except socket.error:
            return {
                "session_id"   : hex(ip_2_int(ip_address)),
                "response_ip" : ip_address,
                "TCP_status"  : "connection refused"
            }

def check_DNS_response(response:bytes, ip_address:str, number_of_entry=100) -> "status":
    readable_packet = network.DNS(response)

    if readable_packet.ancount != number_of_entry:
        return "TCP wrong number of records ({} entries)".format(readable_packet.ancount)
    else:
        answers = [readable_packet.an[index].rdata for index in range(number_of_entry)]
        names   = [readable_packet.an[index].rrname.decode() for index in range(number_of_entry)]
    
    if answers != ["192.168.0.{}".format(num) for num in range(number_of_entry)]:
        return "TCP wrong answer values"
    
    request_id   = hex(ip_2_int(ip_address))
    correct_name = "jumbo-" + request_id + QUESTION_ZONE

    if set(names) != {correct_name+".",}:
        return "TCP wrong name entries"

    return "TCP answer OK"

def make_DNS_request(ip_address:str) -> network.DNS:
    request_id    = hex(ip_2_int(ip_address))
    question_name = "jumbo-" + request_id + QUESTION_ZONE

    return network.DNS(
        rd=1,
        qdcount=1,
        qd=network.DNSQR(qname=question_name)
    )
        

if __name__ == "__main__":

    log.startLogging(sys.stdout)
    mainloop(get_target_from_SQL())

    # print(process_one_ip_address("8.8.8.8"))
