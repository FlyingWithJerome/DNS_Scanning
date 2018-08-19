'''
Listener.py

The base listener
'''
import struct

import scapy.all as network

class DNSListener(object):

    def __init__(self):
        pass

    def run(self):
        pass

    @staticmethod
    def make_response(transaction_id:str, question_name:bytes, size=3, cname=False) -> network.DNS:
        if question_name == b"yumi.ipl.eecs.case.edu.":
            return network.DNS(
                id=transaction_id, 
                qr=1,
                aa=1,
                ra=1,
                qdcount=1,
                qd=network.DNSQR(qname=question_name), 
                ancount=1, 
                an=network.DNSRR(
                    rrname=question_name,
                    rdata="129.22.150.112"
                )
            )
        if cname:
            return network.DNS(
                id=transaction_id, 
                qr=1,
                aa=1,
                ra=1,
                qdcount=1,
                qd=network.DNSQR(qname=question_name), 
                ancount=1, 
                an=network.DNSRR(
                    rrname=question_name,
                    type=5, #CNAME
                    rdata="cname-"+question_name.decode()
                )
            )

        records     = ["192.168.0.{}".format(num) for num in range(size)]
        base_record = network.DNSRR(rrname=question_name, ttl=600, rdata=records[0])
        for resource_records in records[1:]:
            base_record /= network.DNSRR(rrname=question_name, ttl=600, rdata=resource_records)

        return network.DNS(
            id=transaction_id, 
            qr=1,
            aa=1,
            ra=1,
            qdcount=1,
            qd=network.DNSQR(qname=question_name), 
            ancount=len(records), 
            an=base_record
            )

    @staticmethod
    def read_packet_info(packet:bytes) -> {str:str}:
        packet_content = network.DNS(packet)

        try:
            # packet_content.show()
            trans_id = packet_content[network.DNS].id
            question = packet_content[network.DNS][network.DNSQR].qname

        except IndexError as e:
            print(e)
            return None

        ################# Below is for EDNS0 #################
        edns_support = packet_content[network.DNS].haslayer(network.DNSRROPT)
        edns_bufsize = -1

        if edns_support:
            edns_bufsize = packet_content[network.DNS][network.DNSRROPT].rclass

        return {
            "Transaction ID" : trans_id,
            "Question"       : question,
            "Support EDNS0"  : edns_support,
            "EDNS0 Bufsize"  : edns_bufsize
        }
