import socket
import ipaddress
import subprocess
import struct
import sys
import random

SKIP_LIST = [int(ipaddress.IPv4Address("0.0.0.0")),
        range(int(ipaddress.IPv4Address("192.168.0.1")),int(ipaddress.IPv4Address("192.168.255.255"))),
        int(ipaddress.IPv4Address("127.0.0.1"))]

def make_query_name(questionWebsite):
    output = "";
    this_piece = "";
    length = len(questionWebsite);
    count = 0;i = 0;
    while(length>i):
        if(questionWebsite[i]=='.'):
            output += chr(count);
            output += this_piece;
            this_piece = "";
            count = 0;
            i += 1;
        else:
            this_piece += questionWebsite[i];
            count += 1;
            i += 1;
    output += chr(count);
    output += this_piece;
    output += chr(0);
    return output;


def make_dns_packet(questionWebsite):
    '''
    make a customize udp packet (for dns query, carries a message to
    system admins)
    '''
    message = "Tell me, senpai!\0"
    message = bytes(message, "ASCII")

    transaction_id = random.randint(0,65535) # 2 byte short
    control        = 0x0100
    q_counts       = 0x0001
    ans_counts     = 0x0000
    auth_counts    = 0x0000
    add_counts     = 0x0000 # 2 byte short
    type_          = 0x0001 # 2 byte short (A)
    class_         = 0x0001 # 2 byte short (IN)

    query_website  = bytes(make_query_name(questionWebsite), "ASCII");
    # format_= "!HH4H%ds2H%ds"%(len(query_website), len(message))

    header = struct.pack("!6H", transaction_id, control, q_counts, ans_counts, auth_counts, add_counts)

    question_section = struct.pack("!%ds2H"%len(query_website), query_website, type_, class_)

    return header + question_section

def class_reader(Class):
    types=  {0:'Reserved',1:'IN',3:'CH',4:'HS',
            254:'None',255:'Any'};
    return types.get(Class,'UNKNOWN');

def type_reader(Type):
    types=  {1:'A',2:'NS',3:'MD',4:'MF',
            5:'CNAME',6:'SOA',7:'MB',8:'MG',
            9:'MR',10:'NULL',11:'WKS',12:'PTR',
            13:'HINFO',14:'MINFO',15:'MX',16:'TXT',
            17:'RP',18:'AFSDB',19:'X25',20:'ISDN',
            21:'RT',22:'NSAP',23:'NSAP-PTR',24:'SIG',
            25:'KEY',26:'PX',27:'GPOS',28:'AAAA',
            29:'LOC',30:'NXT',31:'EID',32:'EID or NB',
            33:'SRV or NBSTAT',34:'ATMA',35:'NAPTR',36:'KX',
            37:'CERT',38:'A6',39:'DNAME',40:'SINK',
            41:'OPT',42:'APL',43:'DS',44:'SSHFP',
            45:'IPSECKEY',46:'RRSIG',47:'NSEC',48:'DNSKEY',
            49:'DHCID',50:'NSEC3',51:'NSEC3PARAM',52:'TLSA',
            55:'HIP',56:'NINFO',57:'RKEY',58:'TALINK',
            59:'Child DS',99:'SPF',100:'UNIFO',101:'UID',
            102:'GID',249:'TKEY',250:'TSIG',251:'IXFR',
            252:'AXFR',253:'MAILB',254:'MAILA',255:'*',
            256:'URI',257:'CAA',32768:'DNSSEC Trust Authorities',32769:'DNSSEC Lookaside Validation'};
    return types.get(Type,'UNKNOWN');

def opcode_reader(opcode):
    types=  {0:'QUERY',1:'IQUERY',2:'STATUS',4:'Notify',5:'Update'};
    return types.get(opcode,'UNKNOWN');

def rcode_reader(rcode):
    types=  {0:'No Error',1:'Format Error',2:'Server Failure',3:'Name Error',
            4:'Not Implemented',5:'Refused',6:'YXDomain',7:'YXRRSet',
            8:'NXRRSet',9:'NotAuth',10:'NotZone'};
    return types.get(rcode,'UNKNOWN');

def read_pointer_from_offset(packet,offset):
    digit = struct.unpack_from("!B",packet,offset)[0];
    offset += 1;
    web_name = "";
    while(digit):
        web_name += struct.unpack_from("!c",packet,offset)[0].decode('ascii');
        offset += 1;
        digit -= 1;
        if(digit==0):
            digit = struct.unpack_from("!B",packet,offset)[0];
            offset += 1;
            if(digit!=0):
                web_name += '.'
    return web_name;

def read_dns_response(packet):
    packet_info = {}
    offset = 0

    # Read transaction ID
    temp = struct.unpack_from("!2B",packet,offset);
    packet_info['TransactionID'] = hex(temp[0]<<8|temp[1])
    offset += 2;

    # Read the flags 
    temp = struct.unpack_from("!2B",packet,offset);
    flag = temp[0]<<8|temp[1]
    offset += 2;
    QR = bool(flag>>15)
    if(QR):
        packet_info['QR'] = 'Response';
    else:
        packet_info['QR'] = 'Query';
    packet_info['OpCode'] = opcode_reader((flag>>11) & 0x0f)
    packet_info['AA'] = bool(flag>>10 & 0x01)
    packet_info['TC'] = bool(flag>>9  & 0x01)
    packet_info['RD'] = bool(flag>>8  & 0x01)
    packet_info['RA'] = bool(flag>>7  & 0x01)
    packet_info['Z']  = bool(flag>>6  & 0x01)
    packet_info['AD'] = bool(flag>>5  & 0x01)
    packet_info['CD'] = bool(flag>>4  & 0x01)
    packet_info['RCode']  = rcode_reader((flag>>0) & 0x0f)

    # Read the number of Questions
    temp = struct.unpack_from("!2B",packet,offset);
    count_of_questions = temp[0]<<8|temp[1]
    offset += 2;
    packet_info['Questions'] = count_of_questions;

    # Read the number of Answer RRs
    temp = struct.unpack_from("!2B",packet,offset);
    count_of_answer_RR = temp[0]<<8|temp[1]
    offset += 2;
    packet_info['AnswerRR'] = count_of_answer_RR;

    # Read the number of Authority RRs
    temp = struct.unpack_from("!2B",packet,offset);
    count_of_authority_RR = temp[0]<<8|temp[1]
    offset += 2;
    packet_info['AuthorityRR'] = count_of_authority_RR;

    # Read the number of Additional RRs
    temp = struct.unpack_from("!2B",packet,offset);
    count_of_additional_RR = temp[0]<<8|temp[1]
    offset += 2;
    packet_info['AdditionalRR'] = count_of_additional_RR;

    # Read Queries
    Queries = [[]for i in range(count_of_questions)]
    for i in range(0,count_of_questions):
        digit = struct.unpack_from("!B",packet,offset)[0];
        offset += 1;
        web_name = "";
        while(digit):
            web_name += struct.unpack_from("!c",packet,offset)[0].decode('ascii');
            offset += 1;
            digit -= 1;
            if(digit==0):
                digit = struct.unpack_from("!B",packet,offset)[0];
                offset += 1;
                if(digit!=0):
                    web_name += '.'

        temp = struct.unpack_from("!2B",packet,offset);
        offset += 2;
        Type = temp[0]<<8|temp[1];
        Type = type_reader(Type);
        temp = struct.unpack_from("!2B",packet,offset);
        offset += 2;
        Class = temp[0]<<8|temp[1];
        Class = class_reader(Class);
        Queries[i].append(web_name);
        Queries[i].append(Type);
        Queries[i].append(Class);
    packet_info['Queries'] = Queries;

    # Read Answers
    Answers = [[]for i in range(count_of_answer_RR)];
    for i in range(0,count_of_answer_RR):
        #digit = struct.unpack_from("!B",packet,offset)[0];
        digit = int.from_bytes(struct.unpack_from("!c",packet,offset)[0],byteorder='little',signed=False);
        current_byte = digit;
        web_name = "";
        offset += 1;
        while(digit): # Could be \0xc0
            if(current_byte>>4 == 12):# Identifies a pointer
                temp = struct.unpack_from("!2B",packet,offset-1);
                temp_offset = (temp[0]&0x0f)<<8|temp[1];
                try:
                    web_name += read_pointer_from_offset(packet,temp_offset);
                    packet_info["Pointer"] = "Pointer OK"
                except struct.error:
                    packet_info["Pointer"] = "Pointer ERROR"
                offset += 1;
                break;# Break when finished dealing with pointer
            else:# Not a pointer
                web_name += struct.unpack_from("!c",packet,offset)[0].decode('ascii');

            offset += 1;
            digit -= 1; #
            if(digit==0):
                digit = struct.unpack_from("!B",packet,offset)[0];
                offset += 1;
                if(digit!=0):
                    web_name += '.'

            current_byte = int.from_bytes(struct.unpack_from("!c",packet,offset)[0],byteorder='little',signed=False);
        IsAType = False;
        IsAAAAType = False;
        temp = struct.unpack_from("!2B",packet,offset);
        offset += 2;
        Type = temp[0]<<8|temp[1];
        Type = type_reader(Type);
        if(Type=='A'):
            IsAType = True;
        temp = struct.unpack_from("!2B",packet,offset);
        offset += 2;
        Class = temp[0]<<8|temp[1];
        Class = class_reader(Class);
        temp = struct.unpack_from("!4B",packet,offset);
        offset += 4;
        TTL = (temp[0]<<24|temp[1]<<16|temp[2]<<8|temp[3]);
        temp = struct.unpack_from("!2B",packet,offset);
        offset += 2;
        DataLength = temp[0]<<8|temp[1];
        Address = "";
        if(IsAType):#IPv4
            for j in range(0,DataLength):
                temp = struct.unpack_from("!B",packet,offset)[0];
                offset += 1;
                Address += str(temp);
                if(j!=(DataLength-1)):
                    Address += '.';
        elif(IsAAAAType):#IPv6
            for j in range(0,DataLength):
                temp = struct.unpack_from("!2B",packet,offset);
                offset += 2;
                Address += hex(temp[0]);
                Address += hex(temp[1]);
                if(j!=(DataLength-1)):
                    Address += ':';
        Answers[i].append(web_name);
        Answers[i].append(Type);
        Answers[i].append(Class);
        Answers[i].append(TTL);
        Answers[i].append(Address);
    packet_info['Answers']=Answers;
    return packet_info;





def make_datagram_sockets() -> (socket.socket, socket.socket):
    '''
    make a pair of udp socket with our options
    1. send dns queries
    2. listen responses. 
    '''
    send_socket_instance = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) # Produce a UDP DGRAM socket
    recv_socket_instance = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) # Produce a UDP DGRAM socket
    # send_socket_instance.setsockopt(socket.IPPROTO_IP, socket.IP_TTL,     255) # Set the TTL to 255

    return send_socket_instance, recv_socket_instance



def listen_and_check_response(in_socket: socket.socket, out_socket: socket.socket, packet, ip_address:ipaddress.IPv4Address) -> bool:
    '''
    listen to the server side response and check whether it is a legal &
    valid response
    '''
    pass

def multiprocess_scan(start_ip:int, end_ip:int, process_num:int) -> None:
    '''
    scan the IPv4 address space from [start_ip] to [end_ip]
    with [process_num] of processes simultaneously
    '''
    pass


#====================== Private Methods ====================================

def _check_skip_policy(ip_address:int) -> bool:
    pass




#16777217
def main() -> None:

    out_sock, in_sock = make_datagram_sockets()

    out_sock.bind(('', 1053))

    packet = make_dns_packet("case.edu")

    out_sock.sendto(packet,("18.194.101.249",53))
    data,addr = out_sock.recvfrom(1024);
    print(read_dns_response(data));

if __name__ == "__main__":
    main()

