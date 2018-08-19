import ipaddress


def _test_address_filter():
    while True:
        address = input("Input An Address:")
        try:
            address = ipaddress.IPv4Address(address)
            print("It {} a valid address".format(
                "is" if _is_valid_address(int(address)) else "is NOT"
                ))
        except:
            pass
        
def _is_valid_address(int_address:int) -> bool:
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

if __name__ == "__main__":
    _test_address_filter()

