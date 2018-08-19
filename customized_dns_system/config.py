'''
Config.py

Manually config the behavior of the DNS system
'''

DNS_PORT       = 53 # The port # you want the system listens on
HOSTNAME       = "129.22.150.112" # The hostname you want the system listens on
ZONENAME       = "yumi.ipl.eecs.case.edu"
# HOSTNAME       = "127.0.0.1"
SELECT_TIMEOUT = 0.1 # The time interval the system queries the socket

# CNAME TRICKING:
# CNAME TRICKING will let the system first return a CNAME record 
# (and if the system requeries the CNAME) then a series of normal
# A records

# TRUNCATE TRICKING:
# TRUNCATE TRICKING will let the system respond with a truncated flag
# ("tc") in the UDP DNS response. This will usually cause a TCP fallback
CNAME_TRICKING    = False 
TRUNCATE_TRICKING = True

# LONG RESPONSE SIZE:
# The number of ENTRIES you want for a big response. This is usually used
# in TCP DNS

# SHORT RESPONSE SIZE:
# The number of ENTRIES you want for a short response. This is usually used
# in UDP DNS
LONG_RESPONSE_SIZE  = 100
SHORT_RESPONSE_SIZE = 1

# CNAME ITERATION:
# The number of CNAME requeries you want the resolvers do (to this system)
# E.g., If the value is set to 3, the system will return CNAME3-* to the 
# resolver; and when the resolver requeries the CNAME3-* the system returns
# CNAME2-*, etc. The ultimate A records will only be returned for CNAME0
CNAME_ITERATION = 0
