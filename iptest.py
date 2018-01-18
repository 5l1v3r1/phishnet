# test
import socket
from cymruwhois import Client

ip = socket.gethostbyname('lidabus.by')

lw_asn = [32244, 53824, 201682]
print(lw_asn)

c = Client()
r = c.lookup(ip)
print(ip)
print(r.asn)
if int(r.asn) in lw_asn:
    print('in liquidweb')
else:
    print('not in lw')
