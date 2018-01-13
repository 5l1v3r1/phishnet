# test
import socket
from cymruwhois import Client

ip = socket.gethostbyname('nospaceindent.com')

c = Client()
r = c.lookup(ip)
print(r.asn)
