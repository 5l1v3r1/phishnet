#!/usr/bin/env python

import logging
import sys
import datetime
import certstream
import socket
from cymruwhois import Client


def in_network(ip):
    lw_asn = ['32244', '53824', '201682']
    c = Client()
    r = c.lookup(ip)
    if r.asn in lw_asn:
        return True
    else:
        return False


def print_callback(message, context):
    logging.debug("Message -> {}".format(message))

    if message['message_type'] == 'heartbeat':
        return

    if message['message_type'] == 'certificate_update':
        all_domains = message['data']['leaf_cert']['all_domains']
#        print(all_domains)

        if len(all_domains) == 0:
            domain = 'NULL'
        else:
            domain = all_domains[0]
            try:
                ip = socket.gethostbyname(domain)
                if in_network(ip):
                    sys.stdout.write(u"{} - {} {} (SAN: {})\n".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%s'), ip, domain, ", ".join(message['data']['leaf_cert']['all_domains'][1:])))
                    sys.stdout.flush()
            except socket.gaierror:
                ip = 'NULL'
            


#logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

certstream.listen_for_events(print_callback)
