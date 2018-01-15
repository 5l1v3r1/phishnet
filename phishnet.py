#!/usr/bin/env python

import logging
import sys
import datetime
import certstream
import socket
from cymruwhois import Client


def in_network(domain):
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        ip = 'NULL'

    lw_asn = ['32244', '53824', '201682']
    c = Client()
    if ip == 'NULL':
        return False, ip

    r = c.lookup(ip)
    if r.asn in lw_asn:
        return True, ip
    else:
        return False, ip


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
            success, ip = in_network(domain)
            if success:
                sys.stdout.write(u"{} - {} {} (SAN: {})\n".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%s'), ip, domain, ", ".join(message['data']['leaf_cert']['all_domains'][1:])))
                sys.stdout.flush()
            


#logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

certstream.listen_for_events(print_callback)
