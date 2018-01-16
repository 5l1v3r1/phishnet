#!/usr/bin/env python

import logging
import sys
import datetime
import certstream
import socket
from cymruwhois import Client


logFile = 'phishnet.info'

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
log_formatter = logging.Formatter('[%(levelname)s:%(name)s] %(asctime)s - %(message)s')
log_handler = logging.FileHandler(logFile)
log_handler.setFormatter(log_formatter)
logger.addHandler(log_handler)
logger.propagate = False


def in_network(domain):
    # for wildcard certs, remove *.
    if domain.startswith('*.'):
        domain = domain[2:]

    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        ip = 'NULL'
        return False, ip
    else:
        lw_asn = ['32244', '53824', '201682']
        c = Client()
        r = c.lookup(ip)
        if r.asn in lw_asn:
            return True, ip
        else:
            return False, ip


def print_callback(message, context):
#    logging.debug("Message -> {}".format(message))

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
            if not success:
                logger.info(u'{} {} (SAN: {})'.format(ip, domain, ', '.join(message['data']['leaf_cert']['all_domains'][1:])))
#                sys.stdout.write(u"{} - {} {} (SAN: {})\n".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M'), ip, domain, ", ".join(message['data']['leaf_cert']['all_domains'][1:])))
#                sys.stdout.flush()
            

certstream.listen_for_events(print_callback)
