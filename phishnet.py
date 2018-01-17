#!/usr/bin/env python

import logging
import sys
import datetime
import certstream
import socket
import entropy
from Levenshtein import distance
from tld import get_tld
from cymruwhois import Client

from suspicious import keywords, tlds


logFile = 'info.log'

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
log_formatter = logging.Formatter('[%(levelname)s:%(name)s] %(asctime)s - %(message)s')
log_handler = logging.FileHandler(logFile)
log_handler.setFormatter(log_formatter)
logger.addHandler(log_handler)
logger.propagate = False


def score_domain(domain):
    score = 0
    for tld in tlds:
        if domain.endswith(tld):
            score += 20

    try:
        res = get_tld(domain, as_object=True, fail_silentyl=True, fix_protocol=True)
        domain = '.'.join([res.subdomain, res.domain])
    except:
        pass
    
    words_in_domain = re.split("\W+", domain)

    for word in keywords.keys():
        if word in domain:
            score += keywords[word]

    score += int(round(entropy.shannon_entropy(domain)*50))


def in_network(domain):
    lw_asn = ['32244', '53824', '201682']
    success = False

    # for wildcard certs, remove *.
    if domain.startswith('*.'):
        domain = domain[2:]

    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        ip = 'NULL'
    else:
        c = Client()
        r = c.lookup(ip) # causing error sometimes
        if r.asn in lw_asn:
            success = True

    return success, ip, domain


def print_callback(message, context):
#    logging.debug("Message -> {}".format(message))

    if message['message_type'] == 'heartbeat':
        return

    if message['message_type'] == 'certificate_update':
        all_domains = message['data']['leaf_cert']['all_domains']

        if len(all_domains) == 0:
            domain = 'NULL'
        else:
            domain = all_domains[0]
            success, ip, domain = in_network(domain)
            if success:
                logger.info(u'{} {} (SAN: {})'.format(ip, domain, ', '.join(message['data']['leaf_cert']['all_domains'][1:])))
#                sys.stdout.write(u"{} - {} {} (SAN: {})\n".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M'), ip, domain, ", ".join(message['data']['leaf_cert']['all_domains'][1:])))
#                sys.stdout.flush()
            

certstream.listen_for_events(print_callback)
