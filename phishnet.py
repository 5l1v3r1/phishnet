#!/usr/bin/env python

import logging
import sys
import datetime
import certstream
import socket
import re
import entropy
import pygeoip
import time
import tqdm
from Levenshtein import distance
from tld import get_tld
from cymruwhois import Client

from suspicious import keywords, tlds


pbar = tqdm.tqdm(desc='certificate_update', unit='cert')

logFile = 'info.log'

# creating logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
log_formatter = logging.Formatter('[%(levelname)s:%(name)s] %(asctime)s - %(message)s', '%Y-%m-%d %H:%M:%S')
log_handler = logging.FileHandler(logFile)
log_handler.setFormatter(log_formatter)
logger.addHandler(log_handler)
# setting false so no output to console
logger.propagate = False


def score_domain(domain):
    score = 0
    for tld in tlds:
        if domain.endswith(tld):
            score += 20

    # for wildcard certs, remove *.
    if domain.startswith('*.'):
        domain = domain[2:]

    try:
        res = get_tld(domain, as_object=True, fail_silentyl=True, fix_protocol=True)
        domain = '.'.join([res.subdomain, res.domain])
    except:
        pass
    
    words_in_domain = re.split("\W+", domain)


    # for wildcard certs, remove *.
    if domain.startswith('*.'):
        domain = domain[2:]
        if words_in_domain[0] in ['com', 'net', 'org']:
            score += 10

    for word in keywords.keys():
        if word in domain:
            score += keywords[word]

    score += int(round(entropy.shannon_entropy(domain)*50))

    for key in [k for (k,s) in keywords.items() if s >= 70]:
        for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
            if distance(str(word), str(key)) == 1:
                score += 70

    if 'xn--' not in domain and domain.count('-') >= 4:
        score += domain.count('-') * 3

    if domain.count('.') >= 3:
        score += domain.count('.') * 3

    return score


# check if domain is inside lw's network
def in_network(domain):
    lw_asn = ['AS32244', 'AS53824', 'AS201682']
    success = False
    ip = 'None'
#
#    # removes wildcard cert
#    if domain.startswith('*.'):
#        domain = domain[2:]
#
#    try:
#        # gets the ip
#        ip = socket.gethostbyname(domain)
#    # if domain doesn't return an ip
#    except socket.gaierror:
#        ip = 'NULL'
#    else:
#        c = Client()
#        r = c.lookup(ip)
#        if r.asn in lw_asn:
#            success = True
#
#    return success, ip, domain
    asn_data = pygeoip.GeoIP('GeoIPASNum.dat')
    if domain.startswith('*.'):
        domain = domain[2:]

    try:
        asn_lookup = asn_data.org_by_name(domain)
    except socket.gaierror:
        pass
    else:
        if asn_lookup is not None:
            asn = asn_lookup.split()
            if asn[0] in lw_asn:
                ip = socket.gethostbyname(domain)
                success = True

    return success, ip, domain


def print_callback(message, context):
    if message['message_type'] == 'heartbeat':
        return

    if message['message_type'] == 'certificate_update':
        all_domains = message['data']['leaf_cert']['all_domains']

#        all_domains = ['asdfsdflkewlwejdie.com', '*.positiveaddictionsupport.tk', 'googlebizlist.com', 'www.googletagtv.com', 'cpanel.gmailsecurelogin.com', 'www.account-managed.gq', 'portal-ssl1106-5.bmix-dal-yp-442e830e-1b19-4c1b-982e-a02392f87053.oliver-gibson-uk-ibm-com.composedb.com', 'security-support.cf', 'kayseriturkoloji.com', 'kariyererzincan.com', 'kayseriturkoloji.com', 'limited.paypal.com.issues.janetdutson.com', 'viajestandem.com', 'hjinternationals.com', 'www.greenhillsadoptionsupportservices.com']

        pbar.update(1)

        # finds ip on first domain, avoids lookup on all SAN
        if len(all_domains) == 0:
            domain = 'NULL'
        else:
            first_domain = all_domains[0]
            success, ip, first_domain = in_network(first_domain)

        # if domain is inside lw
        if success:
            # puts ip, domain, SAN all inside a list
            domain_list = list()
            domain_list.append(ip)
            # finds score for all domain including SAN
            for domain in all_domains:
                score = score_domain(domain.lower())
                if "Let's Encrypt" in message['data']['chain'][0]['subject']['aggregated']:
                    score += 10
                
                domain_list.append(domain)
                domain_list.append(str(score))

            # this makes output to log pretty, for SAN. {domain score} instead
            # of {domain, score}
            san_list = [ ' '.join(x) for x in zip(domain_list[3::2], domain_list[4::2])]
            # only log if score is above 60
            if score >= 60:
                logger.info(u'{} {} (SAN: {})\n'.format(ip, ' '.join(domain_list[1:3]), ', '.join(san_list)))

        # need to figure out a way to avoid the timeout. output from certstream
        # is too fast for the in_network to handle, I think?
        # time.sleep(1)

#                sys.stdout.write(u"{} - {} {} (SAN: {})\n".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M'), ip, domain, ", ".join(message['data']['leaf_cert']['all_domains'][1:])))
#                sys.stdout.flush()

certstream.listen_for_events(print_callback)
