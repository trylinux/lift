'''This module contains functions that test for DNS-related vulnerabilities.
'''
import logging
import time
import sys

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)


def recurse_DNS_check(options):
    '''Check whether the device, indicated by the given IP address, is
    is vulnerable to DNS amplication.

    Returns: dns.resolver.Answer instance

    Raises:
        Timeout - if no answers could be found in the specified lifetime
        NXDOMAIN - if the query name does not exist
        YXDOMAIN - if the query name is too long after DNAME substitution
        NoAnswer - if the response did not contain an answer and
            raise_on_no_answer is True.
        NoNameservers - if no non-broken nameservers are available to answer
            the question.
    '''
    dest_ip = str(options['ip'])
    myResolver = dns.resolver.Resolver()
    myResolver.nameservers = [dest_ip]
    logging.info("Checking %s for a DNS amplification vulnerabilty" % dest_ip)
    start = time.time()
    try:
        while time.time() < start + 3:
            myAnswers = myResolver.query("google.com", "A")
            if myAnswers:
                logging.info("%s is vulnerable to DNS AMP" % dest_ip)
                break
            else:
                logging.info("%s is not vulnerable to DNS AMP" % dest_ip)
                break
        else:
            logging.info("%s is not vulnerable to DNS AMP" % dest_ip)

    except KeyboardInterrupt:
        logging.error("KeyboardInterrupt. Quitting")
        sys.exit()

    except dns.exception.DNSException as e:
        logging.info("%s is not vulnerable to DNS AMP" % dest_ip)
        logging.debug(str(e))
