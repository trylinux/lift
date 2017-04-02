'''This module contains functions that test for DNS-related vulnerabilities.
'''
import time

import dns.resolver
import dns.exception


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
    try:
        print "Trying: ", dest_ip
        start = time.time()
        while time.time() < start + 3:
            myAnswers = myResolver.query("google.com", "A")
            if myAnswers:
                print dest_ip, " is vulnerable to DNS AMP"
                break
            else:
                print dest_ip, " is a nope"
                break
        else:
            print dest_ip, " is a nope"

    except KeyboardInterrupt:
        print "Quitting"
        sys.exit()

    except dns.exception.DNSException:
        print dest_ip, " is not vulnerable to DNS AMP"
