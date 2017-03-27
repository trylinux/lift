'''This module contains functions that test for DNS-related vulnerabilities.
'''
import dns.resolver
import time


def recurse_DNS_check(dest_ip, **kwargs):
    '''Check whether the device, indicated by the given IP address, is
    is vulnerable to DNS amplication.
    '''
    vbose = kwargs['verbose']
    myResolver = dns.resolver.Resolver()
    myResolver.nameservers = [str(dest_ip)]
    try:
        print "Trying: ", dest_ip
        start = time.time()
        while time.time() < start + 3:
            myAnswers = myResolver.query("google.com", "A")
            if myAnswers:
                print dest_ip, "is vulnerable to DNS AMP"
                break
            else:
                print dest_ip, "is a nope"
                break
        else:
            print dest_ip, "is a nope"
    except KeyboardInterrupt:
        print "Quitting"
        sys.exit()
    except:  # TODO replace with more specific exception
        print dest_ip, "is not vulnerable to DNS AMP"
