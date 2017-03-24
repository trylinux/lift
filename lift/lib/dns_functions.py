'''This module contains functions that test for DNS-related vulnerabilities.

Network Time Protocol (NTP) is used to synchronize the time
between a client and server. It is a UDP protocol that is run on port 123.

Monlist (the NTP Monitor List Scanner) is a remote command in older
versions of NTP that allows administrators to query the server for traffic
counts of connected clients. In response the the "get monlist" request, an
unpatched NTP server sends the requester a list of the last 600 hosts
who have connected to that server.
'''
import dns.resolver
import time


def recurse_DNS_check(dest_ip):
    '''Check whether the device, indicated by the given IP address, is
    is vulnerable to DNS amplication.
    '''
    vbose = kwargs['verbose']
    myResolver = dns.resolver.Resolver()
    myResolver.nameservers = [str(dest_ip)]
    try:
        print "Trying: ",dest_ip
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