'''This module contains functions that test for NTP-related vulnerabilities.

Network Time Protocol (NTP) is used to synchronize the time
between a client and server. It is a UDP protocol that is run on port 123.

Monlist (the NTP Monitor List Scanner) is a remote command in older
versions of NTP that allows administrators to query the server for traffic
counts of connected clients. In response the the "get monlist" request, an
unpatched NTP server sends the requester a list of the last 600 hosts
who have connected to that server.
'''
import logging
import sys
import time

from scapy.all import IP
from scapy.all import UDP
from scapy.all import Raw
from scapy.all import random
from scapy.all import sr1


logger = logging.getLogger("scapy.runtime")
logger.setLevel(49)

MAX_RETRIES = 3


def monlist_scan(self, target):
    '''Simulate the monlist command and return `results`, a boolean
    indicating whether or not the device is vulnerable to this attack.

    If the `target` device is an NTP server that accepts the monlist
    request and that server is unpatched, it will return a lot of packets
    (each about 500 bytes) instead of returning one small packet.
    '''
    results = None

    # number of attempts
    retries = 0

    try:
        # `data` is the "get monlist" request
        data = "\x17\x00\x03\x2a" + "\x00" * 4

        # Create an IP layer for the packet, spoofing the target's address
        ip = IP(dst=target)

        # Create a UDP layer for the packet
        udp = UDP(sport=random.randint(49152, 65536), dport=123)

        # Create a Raw layer for the packet
        a = Raw(load=data)

        # Assemble a packet `pck` comprised of the layers IP, UDP and Raw.
        pck = ip/udp/a

        while (retries < MAX_RETRIES):

            # Send the assembled packet `pck` to `target`, and the given
            # IP address. Return one packet that answered the packet set we
            # sent, not unanswered packets. Quit after receving a single
            # response.
            # The timeout parameter specifies the time to wait after the
            # last packet has been sent.
            rep = sr1(pck, verbose=0, timeout=5)

            if hasattr(rep, 'answers'):
                results = 1
                break

            elif not hasattr(rep, 'answers') and (retries < MAX_RETRIES):
                retries += 1

            else:
                results = None
                break

        return results
    except Exception as e:  # TODO replace with more specific exception
        if kwargs['verbose']:
            print "Error in ntp_monlist ", e


def ntp_monlist_check(dest_ip):
    '''Check whether the device, indicated by the given IP address, is
    vulnerable to the NTP monlist command.
    '''
    try:
        a = monlist_scan(dest_ip)
        if a is None:
            print dest_ip, "is not vulnerable to NTP monlist"
        elif a == 1:
            print dest_ip, "is vulnerable to monlist"
    except KeyboardInterrupt:
        print "Quitting"
        sys.exit(1)