'''This module contains functions that test for NTP-related vulnerabilities.

Network Time Protocol (NTP) is used to synchronize the time
between a client and server. It is a UDP protocol that is run on port 123.

Monlist (the NTP Monitor List Scanner) is a remote command in older
versions of NTP that allows administrators to query the server for traffic
counts of connected clients. In response the the "get monlist" request, an
unpatched NTP server sends the requester a list of the last 600 hosts
who have connected to that server.
'''
import sys
import time

import colorlog
from scapy.all import IP
from scapy.all import UDP
from scapy.all import Raw
from scapy.all import random
from scapy.all import sr1

import logging

logger = colorlog.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# capture any log messages from the scapy package
scapy_logger = colorlog.getLogger("scapy")
scapy_logger.setLevel(logging.DEBUG)

# remove any StreamHandlers attached to the scapy's logger
# to prevent duplicate log messages appearing in the Terminal
for handler in scapy_logger.handlers:
    if isinstance(handler, logging.StreamHandler):
        scapy_logger.removeHandler(handler)

MAX_TRIES = 3
TIMEOUT = 5


def monlist_scan(options):
    '''Simulate the monlist command and return `results`, a boolean
    indicating whether or not the device is vulnerable to this attack.

    If the `target` device is an NTP server that accepts the monlist
    request and that server is unpatched, it will return a lot of packets
    (each about 500 bytes) instead of returning one small packet.
    '''
    results = None

    # number of attempts
    tries = 1

    try:
        # `data` is the "get monlist" request
        data = "\x17\x00\x03\x2a" + "\x00" * 4

        # Create an IP layer for the packet, spoofing the target's address
        ip = IP(dst=options['ip'])

        # Create a UDP layer for the packet
        udp = UDP(sport=random.randint(49152, 65536), dport=123)

        # Create a Raw layer for the packet
        a = Raw(load=data)

        # Assemble a packet `pck` comprised of the layers IP, UDP and Raw.
        pck = ip/udp/a

        while (tries <= MAX_TRIES):

            # Send the assembled packet `pck` to `target`, and the given
            # IP address. Return one packet that answered the packet set we
            # sent, not unanswered packets. Quit after receving a single
            # response.
            # The timeout parameter specifies the time to wait after the
            # last packet has been sent.
            # chainCC=1 so that when Ctrl-C is pressed, scapy will raise
            # the KeyboardInterrupt exception instead of suppressing it
            logger.info('Sending the monlist command. Waiting %d seconds '
                        'before timeout. Attempt %d of %d' %
                        (TIMEOUT, tries, MAX_TRIES))
            rep = sr1(pck, verbose=1, timeout=TIMEOUT, chainCC=1)

            if hasattr(rep, 'answers'):
                logger.debug('Received response from monlist command.')
                results = 1
                break

            elif not hasattr(rep, 'answers') and (tries < MAX_TRIES):
                logger.debug('No response received from monlist. Retrying')
                tries += 1

            else:
                results = None
                break

        return results
    except Exception as e:  # TODO replace with more specific exception
        logger.error("Error in ntp_monlist. %s" % str(e))


def ntp_monlist_check(options):
    '''Check whether the device, indicated by the given IP address, is
    vulnerable to the NTP monlist command.
    '''
    try:
        a = monlist_scan(options)
        if a is None:
            logger.info("%s is not vulnerable to NTP monlist" % options['ip'])
        elif a == 1:
            logger.info("%s is vulnerable to monlist" % options['ip'])
    except KeyboardInterrupt:
        logger.error("KeyboardInterrupt. Quitting")
        sys.exit(1)
