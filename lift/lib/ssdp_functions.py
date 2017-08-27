'''This module contains functions that test for SSDPP-related vulnerabilities.

SSDP (Simple Service Discovery Protocol) is often used for discovery of
Plug & Play (UPnP) devices. Attackers have found that the Simple Object Access
Protocol (SOAP) can be used to deliver control messages to UPnP devices and
pass information. Requests can be crafted to elicit a response that reflects
and amplifies a packet, which can be redirected towards a target.
SSDP is being abused to carry out reflection and amplification distributed
denial-of-service (DDoS) attacks.
'''
import sys
import re
import json
import logging
import time

import colorlog
from scapy.all import IP
from scapy.all import UDP
from scapy.all import sr1
from scapy.all import random
from scapy.all import Raw

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


def active_scan(target):
    # req contains the type of payload that is likely to originate from a
    # UPnP device that is vulnerable to this attack.
    req = ('M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\n'
           'ST:upnp:rootdevice\r\nMan:"ssdp:discover"\r\nMX:3\r\n\r\n')
    ip = IP(dst=target)
    udp = UDP(sport=random.randint(49152, 65536), dport=1900)
    pck = ip/udp/req
    results = None
    try:
        start = time.time()
        rep = sr1(pck, verbose=1, timeout=5, chainCC=1)
        if rep:
            if rep[Raw]:
                results = rep[Raw].load

    except Exception as e:
        # results = None
        logger.error(str(e))
        raise
    return results


def get_ssdp_information(ipaddr):
    try:
        output = active_scan(str(ipaddr))
        string = output.splitlines
        if string is not None:
            for index, item in enumerate(string()):
                if "SERVER" in item:
                    server_information = re.sub('SERVER\: ', '', item)
                elif "LOCATION" in item:
                    ssdp_location = re.sub('LOCATION\: ', '', item)
        if server_information is not None:
            a = {'server': server_information, 'upnp_location': ssdp_location}
            b = json.dumps(a)
        else:
            b = None

    except Exception as e:
        b = None

    return b


def recurse_ssdp_check(options):
    '''Check whether the device, indicated by the given IP address, is
    is an SSDP reflector.
    '''
    try:
        a = get_ssdp_information(options['ip'])
        if a is None:
            logger.info("%s is not an SSDP reflector" % options['ip'])
        elif a is not None:
            logger.info("%s is an SSDP reflector with result %s" % (options['ip'], a))

    except KeyboardInterrupt:
        logger.error("KeyboardInterrupt. Quitting in here")
        sys.exit(0)
    except Exception as e:  # TODO replace with more specific exception
        logger.error("Encountered exception. %s" % e)
        raise
