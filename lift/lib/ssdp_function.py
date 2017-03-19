import logging
import time
from scapy.all import IP
from scapy.all import UDP
from scapy.all import sr1
from scapy.all import random
from scapy.all import Raw


logger = logging.getLogger("scapy.runtime")
logger.setLevel(49)


class ssdp_scan:
    '''
    SSDP (Simple Service Discovery Protocol) is often used for discovery of
    Plug & Play (UPnP) devices. Attackers have found that Simple Object Access
    Protocol (SOAP) – used to deliver control messages to UPnP devices and pass
    information – requests “can be crafted to elicit a response that reflects
    and amplifies a packet, which can be redirected towards a target.
    SSDP is being abused to carry out reflection and amplification distributed
    denial-of-service (DDoS) attacks.
    '''
    def active_scan(self, target):
        # req contains the type of payload that is likely to originate from a
        # UPnP device that is vulnerable to this attack.
        req = ('M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\n'
               'ST:upnp:rootdevice\r\nMan:"ssdp:discover"\r\nMX:3\r\n\r\n')
        ip = IP(dst=target)
        udp = UDP(sport=random.randint(49152, 65536), dport=1900)
        pck = ip/udp/req

        try:
            start = time.time()
            rep = sr1(pck, verbose=0, timeout=5)
            if rep[Raw]:
                results = rep[Raw].load

        except Exception as e:
            results = None

        return results
