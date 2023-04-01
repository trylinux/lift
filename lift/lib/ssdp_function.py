import logging
import random
import time

l = logging.getLogger("scapy.runtime")
l.setLevel(49)

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import sr1


class ssdp_scan:
    def active_scan(self, target):
        req = 'M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:upnp:rootdevice\r\nMan:"ssdp:discover"\r\nMX:3\r\n\r\n'
        ip = IP(dst=target)
        udp = UDP(sport=random.randint(49152, 65536), dport=1900)
        pck = ip / udp / req
        try:
            start = time.time()
            rep = sr1(pck, verbose=0, timeout=5)
            if rep[Raw]:
                results = rep[Raw].load
            else:
                pass
        except Exception as e:
            results = None
            # print(e)
        return results
