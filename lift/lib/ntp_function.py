import sys
if 'threading' in sys.modules:
    del sys.modules['threading']
import gevent
import gevent.socket
import gevent.monkey
gevent.monkey.patch_all()
import logging
import time
l=logging.getLogger("scapy.runtime")
l.setLevel(49)
from scapy.layers.inet import IP, UDP
from scapy.all import send,Raw,random,send,sr1

class NTPscan:
    def monlist_scan(self,target):
        data = "\x17\x00\x03\x2a" + "\x00" * 4
        ip = IP(dst=target)
        udp=UDP(sport=random.randint(49152,65536),dport=123)
        a = Raw(load=data)
        pck = ip/udp/a
        n = 0
        results = None
        #try:
        while (n < 3):
            rep = sr1(pck,verbose=0,timeout=5)
            if hasattr(rep,'answers'):
                results = 1
                break
            elif not hasattr(rep,'answers') and (n < 3):
                #print("Pass ",n)
                n = n + 1
            else:
                results = None
                break
                pass
        #except KeyboardInterrupt:
        #    sys.exit(0)
        #except Exception as e:
    #        results = None
            #print(e)
        return results
