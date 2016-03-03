import logging
import time
l=logging.getLogger("scapy.runtime")
l.setLevel(49)
from scapy.all import IP,UDP,sr1,random,Raw
import sys
class ssdp_scan:
	def active_scan(self, target):
  		req = 'M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:upnp:rootdevice\r\nMan:"ssdp:discover"\r\nMX:3\r\n\r\n'
		ip=IP(dst=target)
  		udp=UDP(sport=random.randint(49152,65536), dport=1900)
  		pck = ip/udp/req
  		try:	
			start = time.time()
			while time.time() < start + 5:
	  			rep = sr1(pck, verbose=0,timeout=7)
				if rep[Raw]:
   					results = rep[Raw].load
				else:
					pass
				break
		except KeyboardInterrupt:
			sys.exit(0)	
  		except Exception as e:
   			results = None
			#print e
		return results


