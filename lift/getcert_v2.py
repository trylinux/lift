from socket import socket
import ssl
import argparse
import time
import sys
import signal
import urllib2
sys.path.append("/opt/sectools/lift/lib/")
import certs
import BeautifulSoup
def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i","--ip", help="An Ip address")
#	parser.add_argument("-u","--user", help="The user you want to use")
	parser.add_argument("-f","--ifile", help="A file of IPs")
	args=parser.parse_args()
	if args.ip:
		dest_ip = args.ip
		testips(args.ip)
	elif args.ifile:
		ipfile = args.ifile
		try:
			with open(ipfile) as f:
				for line in f:
					testips(line)
		except KeyboardInterrupt:
                	#print "Quitting"
                	sys.exit(0)
		except:
			sys.exc_info()[0]
			raise
			pass

def testips(dest_ip):
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	try:	
		s = socket()
		s.settimeout(10)
		c = ssl.wrap_socket(s,cert_reqs=ssl.CERT_NONE)
		c.connect((dest_ip, 443))
		a = c.getpeercert(True)
		b = str(ssl.DER_cert_to_PEM_cert(a))
		device = (certs.getcertinfo(b))
		if device is not None:
			if device is "ubiquiti":
				print str(dest_ip).rstrip('\r\n)') + ": Ubiquiti AirMax or AirFiber Device (SSL)"
			elif "samsung" in device:
				print str(dest_ip).rstrip('\r\n)') + ": Unknown Samsung Device (SSL)"
			elif "qnap" in device:
				print str(dest_ip).rstrip('\r\n)') + ": QNAP NAS TS series detected (SSL)"
			elif "hikvision" in device:
				print str(dest_ip).rstrip('\r\n)') + ": Hikvision Default Cert"
			elif "aviligon" in device:
				print str(dest_ip).rstrip('\r\n)') + ": Aviligon Gateway Default cert"
			elif "netgear" in device:
				print str(dest_ip).rstrip('\r\n)') + ": NetGear Default cert"
			else:
				print "Not in registry"
		if device is None and 'Ubiquiti' in a:
			hostname = "https://%s" % dest_ip
			try:
				checkheaders = urllib2.urlopen(hostname,context=ctx)
				html = checkheaders.read()
				soup = BeautifulSoup.BeautifulSoup(html)
				title = soup.html.head.title
				if 'EdgeOS' in title.contents:
					print str(dest_ip).rstrip('\r\n)') + ": EdgeOS Device (SSL + Server header)"
			except:
				pass
		s.close()
	except KeyboardInterrupt:
                        print "Quitting"
                        sys.exit(0)		
	except:
		s.close()
		sys.exc_info()[0]
		pass

if __name__ == '__main__':	
	main()
