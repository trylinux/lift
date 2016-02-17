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
	parser.add_argument("-p","--port", help="A port")
	args=parser.parse_args()
	if args.port is None:
		dport = 443
	else:
		dport = int(args.port)
	if args.ip:
		dest_ip = args.ip
		testips(args.ip,dport)
	elif args.ifile:
		ipfile = args.ifile
		try:
			with open(ipfile) as f:
				for line in f:
					testips(line,dport)
		except KeyboardInterrupt:
                	#print "Quitting"
                	sys.exit(0)
		except:
			sys.exc_info()[0]
			print "error in first try"
			pass

def testips(dest_ip,dport):
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	try:	
		s = socket()
		s.settimeout(10)
		c = ssl.wrap_socket(s,cert_reqs=ssl.CERT_NONE)
		c.connect((dest_ip,dport))
		a = c.getpeercert(True)
		b = str(ssl.DER_cert_to_PEM_cert(a))
		device = (certs.getcertinfo(b))
		#print device

		if device is not None:
			if device is "ubiquiti":
				print str(dest_ip).rstrip('\r\n)') + ": Ubiquiti AirMax or AirFiber Device (SSL)"
			elif "samsung" in device:
				print str(dest_ip).rstrip('\r\n)') + ": Unknown Samsung Device (SSL)"
			elif "qnap" in device:
				print str(dest_ip).rstrip('\r\n)') + ": QNAP NAS TS series detected (SSL)"
			elif device is "hikvision":
				print str(dest_ip).rstrip('\r\n)') + ": Hikvision Default Cert"
			elif device is "avigilon":
				print str(dest_ip).rstrip('\r\n)') + ": Aviligon Gateway Default cert"
			elif "netgear" in device:
				print str(dest_ip).rstrip('\r\n)') + ": NetGear Default cert"
			elif device is "verifone_sapphire":
				print str(dest_ip).rstrip('\r\n)') + ": Verifone Sapphire Device (SSL)"
			elif "Vigor" in device:
				print str(dest_ip).rstrip('\r\n)') + ": DrayTek Vigor Device (SSL)"
			elif device is "lifesize_1":
				print str(dest_ip).rstrip('\r\n)') + ": Lifesize Product (SSL)"
			elif "filemaker" in device:
				print str(dest_ip).rstrip('\r\n)') + ": Filemaker Secure Database Website (SSL)"
			elif  device is "verizon_jungo":
				print str(dest_ip).rstrip('\r\n)') + ": Verizon Jungo OpenRG product (SSL/8443)"
			elif  device is "canon_iradv":
				print str(dest_ip).rstrip('\r\n)') + ": Canon IR-ADV Login Page (SSL/8443)"
			elif "colubris" in device:
				print str(dest_ip).rstrip('\r\n)') + ": HPE MSM Series Device (SSL)"
			elif device is "ecessa":
				print str(dest_ip).rstrip('\r\n)') + ": Ecessa PowerLink Wan Optimizer (SSL)"
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
				print "error in second pass"
				pass
		if device is None and 'iR-ADV' in a:
			hostname = "https://%s:%s" % (dest_ip,dport)
			try:		
				checkheaders = urllib2.urlopen(hostname,context=ctx)
				html = checkheaders.read()
				soup = BeautifulSoup.BeautifulSoup(html)
				title = soup.html.head.title
				if 'Catwalk' in title.contents:
					print str(dest_ip).rstrip('\r\n)') + ": Canon iR-ADV Login Page (SSL + Server header)"
			except:
				print "error in third pass"
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
