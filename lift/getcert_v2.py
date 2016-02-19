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
	parser.add_argument("-v","--verbose", help="Verbosity On")
	args=parser.parse_args()
	if args.verbose is None:
		verbose = None
	else:
	   	verbose = args.verbose
	if args.port is None:
		dport = 443
	else:
		dport = int(args.port)
	if args.ip:
		dest_ip = args.ip
		testips(args.ip,dport,verbose)
	elif args.ifile:
		ipfile = args.ifile
		try:
			with open(ipfile) as f:
				for line in f:
					testips(line,dport,verbose)
		except KeyboardInterrupt:
                	#print "Quitting"
                	sys.exit(0)
		except:
			sys.exc_info()[0]
			print "error in first try"
			pass

def testips(dest_ip,dport,verbose=None):
	device = None
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	try:	
		s = socket()
		s.settimeout(5)
		c = ssl.wrap_socket(s,cert_reqs=ssl.CERT_NONE)
		c.connect((dest_ip,dport))
		a = c.getpeercert(True)
		b = str(ssl.DER_cert_to_PEM_cert(a))
		device = (certs.getcertinfo(b))
		if verbose is 1:
			print "Trying: ",str(dest_ip).rstrip('\r\n)')

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
			elif device is "nomadix_ag_1":
				print str(dest_ip).rstrip('\r\n)') + ": Nomadix AG series Gateway (SSL)"
			elif "netvanta" in device:
				print str(dest_ip).rstrip('\r\n)') + ": ADTRAN NetVanta Total Access Device (SSL)"
			elif "valuepoint_gwc_1" is device:
				print str(dest_ip).rstrip('\r\n)') + ": ValuePoint Networks Gateway Controller Series (SSL)"
			elif device is "broadcom_1":
				print str(dest_ip).rstrip('\r\n)') + ": Broadcom Generic Modem (SSL)"
			elif device is "lg_nas_1":
				print str(dest_ip).rstrip('\r\n)') + ": LG NAS Device (SSL)"
			elif device is "edgewater_1":
				print str(dest_ip).rstrip('\r\n)') + ": EdgeWater Networks VOIP Solution (SSL)"
			elif device is "foscam_cam":
				print str(dest_ip).rstrip('\r\n)') + ": Foscam IPcam Client Login (SSL)"
			elif device is "lacie_1":
				print str(dest_ip).rstrip('\r\n)') + ": LaCie CloudBox (SSL)"
			elif device is "huawei_hg658":
				print str(dest_ip).rstrip('\r\n)') + ": Huawei Home Gateway HG658d (SSL)"
			elif device is "interpeak_device":
				print str(dest_ip).rstrip('\r\n)') + ": Something made by interpeak (SSL)"
			elif device is "fujistu_celvin":
				print str(dest_ip).rstrip('\r\n)') + ": Fujitsu Celvin NAS (SSL)"
		elif a is not None and device is None:
			getheaders_ssl(dest_ip,dport,a,verbose,ctx)
		elif a is None and device is None:
			getheaders(dest_ip,dport,verbose)
		else:
			print "Something error happened"
		s.close()
	except KeyboardInterrupt:
                        print "Quitting"
                        sys.exit(0)		
	except Exception as e:
		s.close()
		if verbose is 2:
			print "Error in Final Pass: ",e
		sys.exc_info()[0]
	if device is None and dport is 443:
		getheaders_ssl(dest_ip,dport,a,verbose,ctx)
	else:
		getheaders(dest_ip,dport,verbose)
	s.close()
def getheaders_ssl(dest_ip,dport,cert,vbose,ctx):
	hostname = "https://%s:%s" % (dest_ip,dport)
	try:
		checkheaders = urllib2.urlopen(hostname,context=ctx)
		server = checkheaders.info().get('Server')
		html = checkheaders.read()
		soup = BeautifulSoup.BeautifulSoup(html)
		title = soup.html.head.title
		if title is None:
			title = soup.html.title
		 
		if 'EdgeOS' in title.contents and 'Ubiquiti' in cert:
			print str(dest_ip).rstrip('\r\n)') + ": EdgeOS Device (SSL + Server header)"
		if 'iR-ADV' in cert and 'Catwalk' in title.contents:
			print str(dest_ip).rstrip('\r\n)') + ": Canon iR-ADV Login Page (SSL + Server header)"
		if 'Cyberoam' in cert:
			print str(dest_ip).rstrip('\r\n)') + ": Cyberoam Device (SSL)"
		if 'TG582n' in cert:
			print str(dest_ip).rstrip('\r\n)') + ": Technicolor TG582n (SSL)"
		else:
			getheaders(dest_ip,80,vbose)
	except Exception as e:
		if dport is 443:
			dport = 80
		getheaders(dest_ip,dport,vbose)
		if vbose is 2:
			print "Error in Second Pass: "
		pass
def getheaders(dest_ip,dport,vbose):
	if dport == 443:
		dport = 80
	try:
		hostname = "http://%s:%s" % (dest_ip,dport)
		checkheaders = urllib2.urlopen(hostname)
		server = checkheaders.info().get('Server')
		html = checkheaders.read()
		soup = BeautifulSoup.BeautifulSoup(html)
		title = soup.html.head.title
		if title is None:
			title = soup.html.title
		if 'Cambium' in server and 'ePMP' in str(title.contents):
			print str(dest_ip).rstrip('\r\n)') + ": Cambium ePMP 1000 Device (Server type + title)"
	
	except Exception as e:
		if vbose is 2:
			print "Error in Final Pass: ",e
		pass

if __name__ == '__main__':	
	main()
