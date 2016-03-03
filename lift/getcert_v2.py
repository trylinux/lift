from socket import socket
import ssl
import argparse
import time
import sys
import urllib2
sys.path.append("/opt/sectools/lift/lib/")
import certs
import BeautifulSoup
import netaddr
import os
import pyasn
import dns.resolver
import ssdp_info
def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i","--ip", help="An Ip address")
	parser.add_argument("-f","--ifile", help="A file of IPs")
	parser.add_argument("-p","--port", help="A port")
	parser.add_argument("-v","--verbose", help="Verbosity On")
	parser.add_argument("-s","--subnet", help="A subnet!")
	parser.add_argument("-a","--asn", help="ASN number. WARNING: This will take a while")
	parser.add_argument("-r","--recurse", help="Test Recursion", action="store_true")
	args=parser.parse_args()
	asndb=pyasn.pyasn('/opt/sectools/lift/lib/ipasn.dat')
	if args.verbose is None:
		verbose = None
	else:
	   	verbose = args.verbose
	if args.port is None:
		dport = 443
	else:
		dport = int(args.port)
	if args.ip and not args.recurse:
		dest_ip = args.ip
		testips(args.ip,dport,verbose)
	elif args.ifile and not args.recurse:
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
	elif args.subnet:
		for ip in netaddr.IPNetwork(str(args.subnet)):
			testips(str(ip),dport,verbose)
	elif args.asn:
		for subnet in asndb.get_as_prefixes(int(args.asn)):
			for ip in netaddr.IPNetwork(str(subnet)):
                        	testips(str(ip),dport,verbose)
	elif args.ifile and args.recurse:
		ipfile = args.ifile
		try:
                        with open(ipfile) as f:
                                for line in f:
					try:
						if dport == 53:
	                                        	recurse_DNS_check(str(line).rstrip('\r\n'),verbose)
						elif dport == 1900:
							recurse_ssdp_check(str(line).rstrip('\r\n'),verbose)
        					else:
							recurse_ssdp_check(str(line).rstrip('\r\n'),verbose)
							recurse_DNS_check(str(line).rstrip('\r\n'),verbose)        
					except KeyboardInterrupt:
		                        #print "Quitting"
                		        	sys.exit(0)
               				except Exception as e:
		                        	sys.exc_info(0)
                		        	print "error in recurse try",e
                        			pass
		except KeyboardInterrupt:
			sys.exit(0)
		
                except Exception as e:
                        sys.exc_info()[0]
                        print "error in recurse try",e
			pass
	elif args.ip and args.recurse:
		if dport == 53:
			recurse_DNS_check(str(args.ip),verbose)
		elif dport == 1900:
			recurse_ssdp_check(str(args.ip),verbose)
		else:
			print "Trying both 53 and 1900!"
			recurse_DNS_check(str(args.ip),verbose)
			recurse_ssdp_check(str(args.ip),verbose)



def ishostup(dest_ip,dport,verbose):
	response = os.system("ping -c 1 " + dest_ip)
	if response == 0:
  		testips(dest_ip,dport,verbose)
	else:
  		pass

def testips(dest_ip,dport,verbose):
	device = None
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	ctx.set_ciphers('ALL')
	s = socket()
	s.settimeout(5)
	try:
			
		c = ssl.wrap_socket(s,cert_reqs=ssl.CERT_NONE)
		c.connect((dest_ip,dport))
		a = c.getpeercert(True)
		b = str(ssl.DER_cert_to_PEM_cert(a))
		device = (certs.getcertinfo(b))
		#if verbose is not None:
			#print "Trying: ",str(dest_ip).rstrip('\r\n)')
			#print "device: ",device
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
			elif device is "netgear_1":
				print str(dest_ip).rstrip('\r\n)') + ": NetGear Default cert UTM  (SSL)"
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
			elif device is "opengear_default_cert":
				print str(dest_ip).rstrip('\r\n)') + ": Opengear Management Console Default cert (SSL)"
			elif device is "zyxel_pk5001z":
				print str(dest_ip).rstrip('\r\n)') + ": Zyxel PK5001Z default cert (SSL)"
			elif device is "audiocodecs_8443":
				print str(dest_ip).rstrip('\r\n)') + ": AudioCodecs MP serices 443/8443 Default Cert (SSL)"
			elif device is "supermicro_ipmi":
				print str(dest_ip).rstrip('\r\n)') + ": Supermicro Nuvoton Chip IPMI Default Cert (SSL)"
			elif device is "enco_player_1":
				print str(dest_ip).rstrip('\r\n)') + ": Enco Enplayer Default Cert (SSL)"
			elif device is "ami_megarac":
				print str(dest_ip).rstrip('\r\n)') + ": AMI MegaRac Remote Management Default Cert (SSL)"
			elif device is "avocent_1":
				print str(dest_ip).rstrip('\r\n)') + ": Avocent Default cert (unknown device) (SSL)"
		elif a is not None and device is None:
			getheaders_ssl(dest_ip,dport,a,verbose,ctx)
		else:
			print "Something error happened"

		s.close()
	except KeyboardInterrupt:
                        print "Quitting"
                        sys.exit(0)		
	except Exception as e:
		s.close()
		if 111 in e:
			getheaders(dest_ip,dport,verbose)
		elif "timed out" in e:
			pass
		if verbose is not None:
			print "Error Catch at line 133",e
def getheaders_ssl(dest_ip,dport,cert,vbose,ctx):
	hostname = "https://%s:%s" % (str(dest_ip).rstrip('\r\n)'),dport)
	
	try:
		checkheaders = urllib2.urlopen(hostname,context=ctx)
		server = checkheaders.info().get('Server')
		if not server:
			server = None 	
		html = checkheaders.read()
		soup = BeautifulSoup.BeautifulSoup(html)
		title = soup.html.head.title
		if title is None:
			title = soup.html.title
		 
		if 'EdgeOS' in title.contents and 'Ubiquiti' in cert:
			print str(dest_ip).rstrip('\r\n)') + ": EdgeOS Device (SSL + Server header)"
		elif 'iR-ADV' in cert and 'Catwalk' in title.contents:
			print str(dest_ip).rstrip('\r\n)') + ": Canon iR-ADV Login Page (SSL + Server header)"
		elif 'Cyberoam' in cert:
			print str(dest_ip).rstrip('\r\n)') + ": Cyberoam Device (SSL)"
		elif 'TG582n' in cert:
			print str(dest_ip).rstrip('\r\n)') + ": Technicolor TG582n (SSL)"
		elif 'RouterOS' in title.contents:
			print str(dest_ip).rstrip('\r\n)') + ": MikroTik RouterOS (Login Page Title)"
		else:
			getheaders(dest_ip,80,vbose)
		checkheaders.close()
	except Exception as e:
		if dport is 443:
			dport = 80
		getheaders(dest_ip,dport,vbose)
		if vbose is not None:
			print "Error in getsslheaders: ",e
		pass
	return
def getheaders(dest_ip,dport,vbose):
	if dport == 443:
		dport = 80
	try:
		hostname = "http://%s:%s" % (str(dest_ip).rstrip('\r\n)'),dport)
		checkheaders = urllib2.urlopen(hostname)
		try:
			server = checkheaders.info().get('Server')
		except:
			server = None
		html = checkheaders.read()
		soup = BeautifulSoup.BeautifulSoup(html)
		title = soup.html.head.title
		if title is None:
			title = soup.html.title
		a = title.contents
		if 'RouterOS' in str(a) and server is None:
			print str(dest_ip).rstrip('\r\n)') + ": MikroTik RouterOS (Login Page Title)"
		elif 'Cambium' in server and 'ePMP' in str(a):
			print str(dest_ip).rstrip('\r\n)') + ": Cambium ePMP 1000 Device (Server type + title)"
		elif 'Wimax CPE Configuration' in str(a) and 'httpd' in server:
			print str(dest_ip).rstrip('\r\n)') + ": Wimax Device (PointRed, Mediatek etc). with (guest/guest) (Server type + title)"
		checkheaders.close()
	except Exception as e:
		if vbose is not None:
			print "Error in getheaders(): "
		pass
def recurse_DNS_check(dest_ip,vbose):
	myResolver = dns.resolver.Resolver()
	myResolver.nameservers = [str(dest_ip)]
	try:
		start = time.time()
		while time.time() < start + 3: 
			myAnswers = myResolver.query("google.com", "A")
			if myAnswers:
				print dest_ip, "is a resolver"
			else:
				print dest_ip, "is a nope"
			break
		else:
			print dest_ip, "is a nope"
	except KeyboardInterrupt:
		print "Quitting"
		sys.exit()
	except:
		print dest_ip, "is not a reflector"
		pass
def recurse_ssdp_check(dest_ip,vbose):
	try:
		start = time.time()
		while time.time() < start + 3:
			a = ssdp_info.get_ssdp_information(dest_ip)
			if a is None:
				pass
			if vbose is not None and a:
				print dest_ip, "is an SSDP reflector with result", a
				break
			elif a and vbose is None:
				print dest_ip, "is an SSDP reflector"
				break
			else: 
				print "Not a reflector"
				pass
			break
			pass
		else:
			print "Passing"
			pass
	except KeyboardInterrupt:
                print "Quitting"
                sys.exit()
        except Exception as e:
                print "Nope",e
                pass
 

if __name__ == '__main__':	
	main()
