import sys
if 'threading' in sys.modules:
    del sys.modules['threading']
import gevent
import gevent.socket
import gevent.monkey
gevent.monkey.patch_all()
from socket import socket
import ssl
import argparse
import time
import urllib2
sys.path.append("/opt/sectools/lift/lib/")
import certs
import BeautifulSoup
import netaddr
import os
import pyasn
import dns.resolver
import ssdp_info, ntp_function

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i","--ip", help="An Ip address")
	parser.add_argument("-f","--ifile", help="A file of IPs")
	parser.add_argument("-p","--port", help="A port")
	parser.add_argument("-v","--verbose", help="Verbosity On")
	parser.add_argument("-s","--subnet", help="A subnet!")
	parser.add_argument("-a","--asn", help="ASN number. WARNING: This will take a while")
	parser.add_argument("-r","--recurse", help="Test Recursion", action="store_true")
	parser.add_argument("-I","--info", help="Get more info about operations", action="store_true")
	parser.add_argument("-S","--ssl",help="For doing SSL checks only", action="store_true")
	parser.add_argument("-R","--recon",help="Gather information about a given device", action="store_true")
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
	if args.ssl:
		ssl_only=1
	else:
		ssl_only=0
	if not args.info:
		info = None
	else:
		info = 1

	if args.ip and not args.recurse and not args.recon:
		dest_ip = args.ip
		if dport is 80:
			getheaders(args.ip,dport,verbose,info)

		else:
			testips(args.ip,dport,verbose,ssl_only,info)
	elif args.ifile and not args.recurse:
		ipfile = args.ifile
		try:
			with open(ipfile) as f:
				for line in f:
					if args.port == 80:
						getheaders(str(ip).rstrip('\r\n)'),dport,verbose,info)
					else:
						testips(line,dport,verbose,ssl_only,info)
		except KeyboardInterrupt:
                	#print "Quitting"
                	sys.exit(0)
		except Exception as e:
			sys.exc_info()[0]
			print "error in first try",e
			pass
	elif args.subnet:
		try:
			for ip in netaddr.IPNetwork(str(args.subnet)):
				try:
					if dport == 80:
						getheaders(str(ip).rstrip('\r\n)'),dport,verbose,info)
					elif args.recurse:
						if dport == 53:
							recurse_DNS_check(str(ip).rstrip('\r\n'),verbose)
						elif dport == 1900:
							recurse_ssdp_check(str(ip).rstrip('\r\n'),verbose)
						elif dport == 123:
							ntp_monlist_check(str(ip).rstrip('\r\n'),verbose)
						else:
							recurse_ssdp_check(str(ip).rstrip('\r\n'),verbose)
							recurse_DNS_check(str(ip).rstrip('\r\n'),verbose)
							ntp_monlist_check(str(ip).rstrip('\r\n'),verbose)
					else:
						testips(str(ip),dport,verbose,ssl_only,info)
				except KeyboardInterrupt:
					print "Quitting from Subnet"
					sys.exit(0)
					pass
				except Exception as e:
					if args.verbose is not None:
						print "Error occured in Subnet",e
					sys.exit(0)
		except KeyboardInterrupt:
			sys.exit()
		except Exception as e:
			sys.exit()
	elif args.asn:
		for subnet in asndb.get_as_prefixes(int(args.asn)):
			try:
				for ip in netaddr.IPNetwork(str(subnet)):
					if dport == 80:
						getheaders(str(ip).rstrip('\r\n)'),dport,verbose,info)
					elif args.recurse:
						if dport == 53:
							recurse_DNS_check(str(ip).rstrip('\r\n'),verbose)
						elif dport == 1900:
							recurse_ssdp_check(str(ip).rstrip('\r\n'),verbose)
						elif dport == 123:
							ntp_monlist_check(str(ip).rstrip('\r\n'),verbose)
						else:
							recurse_ssdp_check(str(ip).rstrip('\r\n'),verbose)
							recurse_DNS_check(str(ip).rstrip('\r\n'),verbose)
							ntp_monlist_check(str(ip).rstrip('\r\n'),verbose)
					else:
						testips(str(ip),dport,verbose,ssl_only,info)
			except KeyboardInterrupt:
				print "Quitting"
				sys.exit(1)
			except Exception as e:
				if args.verbose is not None:
					print "Error occured in Subnet",e
					sys.exit(0)


	elif args.ifile and args.recurse:
		ipfile = args.ifile
		try:
			with open(ipfile) as f:
				for line in f:
					if dport == 53:
						recurse_DNS_check(str(line).rstrip('\r\n'),verbose)
					elif dport == 1900:
						recurse_ssdp_check(str(line).rstrip('\r\n'),verbose)
					elif dport == 123:
						ntp_monlist_check(str(line).rstrip('\r\n'),verbose)
					else:
						recurse_ssdp_check(str(line).rstrip('\r\n'),verbose)
						recurse_DNS_check(str(line).rstrip('\r\n'),verbose)
						ntp_monlist_check(str(line).rstrip('\r\n'),verbose)
		except KeyboardInterrupt:
			print "Quitting from first try in ifile"
			sys.exit(0)
		except Exception as e:
			sys.exit()
			print "error in recurse try",e
			raise
	elif args.ip and args.recurse:
		if dport == 53:
			recurse_DNS_check(str(args.ip),verbose)
		elif dport == 1900:
			recurse_ssdp_check(str(args.ip),verbose)
		elif dport == 123:
			ntp_monlist_check(str(args.ip).rstrip('\r\n'),verbose)
		else:
			print "Trying 53,1900 and 123!"
			recurse_DNS_check(str(args.ip),verbose)
			recurse_ssdp_check(str(args.ip),verbose)
			ntp_monlist_check(str(args.ip).rstrip('\r\n'),verbose)

	if args.ip and args.recon:
		print "Doing recon on ", args.ip
		dest_ip = args.ip
		try:
			testips(dest_ip,dport,verbose,ssl_only,info)
			recurse_DNS_check(str(args.ip),verbose)
			recurse_ssdp_check(str(args.ip),verbose)
			ntp_monlist_check(str(args.ip).rstrip('\r\n'),verbose)
		except KeyboardInterrupt:
			print "Quitting"
			sys.exit(0)
		except Exception as e:
			print "Encountered an error",e



def ishostup(dest_ip,dport,verbose):
	response = os.system("ping -c 1 " + dest_ip)
	if response == 0:
  		testips(dest_ip,dport,verbose)
	else:
  		pass

def testips(dest_ip,dport,verbose,ssl_only,info):
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
			elif "supermicro_ipmi" in device:
				print str(dest_ip).rstrip('\r\n)') + ": Supermicro IPMI Default Certs (SSL)"
			elif device is "enco_player_1":
				print str(dest_ip).rstrip('\r\n)') + ": Enco Enplayer Default Cert (SSL)"
			elif device is "ami_megarac":
				print str(dest_ip).rstrip('\r\n)') + ": AMI MegaRac Remote Management Default Cert (SSL)"
			elif device is "avocent_1":
				print str(dest_ip).rstrip('\r\n)') + ": Avocent Default cert (unknown device) (SSL)"
			elif device is "ligowave_1":
				print str(dest_ip).rstrip('\r\n)') + ": LigoWave Default Cert (probably APC Propeller 5) (SSL)"
			elif "intelbras_wom500" in device:
				print str(dest_ip).rstrip('\r\n)') + ": IntelBras Wom500 (admin/admin) (SSL)"
			elif "netgear_2" in device:
				print str(dest_ip).rstrip('\r\n)') + ": Netgear Default Cert Home Router (8443/SSL)"
			elif "buffalo_1" in device:
				print str(dest_ip).rstrip('\r\n)') + ": Buffalo Default Cert (443/SSL)"
			elif "digi_int_1" in device:
				print str(dest_ip).rstrip('\r\n)') + ": Digi Passport Default Cert (443/SSL)"
			elif "prtg_network_monitor_1" in device:
				print str(dest_ip).rstrip('\r\n)') + ": Paessler PTRG Monitoring Default Cert(443/SSL)"
			elif 'axentra_1' in device:
				print str(dest_ip).rstrip('\r\n)') + ": Seagate/Axentra NAS Default Cert 863B4AB (443/SSL)"
			elif 'ironport_device' in device:
				print str(dest_ip).rstrip('\r\n)') + ": Cisco IronPort Device Default SSL (443/SSL)"
			#elif "matrix_sample_ssl_1":
			#	print str(dest_ip).rstrip('\r\n)') + ": Matrix SSL default server for WiMax Devices(443/SSL)"
		elif a is not None and device is None:
			getheaders_ssl(dest_ip,dport,a,verbose,ctx,ssl_only,info)
		else:
			print "Something error happened"

		s.close()
	except KeyboardInterrupt:
                        print "Quitting"
                        sys.exit(0)
	except Exception as e:
		s.close()
		if 111 in e and ssl_only==0:
			getheaders(dest_ip,dport,verbose,info)
		elif ("timed out" or 'sslv3' in e) and ssl_only==0:
			getheaders(dest_ip,dport,verbose,info)
			pass
			if verbose is not None:
				print e
		if verbose is not None:
			print "Error Catch at line 133",e


def getheaders_ssl(dest_ip,dport,cert,vbose,ctx,ssl_only,info):
	hostname = "https://%s:%s" % (str(dest_ip).rstrip('\r\n)'),dport)

	try:
		checkheaders = urllib2.urlopen(hostname,context=ctx,timeout=4)
		server = checkheaders.info().get('Server')
		if not server:
			server = None
		html = checkheaders.read()
		soup = BeautifulSoup.BeautifulSoup(html)
		title = soup.html.head.title
		if title is None:
			title = soup.html.title
		a = title.contents
		if 'EdgeOS' in title.contents and 'Ubiquiti' in cert:
			print str(dest_ip).rstrip('\r\n)') + ": EdgeOS Device (SSL + Server header)"
		if 'ubnt.com' in cert:
			print str(dest_ip).rstrip('\r\n)') + ": Ubiquity airOS Device non-default cert (SSL)"
		elif 'iR-ADV' in cert and 'Catwalk' in title.contents:
			print str(dest_ip).rstrip('\r\n)') + ": Canon iR-ADV Login Page (SSL + Server header)"
		elif 'Cyberoam' in cert:
			print str(dest_ip).rstrip('\r\n)') + ": Cyberoam Device (SSL)"
		elif 'TG582n' in cert:
			print str(dest_ip).rstrip('\r\n)') + ": Technicolor TG582n (SSL)"
		elif 'RouterOS' in title.contents:
			print str(dest_ip).rstrip('\r\n)') + ": MikroTik RouterOS (Login Page Title)"
		elif 'axhttpd/1.4.0' in str(server):
			print str(dest_ip).rstrip('\r\n)') + ": IntelBras WOM500 (Probably admin/admin) (Server string)"
		else:
			if ssl_only==0:
				getheaders(dest_ip,80,vbose,info)
			else:
				print "Title on IP",str(dest_ip).rstrip('\r\n)'),"is", str(a.pop()).rstrip('\r\n)'),"and server is",server
		checkheaders.close()
	except Exception as e:
		if dport is 443 and ssl_only==0:
			dport = 80
			getheaders(dest_ip,dport,vbose,info)
		if vbose is not None:
			print "Error in getsslheaders: ",e
		pass
	return
def getheaders(dest_ip,dport,vbose,info):
    if dport == 443:
        dport = 80
    try:
        hostname = "http://%s:%s" % (str(dest_ip).rstrip('\r\n)'),dport)
        checkheaders = urllib2.urlopen(hostname,timeout=4)
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
            router_os_version = soup.find('body').h1.contents
            print str(dest_ip).rstrip('\r\n)') + ": MikroTik RouterOS version",str(soup.find('body').h1.contents.pop()),"(Login Page Title)"
        elif 'axhttpd/1.4.0' in str(server):
            print str(dest_ip).rstrip('\r\n)') + ": IntelBras WOM500 (Probably admin/admin) (Server string)"
        elif 'ePMP' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": Cambium ePMP 1000 Device (Server type + title)"
        elif 'Wimax CPE Configuration' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": Wimax Device (PointRed, Mediatek etc) (Server type + title)"
        elif 'NXC2500' in str(a) and server is None:
            print str(dest_ip).rstrip('\r\n)') + ": Zyxel NXC2500 (Page Title)"
        elif 'MiniServ/1.580' in server:
            print str(dest_ip).rstrip('\r\n)') + ": Multichannel Power Supply System SY4527 (Server Version)"
        elif 'IIS' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ":",str(a.pop()),"Server (Page Title)"
        elif 'Vigor' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ":",str(a.pop()), "Switch (Title)"
        elif 'Aethra' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": Aethra Telecommunications Device (Title)"
        elif 'Industrial Ethernet Switch' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": Industrial Ethernet Switch (Title)"
        elif a.count(1) == 0 and "UI_ADMIN_USERNAME" in html:
            print str(dest_ip).rstrip('\r\n)') + ": Greenpacket device Wimax Device (Empty title w/ Content)"
        elif 'NUUO Network Video Recorder Login' in a:
            print str(dest_ip).rstrip('\r\n)') + ": NUOO Video Recorder (admin/admin) (Title)"
        elif 'CDE-30364' in a:
            print str(dest_ip).rstrip('\r\n)') + ": Hitron Technologies CDE (Title)"
        elif 'BUFFALO' in a:
            print str(dest_ip).rstrip('\r\n)') + ": Buffalo Networking Device (Title)"
        elif 'Netgear' in a:
            print str(dest_ip).rstrip('\r\n)') + ": Netgear Generic Networking Device (Title)"
        elif 'IIS' in server:
            print str(dest_ip).rstrip('\r\n)') + ":",str(server),"Server (Server Version)"
        elif ('CentOS' or 'Ubuntu' or 'Debian') in str(server):
            print str(dest_ip).rstrip('\r\n)') + ":",str(server),"Linux server (Server name)"
        elif "SonicWALL" in str(server):
            print str(dest_ip).rstrip('\r\n)') + ": SonicWALL Device (Server name)"
        elif "iGate" in a:
            print str(dest_ip).rstrip('\r\n)') + ": iGate Router or Modem (Server name)"
        elif 'LG ACSmart Premium' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": LG ACSmart Premium (admin/admin) (Server name)"
        elif 'IFQ360' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": Sencore IFQ360 Edge QAM (Title)"
        elif 'Tank Sentinel AnyWare' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": Franklin Fueling Systems Tank Sentinel System (Title)"
        elif 'Z-World Rabbit' in str(server):
            print str(dest_ip).rstrip('\r\n)') + ": iBootBar (Server)"
        else:
            if info is not None:
                print "Title on IP",str(dest_ip).rstrip('\r\n)'),"is", str(a.pop()).rstrip('\r\n)'),"and server is",server
            else:
                pass
        checkheaders.close()
    except Exception as e:
        if vbose is not None:
            print "Error in getheaders(): ",e
        pass


def recurse_DNS_check(dest_ip,vbose):
	myResolver = dns.resolver.Resolver()
	myResolver.nameservers = [str(dest_ip)]
	try:
		if vbose is not None:
			print "Trying: ",dest_ip
		start = time.time()
		while time.time() < start + 3:
			myAnswers = myResolver.query("google.com", "A")
			if myAnswers:
				print dest_ip, "is vulnerable to DNS AMP"
				break
			else:
				print dest_ip, "is a nope"
				break
		else:
			print dest_ip, "is a nope"
	except KeyboardInterrupt:
		print "Quitting"
		sys.exit()
	except:
		print dest_ip, "is not vulnerable to DNS AMP"
		pass


def recurse_ssdp_check(dest_ip,vbose):
	#try:
	try:
		a = ssdp_info.get_ssdp_information(dest_ip)
		if a is None:
			print dest_ip, "is not an SSDP reflector"
		elif a is not None:
			print dest_ip, "is an SSDP reflector"
		elif vbose is not None and a is not None:
			print dest_ip, "is an SSDP reflector with result", a

	except KeyboardInterrupt:
		if KeyboardInterrupt:
			sys.exit(1)
		print "Quitting in here"
		sys.exit(0)
	except Exception as e:
		print "Encountered exception",e


def ntp_monlist_check(dest_ip,vbose):
	try:
		a = ntp_function.NTPscan().monlist_scan(dest_ip)
		if a is None:
			print dest_ip, "is not vulnerable to NTP monlist"
			pass
		elif a == 1:
			print dest_ip, "is vulnerable to monlist"
	except KeyboardInterrupt:
		print "Quitting"
		sys.exit(1)
	except Exception as e:
		if vbose is not None:
			print "Error in ntp_monlist",e
		pass


if __name__ == '__main__':
	main()
