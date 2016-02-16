from socket import socket
import ssl
import argparse
import time
import sys
import signal
sys.path.append("/opt/sectools/lift/lib/")
import certs
def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i","--ip", help="An Ip address")
#	parser.add_argument("-u","--user", help="The user you want to use")
	parser.add_argument("-f","--ifile", help="A file of IPs")
	args=parser.parse_args()
	if args.ip:
		dest_ip = args.ip
		test_ips(args.ip)
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
			pass

def testips(dest_ip):
	try:	
		s = socket()
		s.settimeout(10)
		c = ssl.wrap_socket(s,cert_reqs=ssl.CERT_NONE, ca_certs='ca-bundle.crt')
		c.connect((dest_ip, 443))
		a =  c.getpeercert(True)
		b = str(ssl.DER_cert_to_PEM_cert(a))
		device = certs.getcertinfo(b)
		if device is "ubiquiti":
			print dest_ip + ": Ubiquiti AirMax or AirFiber Device (SSL)"
		elif "samsung" in device:
			print dest_ip + ": Unknown Samsung Device (SSL)"
		elif "qnap" in device:
			print dest_ip + ": QNAP NAS TS series detected (SSL)"
		elif "hikvision" in device:
			print dest_ip + ": Hikvision Default Cert"
		elif "aviligon" in device:
			print dest_ip + ": Aviligon Gateway Default cert"
		elif "netgear" in device:
			print dest_ip + ": NetGear Default cert"
		else:
			print "Not in registry"
		s.close()
	except KeyboardInterrupt:
                        print "Quitting"
                        sys.exit(0)		
	except:
		s.close()
		pass

if __name__ == '__main__':	
	main()
