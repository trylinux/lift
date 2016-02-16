from socket import socket
import ssl
import argparse
import time
import sys
sys.path.append("lib/")
import certs
def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i","--ip", help="An Ip address")
#	parser.add_argument("-u","--user", help="The user you want to use")
	args=parser.parse_args()
	dest_ip = args.ip
	start = time.time()
	while time.time() < start + 5:
		try:
			s = socket()
			s.settimeout(10)
			c = ssl.wrap_socket(s,cert_reqs=ssl.CERT_NONE, ca_certs='ca-bundle.crt')
			c.connect((dest_ip, 443))
			a =  c.getpeercert(True)
			b = str(ssl.DER_cert_to_PEM_cert(a))
			#print b
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
			

			#if r  ==  b:
			#	print dest_ip +  ": Ubiquiti Device -- Non-EdgeOS "
			#if  qnap_3 == b or qnap_1 == b or qnap_2 == b or qnap_4 == b:
		#		print dest_ip + ": QNAP NAS"
		#	if cisco_sa450g == b:
		#		print dest_ip + ": Cisco SA40G"
		#	if samsung_device == b:
		#		print dest_ip + ": Samsung Device-Unknown"
		#	if belair_1 == b:
		#		print dest_ip + ": Belair Device"
		#	if aviligon_gateway == b:
		#		print dest_ip + ": Avigilon Gateway"
		#	if hikvision == b:
		#		print dest_ip + ": Hikvision"
			break	
			s.close()
		except KeyboardInterrupt:
			s.close()
                	print "Quitting "
               	 	sys.exit(0)
		except:
			s.close()
			pass


if __name__ == '__main__':	
	main()
	#except KeyboardInterrupt:
	#	print "Quitting "
         #       sys.exit(0)
