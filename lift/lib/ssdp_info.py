from ssdp_function import ssdp_scan
import re
import json
import sys

def get_ssdp_information(ipaddr):
	try:
		string = (ssdp_scan().active_scan(str(ipaddr))).splitlines
		if string is not None:
			for index,item in enumerate(string()):
					if "SERVER" in item:
						server_information = re.sub('SERVER\: ', '', item)
					elif "LOCATION" in item:
						ssdp_location = re.sub('LOCATION\: ', '', item)
			if server_information is not None:
				a = {'server':server_information, 'upnp_location': ssdp_location}
				b = json.dumps(a)
			else:
				b = None
		else:
			b = None
	except KeyboardInterrupt:
		print "Quitting"
		sys.exit(0)
	except:
		b = None
	return b
