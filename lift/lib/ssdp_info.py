from ssdp_function import *
import re
import json

def get_ssdp_information(ipaddr):

	string = (ssdp_scan().active_scan('201.180.96.183')).splitlines
	for index,item in enumerate(string()):
			if "SERVER" in item:
 				server_information = re.sub('SERVER\: ', '', item)
 			elif "LOCATION" in item:
 				ssdp_location = re.sub('LOCATION\: ', '', item)
	a = {'server':server_information, 'upnp_location': ssdp_location}
	b = json.dumps(a)
	return b
