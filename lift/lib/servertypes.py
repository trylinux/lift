import urllib2

def servertypes(ipaddr):
	
	host = urllib2.urlopen("http://96.245.113.24").info().getheader('Server')
