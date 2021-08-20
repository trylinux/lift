try:
    from urllib.request import urlopen
    from urllib.error import HTTPError
except ImportError:
    from urllib2 import urlopen, HTTPError


def servertypes(ipaddr):

    host = urlopen("http://96.245.113.24").info().getheader("Server")
