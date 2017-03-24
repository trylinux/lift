import argparse
import itertools
import json
import logging
import os
import subprocess
import sys
import socket
import ssl
import time
import urllib2

import BeautifulSoup
import colorlog
import dns.resolver
import netaddr
import pyasn

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
import ssdp_info
import ntp_function


logger = colorlog.getLogger('lift')


def configure_logging(level=logging.DEBUG, write_to_file=False, filename=''):
    '''Configure the logger by specifying the format for the log messages,
    whether to write the messages to the console or a file, and by
    setting the severity level of the messages to control the type
    of messages displayed in the log.
    '''
    format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    if write_to_file:
        handler = logging.FileHandler(filename)
        formatter = logging.Formatter(format)
    else:
        handler = colorlog.StreamHandler()
        formatter = colorlog.ColoredFormatter(
            '%(log_color)s' + format,
            datefmt=None,
            reset=True,
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'purple',
            },
            secondary_log_colors={},
            style='%'
        )

    logger.setLevel(level)
    handler.setFormatter(formatter)
    logger.addHandler(handler)


class UsageError(Exception):
    '''Exception raised for errors in the usage of this module.

    Attributes:
        expr -- input expression in which the error occurred
        msg  -- explanation of the error
    '''

    def __init__(self, expr, msg):
        self.expr = expr
        self.msg = msg


def parse_args():
    '''Parse the command line attributes and return them as the dict `options`.
    '''
    parser = argparse.ArgumentParser(description='Low Impact Identification Tool')
    argroup = parser.add_mutually_exclusive_group(required=True)
    argroup.add_argument("-i", "--ip", dest='ip', help="An IP address")
    argroup.add_argument("-f", "--ifile", dest='ifile', help="A file of IPs")
    parser.add_argument("-p", "--port", dest='port', type=int, default=443,
                        help="A port")
    parser.add_argument("-v", "--verbose", dest='verbose',
                        help=("Not your usual verbosity. This is for debugging "
                              "why specific outputs aren't working! USE WITH "
                              "CAUTION"))
    argroup.add_argument("-s", "--subnet", dest='subnet', help="A subnet!")
    argroup.add_argument("-a", "--asn", dest='asn', type=int,
                         help=("ASN number. WARNING: This will take a while"))
    parser.add_argument("-r", "--recurse", dest='recurse', action="store_true",
                        default=False, help="Test Recursion")
    parser.add_argument("-I", "--info", dest='info', action="store_true",
                        default=False, help="Get more info about operations")
    parser.add_argument("-S", "--ssl", dest='ssl_only', action="store_true",
                        default=False, help="For doing SSL checks only", )
    parser.add_argument("-R", "--recon", dest='recon', action="store_true",
                        default=False, help="Gather info about a given device")
    args = parser.parse_args()
    options = vars(args)    
    return options


def get_ips_from_ip(options):
    '''Return a list with the IP address supplied to the command line.
    '''
    return list(options['ip'])


def get_ips_from_file(options):
    '''Read each line of the IP file and return a list of IP addresses.
    '''
    ip_list = []

    with open(options['ifile']) as f:
        ip_list = f.readlines()
    
    # TODO add a more specific exception, like IOError
    # https://www.python.org/dev/peps/pep-0343/
    return ip_list


def get_ips_from_subnet(options):
    '''Return a list of IP addresses in the given subnet.
    '''
    ip_list = []

    try:
        ip_list = [ip for ip in netaddr.IPNetwork(options['subnet'])]
    except Exception as e:
    # TODO replace with more specific exception:
    # http://netaddr.readthedocs.io/en/latest/_modules/netaddr/core.html#AddrFormatError
        sys.exit()

    return ip_list


def get_ips_from_asn(options):
    '''Lookup and return a list of IP addresses associated with the
    subnets in the given Autonomous System Number.
    '''
    ip_list = []
    libpath = os.path.dirname(os.path.realpath(__file__)) + '/lib'
    asndb = pyasn.pyasn(libpath + '/ipasn.dat')

    subnets = [subnet for subnet in asndb.get_as_prefixes(options['asn'])]

    # creates a nested list of lists
    nested_ip_list = [get_ips_from_subnet(subnet) for subnet in subnets]

    # flattens the nested list to a shallow list
    ip_list = itertools.chain.from_iterable(nested_ip_list)
    
    return ip_list


def get_certs_from_handshake(dest_ip, **kwargs):
    '''Perform a SSL handshake with the given IP address, and
    return the SSLContext object, as well as two formats of the SSL certificate,
    a DER-encoded blob of bytes and a PEM-encoded string.  
    '''
    dport = kwargs['port']
    verbose = kwargs['verbose']
    ssl_only = kwargs['ssl_only']
    info = kwargs['info']
    
    PEM_cert = ''

    # Create a new SSLContext object `ctx` with default settings
    ctx = ssl.create_default_context()
    
    # Do not match the peer cert's hostname with match_hostname() in
    # SSLSocket.do_handshake().
    ctx.check_hostname = False

    # The verify_mode attribute is about whether to try to verify other peers'
    # certificates and how to behave if verification fails.
    # In the CERT_NONE mode, no certificates will be required from the other
    # side of the socket connection. If a certificate is received from the other
    # end, no attempt to validate it is made.
    ctx.verify_mode = ssl.CERT_NONE

    # Set the available ciphers for sockets created with this context.
    ctx.set_ciphers('ALL')
    
    # Create an instance `sock` of socket.socket
    sock = socket.socket()

    # Set a timeout on blocking socket operations. Raise a timeout exception
    # if the timeout period value has elapsed before the operation has completed.
    sock.settimeout(5)

    try:
        # Takes an instance sock of socket.socket, and returns an instance
        # of ssl.SSLSocket
        ssl_sock = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_NONE)

        # Connect to a remote socket at the given IP address on the given port
        ssl_sock.connect((dest_ip, dport))

        # DER_cert is either an ssl certificate, provided as DER-encoded blob of
        # bytes, or None if the peer did not provide a certificate.
        # If the SSL handshake hasn't been done yet, getpeercert() raises ValueError.
        DER_cert = ssl_sock.getpeercert(True)

        # PEM_cert is a PEM-encoded string version of the ssl certificate
        # If DER_cert is not a string or buffer,
        # DER_cert_to_PEM_cert() raises TypeError.
        PEM_cert = str(ssl.DER_cert_to_PEM_cert(DER_cert))

    except KeyboardInterrupt:
        print "Quitting"
        sys.exit(0)

    except Exception as e:
        # TODO replace with more specific exceptions:
        # SSLError (a subtype of socket.error), a more specific SSLError, 
        # socket time out, socket.error
        # If the SSL handshake hasn't been done yet, getpeercert() raises ValueError.
        if verbose:
            print "Error Catch at line 268 ", e
    
    # Close the socket. All future operations on the socket object will fail
    sock.close()

    return DER_cert, PEM_cert, ctx
        

def recurse_DNS_check(dest_ip, **kwargs):
    '''Check whether the device, indicated by the given IP address, is
    is vulnerable to DNS amplication.
    '''
    vbose = kwargs['verbose']
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
    except:  # TODO replace with more specific exception
        print dest_ip, "is not vulnerable to DNS AMP"
        


def recurse_ssdp_check(dest_ip, **kwargs):
    '''Check whether the device, indicated by the given IP address, is
    is an SSDP reflector.
    '''
    vbose = kwargs['verbose']
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
    except Exception as e:  # TODO replace with more specific exception
        print "Encountered exception",e


def ntp_monlist_check(dest_ip, **kwargs):
    '''Check whether the device, indicated by the given IP address, is
    vulnerable to the NTP monlist command.
    '''
    try:
        a = ntp_function.NTPscan().monlist_scan(dest_ip)
        if a is None:
            print dest_ip, "is not vulnerable to NTP monlist"
        elif a == 1:
            print dest_ip, "is vulnerable to monlist"
    except KeyboardInterrupt:
        print "Quitting"
        sys.exit(1)


def is_host_up(dest_ip, **kwargs):
    '''Issue the ping (Packet INternet Groper) command to check if there is a 
    network connection to the given IP address. If there is no connectivity,
    call the testips() function. 
    '''
    dport = kwargs['port']
    verbose = kwargs['verbose']
    response = os.system("ping -c 1 " + dest_ip)
    if response == 0:
          test_ip(dest_ip, **kwargs)
    # TODO think about a relevant exception


def is_valid_ip(ip):
    '''Try to create an IP object using the given ip.
    Return True if an instance is successfully created, otherwise return False.
    '''
    # TODO install & import IPy
    return True


def convert_input_to_ips(options):
    '''Call the correct function to normalize the command line argument that
    contains the IP addresses, and return a list of IP addresses.
    '''
    try:
        dispatch = {
            'ip': get_ips_from_ip,
            'ifile': get_ips_from_file,
            'subnet': get_ips_from_subnet,
            'asn': get_ips_from_asn,
        }

        correct_function = next(v for k, v in dispatch.items() if options[k])
        ip_list = correct_function(options)
        return ip_list
    except KeyError:
        raise ValueError('None of the cli arguments contained IP addresses.')


def identify_using_http_response(ip, **kwargs):
    '''Calls functions for each of the steps required to identify a device
    based on data in the HTTP response headers or resource.
    1. send request
    2. parse response
    3. lookup response data
    4. print findings
    '''
    headers, html = send_http_request(ip, **kwargs)
    title, server = parse_response(html, headers)
    device = lookup_http_data(title, server, cert_lookup_dict)
    if device:
        print_findings(ip, device, title=title, server=server)
    else:
        logger.info('No matching certs were found for IP %s' % ip)        
        # TODO add logic to try rtsp request if http doesn't provide info

    return device


def send_rstp_request(dest_ip):
    new_ip = str(dest_ip).rstrip('\r\n)')
    bashcommand = ('curl --silent rtsp://'+ new_ip +
                   ' -I -m 5| grep Server')
    proc = subprocess.Popen(['bash','-c', bashcommand], 
                            stdout=subprocess.PIPE)
    output = proc.stdout.read()
    rtsp_server = str(output).rstrip('\r\n)')
    if 'Dahua' in str(rtsp_server):
        print (str(dest_ip).rstrip('\r\n)') + 
               ": Dahua RTSP Server Detected (RTSP Server)")
    return


def send_http_request(ip, **kwargs):
    #TODO add logic to try port 443, then port 80
    url = "https://%s:%s" % (ip, kwargs['port'])
    ctx = kwargs.get('ctx', None)
    
    f = urllib2.urlopen(url, context=ctx, timeout=10)
    
    html = f.read()
    headers = f.info()
    f.close()
    
    return headers, html


def parse_response(html, headers):
    '''Parse the HTML and headers from the HTTP response and return a dict with
    all extracted data. 
    '''
    # TODO figure out relevant exception from parsing to catch/react to
    soup = BeautifulSoup.BeautifulSoup(html)
    title_tag = soup.find('title')
    title = str(title_tag.contents[0]) if title_tag else ''
    server = headers.get('Server') or ''

    return title, server


def print_findings(ip, device, title='', server=''):
    msg = str(ip).rstrip('\r\n)') + ": " + device
    extra_params = {'title': title, 'server': server}
    print msg.format(**extra_params)


def identify_using_ssl_cert(ip, **kwargs):
    '''Calls functions that correspond to steps involved in identifying a device
    based on data in the HTTP response headers or resource.
    1. get cert from handshake 
    2. lookup cert
    3. print findings
    '''
    DER_cert, PEM_cert, ctx = get_certs_from_handshake(ip, **kwargs)
    device = lookup_cert(pem_cert, cert_lookup_dict)
    if device:
        print_findings(ip, device)
    else:
        logger.info('No matching certs were found for IP %s' % ip)
    return device


def process_ip(ip, options):
    '''Call the correct function(s) to process the IP address based on the
    port and recurse options passed into the command line..
    '''
    dispatch_by_port = {
        options['port'] == 80: (identify_using_http_response),
        options['port'] != 80 and not options['recurse']: (identify_using_ssl_cert),
        options['port'] == 53 and options['recurse']: (recurse_DNS_check),
        options['port'] == 123 and options['recurse']: (ntp_monlist_check),
        options['port'] == 1900 and options['recurse']: (recurse_ssdp_check),
        options['port'] != 80 and options['recurse']: (
            recurse_DNS_check, ntp_monlist_check, recurse_ssdp_check),
    }

    try:
        correct_functions = dispatch_by_port[True]
        [func(ip, **options) for func in correct_functions]
    except KeyError:
        raise ValueError('Invalid port number was supplied by the user.')


def setup_cert_collection():
    '''Returns the cert_lookup_dict against which the user-supplied IP
    address will be compared for matching SSL certificates or HTTP
    response data.

    Open all the JSON files in the directory `cert_collection`, and
    concatenate the data to form one massive JSON string.
    Convert this JSON string into a Python object, using json.loads()
    and return this object.
    '''
    json_file = '['
    cert_collection_path = (os.path.dirname(os.path.realpath(__file__)) + 
                            '/cert_collection')
    cert_files = os.listdir(cert_collection_path)
    
    num_files = len(cert_files)
    
    for x in range(num_files):
        cert_file = cert_collection_path + '/' + cert_files[x]
        
        with open(cert_file) as f:
            try:
                file_contents = f.read()
                json.loads(file_contents)
            except ValueError:
                logger.error('File %s is an invalid JSON object' % cert_file)
                num_files -= 1
            else:
                json_file += file_contents  + ','

    final = json_file.rstrip(',') + ']'
    cert_lookup_dict = json.loads(final)
    logger.debug('Created cert_lookup_dict using %d manufacturer JSON files' 
                 % num_files)

    return cert_lookup_dict


def lookup_cert(pem_cert, cert_lookup_dict):
    '''Lookup the given PEM cert in a dictionary containing all the certs in
    the cert_collection directory and return the device description if there's
     a match.
    '''
    keys =  [cert_lookup_dict[x]['ssl_cert_info'][y]['PEM_cert'] 
             for x in range(len(cert_lookup_dict)) 
             for y in range(len(cert_lookup_dict[x]['ssl_cert_info']))
            ]
    
    values = [cert_lookup_dict[x]['ssl_cert_info'][y]['display_name'] 
              for x in range(len(cert_lookup_dict))
              for y in range(len(cert_lookup_dict[x]['ssl_cert_info']))
              ]   

    pem_dict = dict(zip(keys, values))
    device = pem_dict.get(pem_cert, '')   
    return device


def lookup_http_data(title, server, cert_lookup_dict):
    '''Lookup the given title and server in a dictionary containing all the
    HTTP response data in the cert_collection directory. Return the device 
    description if there's a match.
    '''
    c = cert_lookup_dict

    server_search_terms =  [c[x]['http_response_info'][y]['server_search_text'] 
                            for x in range(len(c)) 
                            for y in range(len(c[x]['http_response_info']))
                            ]
    
    title_search_terms =  [c[x]['http_response_info'][y]['title_search_text'] 
                           for x in range(len(c)) 
                           for y in range(len(c[x]['http_response_info']))
                           ]

    display_names = [c[x]['http_response_info'][y]['display_name'] 
              for x in range(len(c))
              for y in range(len(c[x]['http_response_info']))
              ]   

    lookup_list = zip(server_search_terms, title_search_terms, display_names)
    
    device_description = next((n[2] for n in lookup_list 
                               if n[0] in server and n[1] in title), '')
    return device_description


def main():
    configure_logging()
    options = parse_args()
    cert_lookup_dict = setup_cert_collection()
    results = []
    try:
        ip_list = convert_input_to_ips(options)
        for ip in ip_list:
            if is_valid_ip(ip):
                process_ip(ip, options)
                msg = '%s : success' % ip
            else:
                msg = '%s : fail' % ip

            results.append(msg) 
        return results
    except KeyboardInterrupt:
        print "Quitting"
        sys.exit(0)
    except Exception as e:  
        # TODO remove or replace with more specific exception
        print "Encountered an error ",e


if __name__ == '__main__':
    main()
