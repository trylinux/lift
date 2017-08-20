from __future__ import print_function
from __future__ import absolute_import
from contextlib import contextmanager
import argparse
import itertools
import json
import logging
import os
import subprocess
import sys
import socket
import ssl
import urllib2

import BeautifulSoup
import IPy
import jsonschema
import netaddr
import pyasn
import colorlog

local_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(local_path + '/lib')
from .lib.ssdp_functions import recurse_ssdp_check
from .lib.ntp_functions import ntp_monlist_check
from .lib.dns_functions import recurse_DNS_check

logger = colorlog.getLogger()


def configure_logging(logger, level=logging.DEBUG, write_to_file=False, filename=''):
    '''Configure the logger.

    Args:
        level (str, optional): Sets the severity level of the messages to be
            displayed in the log. Defaults to logging.DEBUG, the lowest level.
        write_to_file (str, optional): Whether to write the log messages to a
            file. Defaults to False.
        filename (str, optional): The name of the file where log messages
            should be written. Defaults to '' since log messages are written to
            the console by default.

    Returns:
        None
    '''
    format = '%(asctime)s - %(module)s - %(levelname)s - %(message)s'
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
        msg  -- explanation of the error
    '''
    def __init__(self, msg):
        self.msg = msg


def parse_args():
    '''Parse the command line attributes and return them as the dict `options`.
    '''
    parser = argparse.ArgumentParser(description='Low Impact Identification'
                                     ' Tool')
    argroup = parser.add_mutually_exclusive_group(required=True)
    argroup.add_argument("-i", "--ip", dest='ip', help="An IP address")
    argroup.add_argument("-f", "--ipfile", dest='ipfile', help="A file of IPs")
    argroup.add_argument("-s", "--subnet", dest='subnet', help="A subnet!")
    argroup.add_argument("-a", "--asn", dest='asn', type=int,
                         help="ASN number. WARNING: This will take a while")
    parser.add_argument("-p", "--port", dest='port', type=int, default=443,
                        help=" The port number at the supplied IP address that"
                        " lift should connect to")
    parser.add_argument("-r", "--recurse", dest='recurse', action="store_true",
                        default=False, help="Test Recursion")
    parser.add_argument("-R", "--recon", dest='recon', action="store_true",
                        default=False, help="Gather info about a given device")
    parser.add_argument("-v", "--verbose", dest='verbose', action="store_true",
                        default=False, help="WARNING DO NOT USE -v UNLESS YOU"
                        "WANT ALL THE REASONS WHY SOMETHING IS FAILING.")
    parser.add_argument("-o", "--outfile", dest='outfile', default='./outfile.txt',
                    help=" Where to write the results of this IP scanning")
    # TODO Is --ssl flag still needed?
    args = parser.parse_args()
    options = vars(args)
    logger.debug('Parsed the cli args: %s' % options)
    return options


def get_ips_from_ip(options):
    '''Return a list with the IP address supplied to the command line.
    '''
    return [options['ip']] if options['ip'] else []


@contextmanager
def opened_w_error(filename, mode="r"):
    '''
    A factory function that allows us to enter and exit the opened file context
    while also catching and yielding any errors that occur in that context.

    Args:
        filename (str): The name of the file to be opened.
        mode (str, optional): String indicating how the file is to be opened.
            Defaults to 'r', reading mode.

    Yields:
        f (file):  The file object.
        err (IOError): If the file cannot be opened.
    '''
    try:
        f = open(filename, mode)
    except IOError as err:
        yield None, err
    else:
        try:
            yield f, None
        finally:
            f.close()


def get_ips_from_file(options):
    '''Read each line of the IP file and return a list of IP addresses.
    '''
    ip_list = []

    with opened_w_error(options['ipfile']) as (f, err):
        if err:
            logger.error(err)
        else:
            ip_list = f.readlines()
            logger.debug("Found %d IPs in the given ipfile: %s" %
                        (len(ip_list), options['ipfile']))
    return ip_list


def get_ips_from_subnet(options):
    '''Return a list of IP addresses in the given subnet.
    '''
    ip_list = []

    try:
        ip_list = [ip for ip in netaddr.IPNetwork(options['subnet'])]
        logger.debug("Found %d IPs in the given subnet: %s" %
                    (len(ip_list), options['subnet']))
    except (netaddr.core.AddrFormatError, ValueError) as err:
        logger.error(err)

    return ip_list


def get_ips_from_asn(options):
    '''Lookup and return a list of IP addresses associated with the
    subnets in the given Autonomous System Number.
    '''
    ip_list = []

    try:
        ipasn_file = local_path + '/lib/ipasn.dat'
        asndb = pyasn.pyasn(ipasn_file)
        subnets = [subnet for subnet in asndb.get_as_prefixes(options['asn'])]
        logger.debug("Found %d prefixes advertised by the given ASN: %s" %
                    (len(subnets), options['asn']))
    except Exception as err:
        logger.error("AsnError: %s" % err)
    else:
        # creates a nested list of lists
        nested_ip_list = [get_ips_from_subnet(subnet) for subnet in subnets]

        # flattens the nested list into a shallow list
        ip_list = itertools.chain.from_iterable(nested_ip_list)

    return ip_list


def convert_input_to_ips(options):
    '''Call the correct function to normalize the command line argument that
    contains the IP addresses, and return a list of IP addresses.
    '''
    try:
        dispatch = {
            'ip': get_ips_from_ip,
            'ipfile': get_ips_from_file,
            'subnet': get_ips_from_subnet,
            'asn': get_ips_from_asn,
        }
        correct_function = next(v for k, v in dispatch.items() if options[k])
        ip_list = correct_function(options)
        return ip_list
    except StopIteration as KeyError:
        raise UsageError('None of the cli arguments contained IP addresses.')


def is_valid_ip(ip):
    '''Try to create an IP object using the given ip.
    Return True if an instance is successfully created, otherwise return False.
    '''
    valid = isinstance(ip, netaddr.ip.IPAddress)
    if valid:
        return valid

    try:
        valid = True if IPy.IP(ip) else False
    except ValueError as TypeError:
        logger.error('%s is not a valid IP address' % ip)

    return valid


def get_certs_from_handshake(options):
    '''Negotiates an SSL connection with the given IP address.

    Args:
        options: Keyword arguments containing the user-supplied, cli inputs.

    Returns:
        der_cert (bytes): The SSL certificate as a DER-encoded blob of bytes.
            Defaults to None.
        pem_cert: The SSL certificate as a PEM-encoded string. Defaults to
            empty string.
        ctx (SSLContext): An SSLContext object with default settings.

    Raises:
        socket.error: If any socket-related errors occur.
        TypeError: If the DER-encoded cert that is provided is neither a string
            nor buffer.
        ValueError: If we attempt to get the given IP's certificate before the
            SSL handshake is done.
    '''
    der_cert = None
    pem_cert = ''
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers('ALL')

    try:
        sock = socket.socket()
        sock.settimeout(5)
        ssl_sock = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_NONE)
        ssl_sock.connect((options['ip'], options['port']))
        logger.debug('Connected to %s:%d' % (options['ip'], options['port']))

        der_cert = ssl_sock.getpeercert(True)
        if not der_cert:
            logger.info('%s did not provide an SSL certificate' % ip)

        logger.info('Received an SSL certificate: %s' % str(der_cert))
        pem_cert = str(ssl.DER_cert_to_PEM_cert(der_cert))
        logger.debug('Converted the cert from the DER to the PEM format')

    except TypeError as err:
        logger.debug('ssl.DER_cert_to_PEM_cert() raises a TypeError if the'
                     'given DER-encoded cert is neither a string nor buffer')
        logger.error(err)
    except ValueError as err:
        logger.debug('The SSL handshake might not have been done yet.'
                     'getpeercert() raises ValueError in that case')
        logger.error(err)
    except socket.error as err:
        logger.error(err)
    finally:
        sock.close()
        logger.debug('Closed socket.')
    return der_cert, pem_cert, ctx


def identify_using_http_response(options):
    '''Calls functions for each of the steps required to identify a device
    based on data in the HTTP response headers or resource.
    1. send request
    2. parse response
    3. lookup response data
    4. print findings
    '''
    device = ''
    headers, html = send_http_request(options)
    title, server = parse_response(html, headers)

    if title or server:
        device = lookup_http_data(title, server)

    if device:
        print_findings(options['ip'], device, title=title, server=server)
    else:
        logger.info('No matching title/server was found for IP %s' %
                    options['ip'])
        logger.info('Trying an RTSP request since the HTTP request(s) didn\'t'
                    ' return a helpful response.')
        send_rstp_request(options['ip'])

    return device


def send_rstp_request(ip):
    new_ip = str(ip).rstrip('\r\n)')
    bashcommand = ('curl --silent rtsp://' + new_ip +
                   ' -I -m 5| grep Server')
    try:
        logger.info('Sending RTSP request...')
        proc = subprocess.Popen(['bash', '-c', bashcommand],
                                stdout=subprocess.PIPE)
        output = proc.stdout.read()

    except Exception as err:
        logger.error(err)
    else:
        rtsp_server = str(output).rstrip('\r\n)')
        if 'Dahua' in str(rtsp_server):
            print (str(ip).rstrip('\r\n)') +
                   ": Dahua RTSP Server Detected (RTSP Server)")
    return


def send_http_request(options):
    '''Sends one HTTP request to the port number supplied via command line
    parameter OR port 443 if none was given.
    If the HTTP connection is refused (or another HTTP error is raised),
    re-attempt a request but this time to port 80.

    Args:
        options: Keyword arguments containing the user-supplied, cli inputs.

    Returns:
        headers (dict): The HTTP response headers
        html (str): The HTTP response body
    '''
    headers = {}
    html = ''

    MAX_ATTEMPTS = 2
    attempts = 1

    # options['port'] = 443
    ctx = options.get('ctx', None)

    while attempts <= MAX_ATTEMPTS:
        try:
            logger.info('Attempt %d of %d at sending HTTP request to %s:%d' %
                        (attempts, MAX_ATTEMPTS, options['ip'],
                         options['port']))
            url = "https://%s:%s" % (options['ip'], options['port'])
            response = urllib2.urlopen(url, context=ctx, timeout=10)

        except urllib2.URLError as err:
            if hasattr(err, 'reason'):
                logger.error('Failed to reach a server at %s. Reason: %s' %
                            (url, err.reason))
            elif hasattr(err, 'code'):
                logger.error('The server %s couldn\'t fulfill the request.'
                             ' Error code: %s' % (url, err.code))
            attempts += 1
            options['port'] = 80
        else:
            html = response.read()
            headers = response.info()
            response.close()
            break

    return headers, html


def parse_response(html, headers):
    '''Parse the HTML and headers from the HTTP response and return a dict with
    all extracted data.
    '''
    soup = BeautifulSoup.BeautifulSoup(html)
    title_tag = soup.find('title')
    title = str(title_tag.contents[0]) if title_tag else ''
    server = headers.get('Server') or ''
    return title, server


def print_findings(ip, device, title='', server='', outfile='./outfile.txt'):
    """Print the result to stdout and write it to the outfile"""
    msg = "IP: " + str(ip).rstrip('\r\n)') + ", data: " + device + "\n"
    extra_params = {'title': title, 'server': server}
    print(msg.format(**extra_params))

    with open(outfile, 'a') as f:
        f.write(msg.format(**extra_params))
    return

def identify_using_ssl_cert(options):
    '''Calls functions that correspond to steps involved in identifying a
    device based on data in the HTTP response headers or resource.
    1. get cert from handshake
    2. lookup cert
    3. print findings
    '''
    der_cert, pem_cert, ctx = get_certs_from_handshake(options)
    if pem_cert:
        device = lookup_cert(pem_cert)
    else:
        logger.info('IP %s did not send a PEM certificate' % options['ip'])
        device = ''
        print_findings(options['ip'], device)

    if device:
        logger.debug('Found %s as a match for the cert provided by %s' %
                    (device, options['ip']))
        print_findings(options['ip'], device)
    else:
        logger.info('No luck identifying IP %s using ssl cert.'
                    'Try using HTTP response data' % options['ip'])
        device = identify_using_http_response(options)
    return device


def process_ip(options):
    '''Call the correct function(s) to process the IP address based on the
    port and recurse options passed into the command line.

    Args:
        options: Keyword arguments containing the user-supplied, cli inputs.

    Returns:
        None

    Raises:
        ValueError: If the user-supplied combination of port number and recurse
            option is not one of cases supported in the dispatch_by_port dict.
    '''

    if options['port'] == 80:
        correct_functions = [identify_using_http_response]
    elif options['port'] != 80 and not options['recurse']:
        correct_functions = [identify_using_ssl_cert]
    elif options['port'] == 53 and options['recurse']:
        correct_functions = [recurse_DNS_check]
    elif options['port'] == 123 and options['recurse']:
        correct_functions = [ntp_monlist_check]
    elif options['port'] == 1900 and options['recurse']:
        correct_functions = [recurse_ssdp_check]
    elif options['port'] != 80 and options['recurse']:
        correct_functions = [recurse_DNS_check, ntp_monlist_check, recurse_ssdp_check]
    else:
        raise ValueError('Unsure how to handle the given port number (%d) with'
                         ' the other cli arguments' % options['port'])

    logger.debug('Calling the function %s to process IP %s' %
                (correct_functions, options['ip']))
    for func in correct_functions:
        func(options)


def setup_cert_collection():
    '''Returns the cert_lookup_dict against which the user-supplied IP
    address will be compared for matching SSL certificates or HTTP
    response data.

    Open all the JSON files in the directory `cert_collection`, and
    concatenate the data to form one massive JSON string.
    Convert this JSON string into a Python object, using json.loads()
    and return this object.
    '''
    cert_collection_path = os.path.abspath(os.path.join(local_path, 'cert_collection'))
    schemas_path = os.path.abspath(os.path.join(local_path, 'schemas'))
    cert_files = os.listdir(cert_collection_path)

    num_files = len(cert_files)

    # start concatenating the array object for the massive JSON file that will
    # contain every JSON file in the cert_collection folder
    json_file = '['

    # load the schema for all JSON files in the cert_collection directory
    cert_file_schema = ''
    with open(os.path.join(schemas_path, 'cert_file_schema.json')) as schema_file:
        cert_file_schema = json.loads(schema_file.read())

    for i in range(num_files):
        cert_file_path = os.path.join(cert_collection_path, cert_files[i])

        with opened_w_error(cert_file_path) as (f, err):
            if err:
                logger.error(err)
            else:
                file_contents = f.read()
                try:
                    cert_file = json.loads(file_contents)
                    jsonschema.validate(cert_file, cert_file_schema)
                except ValueError as e:
                    logger.error('File %s has invalid JSON. %s' %
                                (cert_file_path, str(e)))
                    num_files -= 1
                except jsonschema.exceptions.ValidationError as e:
                    logger.error('File %s is invalid given the schema. %s' %
                                (cert_file_path, str(e)))
                    num_files -= 1
                else:
                    # append the contents of this opened JSON file to that
                    # massive file we're creating
                    json_file += file_contents + ','

    # remove the trailing comma from the last JSON file we appended and
    # append a closing bracket to close the array object
    final = json_file.rstrip(',') + ']'

    global cert_lookup_dict
    cert_lookup_dict = json.loads(final)
    logger.debug('Created cert_lookup_dict using %d JSON files from dir %s' %
                 (num_files, cert_collection_path))

    return


def lookup_cert(pem_cert):
    '''Lookup the given PEM cert in a dictionary containing all the certs in
    the cert_collection directory and return the device description if there's
     a match.
    '''
    keys = [cert_lookup_dict[x]['ssl_cert_info'][y]['PEM_cert']
            for x in range(len(cert_lookup_dict))
            for y in range(len(cert_lookup_dict[x]['ssl_cert_info']))
            ]

    values = [cert_lookup_dict[x]['ssl_cert_info'][y]['display_name']
              for x in range(len(cert_lookup_dict))
              for y in range(len(cert_lookup_dict[x]['ssl_cert_info']))
              ]

    pem_dict = dict(zip(keys, values))
    logger.debug('Searching for the PEM cert (%s...) in the cert_collection '
                 'directory' % pem_cert[29:39])
    device = pem_dict.get(pem_cert, '')
    return device


def lookup_http_data(title, server):
    '''Lookup the given title and server in a dictionary containing all the
    HTTP response data in the cert_collection directory. Return the device
    description if there's a match.
    '''
    c = cert_lookup_dict

    server_search_terms = [c[x]['http_response_info'][y]['server_search_text']
                           for x in range(len(c))
                           for y in range(len(c[x]['http_response_info']))
                           ]

    title_search_terms = [c[x]['http_response_info'][y]['title_search_text']
                          for x in range(len(c))
                          for y in range(len(c[x]['http_response_info']))
                          ]

    display_names = [c[x]['http_response_info'][y]['display_name']
                     for x in range(len(c))
                     for y in range(len(c[x]['http_response_info']))
                     ]

    lookup_list = zip(server_search_terms, title_search_terms, display_names)
    logger.debug('Searching for the title (%s) and server (%s) in the'
                 ' cert_collection directory' % (title, server))
    device_description = next((n[2] for n in lookup_list
                               if n[0] in server and n[1] in title), '')
    return device_description


def main():
    configure_logging(logger)
    setup_cert_collection()
    options = parse_args()

    ip_list = convert_input_to_ips(options)
    for ip in ip_list:
        if is_valid_ip(ip):
            # cast the ip value as a string in case it's type is IPNetwork.
            options['ip'] = str(ip)
            process_ip(options)
            logger.debug('Done trying to identify IP %s' % ip)


if __name__ == '__main__':
    main()
