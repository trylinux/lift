import os
import subprocess
import sys
from socket import socket
import ssl
import argparse
import time
import itertools
import logging
import urllib2
import BeautifulSoup
import netaddr
import os
import pyasn
import dns.resolver
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
import ssdp_info
import ntp_function
import certs

# create logger
logger = logging.getLogger('lift')


def configure_logging():
    logger.setLevel(logging.DEBUG)

    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - '
                                  '%(message)s')

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    return logger

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
    logger.debug('Starting parse_args')
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
                        default=False,help="Test Recursion")
    parser.add_argument("-I", "--info", dest='info', action="store_true",
                        default=False, help="Get more info about operations")
    parser.add_argument("-S", "--ssl", dest='ssl_only', action="store_true",
                        default=False, help="For doing SSL checks only", )
    parser.add_argument("-R", "--recon",dest='recon', action="store_true",
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
    subnets = [subnet for subnet in asndb.get_as_prefixes(options['asn'])]
    
    # creates a nested list of lists
    nested_ip_list = [get_ips_from_subnet(subnet) for subnet in subnets]

    # flattens the nested list to a shallow list
    ip_list = itertools.chain.from_iterable(nested_ip_list)
    
    return ip_list


def convert_input_to_ips(options):
    '''Call the correct function to normalize the `options` dict, containing all
    command line arguments, into a list of ip addresses.
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


def process_ip(ip, options):
    '''Call the correct function(s) to process the IP address based on the
    port and recurse options passed into the command line..
    '''
    dispatch_by_port = {
        options['port'] == 80: (getheaders),
        options['port'] != 80 and not options['recurse']: (testips),
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


def is_valid_ip(ip):
    '''Try to create an IP object using the given ip.
    Return True if an instance is successfully created, otherwise return False.
    '''
    # TODO install & import IPy
    return True


def ishostup(dest_ip, **kwargs):
    dport = kwargs['port']
    verbose = kwargs['verbose']
    response = os.system("ping -c 1 " + dest_ip)
    if response == 0:
          testips(dest_ip, **kwargs)
    # TODO think about a relevant exception

def testips(dest_ip, **kwargs):
    dport = kwargs['port']
    verbose = kwargs['verbose']
    ssl_only = kwargs['ssl_only']
    info = kwargs['info']
    
    device = None

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
    sock = socket()

    # Set a timeout on blocking socket operations. Raise a timeout exception
    # if the timeout period value has elapsed before the operation has completed.
    sock.settimeout(5)

    try:
        # Takes an instance sock of socket.socket, and returns an instance
        # of ssl.SSLSocket
        ssl_sock = ssl.wrap_socket(sock,cert_reqs=ssl.CERT_NONE)

        # Connect to a remote socket at the given IP address on the given port
        ssl_sock.connect((dest_ip,dport))

        # DER_cert is either an ssl certificate, provided as DER-encoded blob of
        # bytes, or None if the peer did not provide a certificate.
        # If the SSL handshake hasn't been done yet, getpeercert() raises ValueError.
        DER_cert = ssl_sock.getpeercert(True)

        # PEM_cert is a PEM-encoded string version of the ssl certificate
        # If DER_cert is not a string or buffer,
        # DER_cert_to_PEM_cert() raises TypeError.
        PEM_cert = str(ssl.DER_cert_to_PEM_cert(DER_cert))

        # device is the name of the device corresponding to the cert.
        # lookup the cert in a dict containing 54 key-pairs {cert:device,...}
        device = (certs.getcertinfo(PEM_cert))

        if device is not None:
            if device is "ubiquiti":
                print str(dest_ip).rstrip('\r\n)') + ": Ubiquiti AirMax or AirFiber Device (SSL)"
            if "UBNT" in device:
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
            elif 'meru_net_1' in device:
                print str(dest_ip).rstrip('\r\n)') + ": Meru Network Management Device  (443/SSL)"
            #elif "matrix_sample_ssl_1":
            #    print str(dest_ip).rstrip('\r\n)') + ": Matrix SSL default server for WiMax Devices(443/SSL)"
        elif DER_cert is not None and device is None:
            kwargs.update({'cert': DER_cert, 'ctx': ctx})
            getheaders_ssl(dest_ip, **kwargs)
        else:
            print "Something error happened"

        # Close the socket. All future operations on the socket object will fail
        sock.close()
    except KeyboardInterrupt:
                        print "Quitting"
                        sys.exit(0)
    except Exception as e:
    # TODO replace with more specific exceptions:
    # SSLError (a subtype of socket.error), a more specific SSLError, socket time out, socket.error
    # If the SSL handshake hasn't been done yet, getpeercert() raises ValueError.

        sock.close()
        if 111 in e and ssl_only == 0:
            getheaders(dest_ip,dport,verbose,info)
        elif ("timed out" or 'sslv3' in e) and ssl_only==0:
            getheaders(dest_ip,dport,verbose,info)
            pass
            if verbose is not None:
                print e
        if verbose is not None:
            print "Error Catch at line 133 ",e


def getheaders_ssl(dest_ip, **kwargs):
    dport = kwargs['port']
    vbose = kwargs['verbose']
    ssl_only = kwargs['ssl_only']
    info = kwargs['info']
    cert = kwargs['cert']  # TODO how to pass this into kwargs??
    ctx = kwargs['ctx']  # TODO how to pass this into kwargs??
    hostname = "https://%s:%s" % (str(dest_ip).rstrip('\r\n)'),dport)

    try:
        checkheaders = urllib2.urlopen(hostname,context=ctx,timeout=10)
        if ('ubnt.com','UBNT') in cert:
                        print str(dest_ip).rstrip('\r\n)') + ": Ubiquity airOS Device non-default cert (SSL)"
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
        if ('ubnt.com','UBNT') in cert:
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
                kwargs['port'] = 80
                getheaders(dest_ip, **kwargs)
            else:
                print "Title on IP",str(dest_ip).rstrip('\r\n)'), "is", str(a.pop()).rstrip('\r\n)'), "and server is",server
        checkheaders.close()
    except Exception as e:  # TODO replace with more specific exceptions:
        if dport is 443 and ssl_only==0:
            dport = 80
            getheaders(dest_ip,dport,vbose,info)
        if vbose is not None:
            print "Error in getsslheaders: ",e
    return


def getheaders(dest_ip, **kwargs):
    dport = kwargs['port']
    vbose = kwargs['verbose']
    info = kwargs['info']

    if dport == 443:
        dport = 80
    try:
        hostname = "http://%s:%s" % (str(dest_ip).rstrip('\r\n)'),dport)
        checkheaders = urllib2.urlopen(hostname,timeout=10)
        try:
            server = checkheaders.info().get('Server')
        except:  # TODO replace with more specific exception
            server = None
        html = checkheaders.read()
        soup = BeautifulSoup.BeautifulSoup(html)
        title = soup.html.head.title
        if title is None:
            title = soup.html.title
        a = title.contents
        if 'RouterOS' in str(a) and server is None:
            router_os_version = soup.find('body').h1.contents
            print str(dest_ip).rstrip('\r\n)') + ": MikroTik RouterOS version",str(soup.find('body').h1.contents.pop()), "(Login Page Title)"
        # soup = BeautifulSoup.BeautifulSoup(html)
        if 'D-LINK' in str(a) and 'siyou server' in server:
            dlink_model = str(soup.find("div",{"class": "modelname"}).contents.pop())
            print str(dest_ip).rstrip('\r\n)') + ": D-LINK Router", dlink_model
            soup = BeautifulSoup.BeautifulSoup(html)
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
            print str(dest_ip).rstrip('\r\n)') + ":",str(a.pop()), "Server (Page Title)"
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
            print str(dest_ip).rstrip('\r\n)') + ":",str(server), "Server (Server Version)"
        elif ('CentOS' or 'Ubuntu' or 'Debian') in str(server):
            print str(dest_ip).rstrip('\r\n)') + ":",str(server), "Linux server (Server name)"
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
        elif 'Intellian Aptus Web' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": Intellian Device (Title)"
        elif 'SECURUS' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": Securus DVR (Title)"
        elif 'uc-httpd' in str(server):
            print str(dest_ip).rstrip('\r\n)') + ": XiongMai Technologies-based DVR/NVR/IP Camera w/ title", str(a.pop()), "(Server)"
        elif '::: Login :::' in str(a) and 'Linux/2.x UPnP/1.0 Avtech/1.0' in server:
            print str(dest_ip).rstrip('\r\n)') + ": AvTech IP Camera (admin/admin) (Title and Server)"
        elif 'NetDvrV3' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": NetDvrV3-based DVR (Title)"
        elif 'Open Webif' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": Open Web Interface DVR system (OpenWebIF) (root/nopassword) (Title)"
        elif 'IVSWeb' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": IVSWeb-based DVR (Possibly zenotinel ltd) (Title)"
        elif 'DVRDVS-Webs' in server or 'Hikvision-Webs' in server or 'App-webs/' in server:
                print str(dest_ip).rstrip('\r\n)') + ": Hikvision-Based DVR (Server)"
        elif 'Router Webserver' in str(server):
            print str(dest_ip).rstrip('\r\n)') + ": TP-LINK", str(a.pop()), "(Title)"
        elif 'DD-WRT' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ":", str(a.pop()), "Router (Title)"
        elif 'Samsung DVR' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": Samsung DVR Unknown type (Title)"
        elif 'HtmlAnvView' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": Possible Shenzhen Baoxinsheng Electric DVR (Title)"
        elif 'ZTE corp' in str(server):
            print str(dest_ip).rstrip('\r\n)') + ": ZTE", str(a.pop()), "Router (Title and Server)"
        elif 'Haier Q7' in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": Haier Router Q7 Series (Title)"
        elif 'Cross Web Server' in str(server):
            print str(dest_ip).rstrip('\r\n)') + ": TVT-based DVR/NVR/IP Camera (Server)"
        elif 'uhttpd/1.0.0' in str(server) and "NETGEAR" in str(a):
            print str(dest_ip).rstrip('\r\n)') + ": ", str(a.pop()), "(Title and server)"
        else:
            if info is not None:
                try:
                    a="Title on IP " + str(dest_ip).rstrip('\r\n)') + " is " + str(a.pop()).rstrip('\r\n)') + " and server is " + server
                    print str(a)
                except:  # TODO replace with more specific exception
                    print "Title on IP",str(dest_ip).rstrip('\r\n)'), "does not exists and server is",server
            else:
                pass
            checkheaders.close()
    except Exception as e:  # TODO replace with more specific exception
        try:
            if 'NoneType' in str(e):
                new_ip = str(dest_ip).rstrip('\r\n)')
                bashcommand='curl --silent rtsp://'+new_ip+' -I -m 5| grep Server'
                #print bashcommand
                proc = subprocess.Popen(['bash','-c', bashcommand],stdout=subprocess.PIPE)
                output = proc.stdout.read()
                rtsp_server = str(output).rstrip('\r\n)')
                #print rtsp_server
                if 'Dahua' in str(rtsp_server):
                    print str(dest_ip).rstrip('\r\n)') + ": Dahua RTSP Server Detected (RTSP Server)"
        except Exception as t:  # TODO replace with more specific exceptions:
            print "This didn't work", t
            pass
            
            if vbose is not None:
                print "Error in getheaders(): ",e, dest_ip
            pass


def recurse_DNS_check(dest_ip, **kwargs):
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
        pass


def recurse_ssdp_check(dest_ip, **kwargs):
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
    vbose = kwargs['verbose']
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
    except Exception as e:  # TODO replace with more specific exception
        if vbose is not None:
            print "Error in ntp_monlist",e
        pass

def main():
    configure_logging()
    logger.warning('Link, watch out :-)')
    options = parse_args()
    libpath = os.path.dirname(os.path.realpath(__file__)) + '/lib'
    asndb=pyasn.pyasn(libpath + '/ipasn.dat')
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
