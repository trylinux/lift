from __future__ import print_function

import traceback

import os
import subprocess
import sys
import re

if 'threading' in sys.modules:
    del sys.modules['threading']

from socket import socket
import ssl
import argparse
import time

try:
    from urllib.request import urlopen
    from urllib.error import HTTPError, URLError
except ImportError:
    from urllib2 import urlopen, HTTPError, URLError


import bs4
import netaddr
import os
#import pyasn
import dns.resolver

#Removing for the future fixing
from lib import certs
#from lib import ssdp_info, ntp_function


def main():
    parser = argparse.ArgumentParser(description='Low Impact Identification Tool')
    argroup = parser.add_mutually_exclusive_group(required=True)
    argroup.add_argument("-i", "--ip", help="An Ip address")
    argroup.add_argument("-f", "--ifile", help="A file of IPs")
    parser.add_argument("-p", "--port", help="A port")
    parser.add_argument("-v", "--verbose",
                        help="Not your usual verbosity. This is for debugging why specific outputs aren't working! USE WITH CAUTION")
    argroup.add_argument("-s", "--subnet", help="A subnet!")
    #argroup.add_argument("-a", "--asn", help="ASN number. WARNING: This will take a while")
    parser.add_argument("-r", "--recurse", help="Test Recursion", action="store_true")
    parser.add_argument("-I", "--info", help="Get more info about operations", action="store_true")
    parser.add_argument("-S", "--ssl", help="For doing SSL checks only", action="store_true")
    parser.add_argument("-R", "--recon", help="Gather information about a given device", action="store_true")
    args = parser.parse_args()
    #libpath = os.path.dirname(os.path.realpath(__file__)) + '/lib'
    #asndb = pyasn.pyasn(libpath + '/ipasn.dat')
    if args.verbose is None:
        verbose = None
    else:
        verbose = args.verbose
    if args.port is None:
        dport = 443
    else:
        dport = int(args.port)
    if args.ssl:
        ssl_only = 1
    else:
        ssl_only = 0
    if not args.info:
        info = None
    else:
        info = 1

    if args.ip and not args.recurse and not args.recon:
        dest_ip = args.ip
        if dport in [80, 8080, 81, 88, 8000, 8888, 7547, 8081]:
            getheaders(args.ip, dport, verbose, info)
            print("Skipping SSL test for", dport)

        else:
            testips(args.ip, dport, verbose, ssl_only, info)
    elif args.ifile and not args.recurse:
        ipfile = args.ifile
        dest_ip = args.ip
        try:
            active_futures = []
            with open(ipfile) as f:
                for line in f:
                    if dport in [80, 8080, 81, 88, 8000, 8888, 7547]:
                        # print("Skipping SSL test for", dport)
                        getheaders(str(line).rstrip('\r\n)'), dport, verbose, info)
                    else:
                        testips(str(line).rstrip('\r\n)'), dport, verbose, ssl_only, info)
        except KeyboardInterrupt:
            # print("Quitting")
            sys.exit(0)
        except Exception as e:
            sys.exc_info()[0]
            print("error in first try", e, traceback.format_exc())
            pass
    elif args.subnet:
        try:
            for ip in netaddr.IPNetwork(str(args.subnet)):
                try:
                    if dport == 80:
                        getheaders(str(ip).rstrip('\r\n)'), dport, verbose, info)
                    elif args.recurse:
                        if dport == 53:
                            recurse_DNS_check(str(ip).rstrip('\r\n'), verbose)
                        elif dport == 1900:
                            recurse_ssdp_check(str(ip).rstrip('\r\n'), verbose)
                        elif dport == 123:
                            ntp_monlist_check(str(ip).rstrip('\r\n'), verbose)
                        else:
                            recurse_ssdp_check(str(ip).rstrip('\r\n'), verbose)
                            recurse_DNS_check(str(ip).rstrip('\r\n'), verbose)
                            ntp_monlist_check(str(ip).rstrip('\r\n'), verbose)
                    else:
                        testips(str(ip), dport, verbose, ssl_only, info)
                except KeyboardInterrupt:
                    print("Quitting from Subnet")
                    sys.exit(0)
                    pass
                except Exception as e:
                    if args.verbose is not None:
                        print("Error occured in Subnet", e)
                    sys.exit(0)
        except KeyboardInterrupt:
            sys.exit()
        except Exception as e:
            sys.exit()
 # #   elif args.asn:
 # #      for subnet in asndb.get_as_prefixes(int(args.asn)):
 # #           try:
 #                for ip in netaddr.IPNetwork(str(subnet)):
 #                    if dport == 80:
 #                        getheaders(str(ip).rstrip('\r\n)'), dport, verbose, info)
 #                    elif args.recurse:
 #                        if dport == 53:
 #                            recurse_DNS_check(str(ip).rstrip('\r\n'), verbose)
 #                        elif dport == 1900:
 #                            recurse_ssdp_check(str(ip).rstrip('\r\n'), verbose)
 #                        elif dport == 123:
 #                            ntp_monlist_check(str(ip).rstrip('\r\n'), verbose)
 #                        else:
 #                            recurse_ssdp_check(str(ip).rstrip('\r\n'), verbose)
 #                            recurse_DNS_check(str(ip).rstrip('\r\n'), verbose)
 #                            ntp_monlist_check(str(ip).rstrip('\r\n'), verbose)
 #                    else:
 #                        testips(str(ip), dport, verbose, ssl_only, info)
 #            except KeyboardInterrupt:
 #                print("Quitting")
 #                sys.exit(1)
 #            except Exception as e:
 #                if args.verbose is not None:
 #                    print("Error occured in Subnet", e)
 #                    sys.exit(0)


    elif args.ifile and args.recurse:
        ipfile = args.ifile
        try:
            with open(ipfile) as f:
                for line in f:
                    if dport == 53:
                        recurse_DNS_check(str(line).rstrip('\r\n'), verbose)
                    elif dport == 1900:
                        recurse_ssdp_check(str(line).rstrip('\r\n'), verbose)
                    elif dport == 123:
                        ntp_monlist_check(str(line).rstrip('\r\n'), verbose)
                    else:
                        recurse_ssdp_check(str(line).rstrip('\r\n'), verbose)
                        recurse_DNS_check(str(line).rstrip('\r\n'), verbose)
                        ntp_monlist_check(str(line).rstrip('\r\n'), verbose)
        except KeyboardInterrupt:
            print("Quitting from first try in ifile")
            sys.exit()
        except Exception as e:
            sys.exit()
            print("error in recurse try", e)
            raise
    elif args.ip and args.recurse:
        if dport == 53:
            recurse_DNS_check(str(args.ip), verbose)
        elif dport == 1900:
            recurse_ssdp_check(str(args.ip), verbose)
        elif dport == 123:
            ntp_monlist_check(str(args.ip).rstrip('\r\n'), verbose)
        else:
            print("Trying 53,1900 and 123!")
            recurse_DNS_check(str(args.ip), verbose)
            recurse_ssdp_check(str(args.ip), verbose)
            ntp_monlist_check(str(args.ip).rstrip('\r\n'), verbose)

    if args.ip and args.recon:
        print("Doing recon on ", args.ip)
        dest_ip = args.ip
        try:
            testips(dest_ip, dport, verbose, ssl_only, info)
            recurse_DNS_check(str(args.ip), verbose)
            recurse_ssdp_check(str(args.ip), verbose)
            ntp_monlist_check(str(args.ip).rstrip('\r\n'), verbose)
        except KeyboardInterrupt:
            print("Quitting")
            sys.exit(0)
        except Exception as e:
            print("Encountered an error", e)


def ishostup(dest_ip, dport, verbose):
    response = os.system("ping -c 1 " + dest_ip)
    if response == 0:
        testips(dest_ip, dport, verbose)
    else:
        pass


def testips(dest_ip, dport, verbose, ssl_only, info):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers('ALL:eNULL')
    s = socket()
    s.settimeout(3)
    try:
        c = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE)
        c.connect((dest_ip, dport))
        try:
            a = c.getpeercert(True)
            b = str(ssl.DER_cert_to_PEM_cert(a))
            device = (certs.getcertinfo(b))
            # if verbose is not None:
            # print("Trying: ",str(dest_ip).rstrip('\r\n)'))
            # print("device: ",device)
            if device is not None:
                if device == "ubiquiti":
                    print(str(dest_ip).rstrip('\r\n)') + ": Ubiquiti AirMax or AirFiber Device (SSL)")
                if "UBNT" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Ubiquiti AirMax or AirFiber Device (SSL)")
                elif "samsung" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Unknown Samsung Device (SSL)")
                elif "qnap" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": QNAP NAS TS series detected (SSL)")
                elif device == "hikvision":
                    print(str(dest_ip).rstrip('\r\n)') + ": Hikvision Default Cert")
                elif device == "avigilon":
                    print(str(dest_ip).rstrip('\r\n)') + ": Aviligon Gateway Default cert")
                elif device == "netgear_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": NetGear Default cert UTM  (SSL)")
                elif device == "verifone_sapphire":
                    print(str(dest_ip).rstrip('\r\n)') + ": Verifone Sapphire Device (SSL)")
                elif "Vigor" == device:
                    print(str(dest_ip).rstrip('\r\n)') + ": DrayTek Vigor Device (SSL)")
                elif device == "lifesize_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": Lifesize Product (SSL)")
                elif "filemaker" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Filemaker Secure Database Website (SSL)")
                elif device == "verizon_jungo":
                    print(str(dest_ip).rstrip('\r\n)') + ": Verizon Jungo OpenRG product (SSL/8443)")
                elif device == "canon_iradv":
                    print(str(dest_ip).rstrip('\r\n)') + ": Canon IR-ADV Login Page (SSL/8443)")
                elif "colubris" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": HPE MSM Series Device (SSL)")
                elif device == "ecessa":
                    print(str(dest_ip).rstrip('\r\n)') + ": Ecessa PowerLink Wan Optimizer (SSL)")
                elif device == "nomadix_ag_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": Nomadix AG series Gateway (SSL)")
                elif "netvanta" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": ADTRAN NetVanta Total Access Device (SSL)")
                elif "valuepoint_gwc_1" == device:
                    print(str(dest_ip).rstrip('\r\n)') + ": ValuePoint Networks Gateway Controller Series (SSL)")
                elif device == "broadcom_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": Broadcom Generic Modem (SSL)")
                elif device == "lg_nas_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": LG NAS Device (SSL)")
                elif device == "edgewater_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": EdgeWater Networks VOIP Solution (SSL)")
                elif device == "foscam_cam":
                    print(str(dest_ip).rstrip('\r\n)') + ": Foscam IPcam Client Login (SSL)")
                elif device == "lacie_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": LaCie CloudBox (SSL)")
                elif device == "huawei_hg658":
                    print(str(dest_ip).rstrip('\r\n)') + ": Huawei Home Gateway HG658d (SSL)")
                elif device == "interpeak_device":
                    print(str(dest_ip).rstrip('\r\n)') + ": Something made by interpeak (SSL)")
                elif device == "fujistu_celvin":
                    print(str(dest_ip).rstrip('\r\n)') + ": Fujitsu Celvin NAS (SSL)")
                elif device == "opengear_default_cert":
                    print(str(dest_ip).rstrip('\r\n)') + ": Opengear Management Console Default cert (SSL)")
                elif device == "zyxel_pk5001z":
                    print(str(dest_ip).rstrip('\r\n)') + ": Zyxel PK5001Z default cert (SSL)")
                elif device == "audiocodecs_8443":
                    print(str(dest_ip).rstrip('\r\n)') + ": AudioCodecs MP serices 443/8443 Default Cert (SSL)")
                elif "supermicro_ipmi" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Supermicro IPMI Default Certs (SSL)")
                elif device == "enco_player_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": Enco Enplayer Default Cert (SSL)")
                elif device == "ami_megarac":
                    print(str(dest_ip).rstrip('\r\n)') + ": AMI MegaRac Remote Management Default Cert (SSL)")
                elif device == "avocent_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": Avocent Default cert (unknown device) (SSL)")
                elif device == "ligowave_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": LigoWave Default Cert (probably APC Propeller 5) (SSL)")
                elif "intelbras_wom500" == device:
                    print(str(dest_ip).rstrip('\r\n)') + ": IntelBras Wom500 (admin/admin) (SSL)")
                elif "netgear_2" == device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Netgear Default Cert Home Router (8443/SSL)")
                elif "buffalo_1" == device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Buffalo Default Cert (443/SSL)")
                elif "digi_int_1" == device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Digi Passport Default Cert (443/SSL)")
                elif "prtg_network_monitor_1" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Paessler PTRG Monitoring Default Cert(443/SSL)")
                elif 'axentra_1' in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Seagate/Axentra NAS Default Cert 863B4AB (443/SSL)")
                elif 'ironport_device' in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Cisco IronPort Device Default SSL (443/SSL)")
                elif 'meru_net_1' in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Meru Network Management Device  (443/SSL)")
                elif 'bticino_1' in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": BTcinino My Home Device w/ Default Cert  (443/SSL)")
            # elif "matrix_sample_ssl_1":
            #	print(str(dest_ip).rstrip('\r\n)') + ": Matrix SSL default server for WiMax Devices(443/SSL)")
            elif a is not None and device is None:
                getheaders_ssl(dest_ip, dport, a, verbose, ctx, ssl_only, info)
            else:
                print("Something error happened")

            s.close()
        except KeyboardInterrupt:
            print("Quitting")
            sys.exit(0)
        except URLError as e:
            if verbose is not None:
                print(str(dest_ip).rstrip('\r\n)') + ":" + str(dport) + " is not open")
                getheaders(dest_ip, dport, verbose, info)
            else:
                getheaders(dest_ip, dport, verbose, info)
                pass
        except Exception as e:
            s.close()
            if 111 in e and ssl_only == 0:
                getheaders(dest_ip, dport, verbose, info)
            elif ("timed out" or 'sslv3' in e) and ssl_only == 0:
                getheaders(dest_ip, dport, verbose, info)
                pass
            else:
                getheaders(dest_ip, dport, verbose, info)
            # if verbose is not None:
            #	print( )str(dest_ip).rstrip('\r\n)') + ": had error " + str(e).rstrip('\r\n)'))
            if verbose is not None:
                print("Error in testip: " + str(e) + " " + str(dest_ip).rstrip('\r\n)'))
    except Exception as e:
        if 'gaierror' in str(e):
            pass
        else:
            if verbose is not None:
                print("Error in TestIPs",str(e))




def getheaders_ssl(dest_ip, dport, cert, vbose, ctx, ssl_only, info):
    hostname = "https://%s:%s" % (str(dest_ip).rstrip('\r\n)'), dport)
    try:
        checkheaders = urlopen(hostname, context=ctx, timeout=5)
        try:
            if ('ubnt.com', 'UBNT') in cert:
                print(str(dest_ip).rstrip('\r\n)') + ": Ubiquity airOS Device non-default cert (SSL)")
        except:
            pass
        server = checkheaders.info().get('Server')
        if not server:
            server = None
        html = checkheaders.read()
        soup = bs4.BeautifulSoup(html,'html.parser')
        try:
            title = soup.html.head.title
            title_contents = title.contents
        except:
            title = None
        if title is None:
            try:
                title = soup.html.title
                title_contents = title.contents
            except:
                title_contents = None
        if 'EdgeOS' in str(title_contents) and 'Ubiquiti' in cert:
            print(str(dest_ip).rstrip('\r\n)') + ": EdgeOS Device (SSL + Server header)")
        # if ('ubnt.com','UBNT') in cert:
        #	print(str(dest_ip).rstrip('\r\n)') + ": Ubiquity airOS Device non-default cert (SSL)")
        elif 'iR-ADV' in str(cert) and 'Catwalk' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Canon iR-ADV Login Page (SSL + Server header)")
        elif 'Cyberoam' in str(cert):
            print(str(dest_ip).rstrip('\r\n)') + ": Cyberoam Device (SSL)")
        elif 'TG582n' in str(cert):
            print(str(dest_ip).rstrip('\r\n)') + ": Technicolor TG582n (SSL)")
        elif 'RouterOS' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": MikroTik RouterOS (Login Page Title)")
        elif 'axhttpd/1.4.0' in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": IntelBras WOM500 (Probably admin/admin) (Server string)")
        elif 'ZeroShell' in str(cert):
            print(str(dest_ip).rstrip('\r\n)') + ": ZeroShell Firewall")
        elif 'FIBERHOME.COM.CN' in str(cert):
            print(str(dest_ip).rstrip('\r\n)') + ": Fiberhome ONU/OLT Device (SSL Cert name)")
        else:
            if ssl_only == 0:
                getheaders(dest_ip, 80, vbose, info)
            else:
                print("Title on IP", str(dest_ip).rstrip('\r\n)'), "is", str(a.pop()).rstrip(), '\r\n)', "and server is", server)
        checkheaders.close()
    except HTTPError as e:
        if "Server" in str(e.info()):
            try:
                server = str(e.info().get('Server'))
            except:
                server = "is not available"
        else:
            server = "is not available"
        if "AkamaiGHost" in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": Akamai GHost Server")
        elif vbose is not None:
            try:
                authenticate_header = e.headers.get('WWW-Authenticate')
            except:
                authenticate_header = "noauth"
            print(str(dest_ip).rstrip('\r\n)') + ": has HTTP status " + str(e.code) + " and server " + str(server) + " " + authenticate_header)
        else:
            pass
    except Exception as e:
        if dport == 443 and ssl_only == 0:
            dport = 80
            getheaders(dest_ip, dport, vbose, info)
        if vbose != None:
            print("Error in getsslheaders: " + str(e) + str(dest_ip), traceback.format_exc())
        pass
    return


def getheaders(dest_ip, dport, vbose, info, output_file=None):
    if dport == 443:
        dport = 80
    try:
        hostname = "http://%s:%s" % (str(dest_ip).rstrip('\r\n)'), dport)
        checkheaders = urlopen(hostname, timeout=5)

        try:
            server = checkheaders.info().get('Server')
        except:
            server = None

        html = checkheaders.read()
        content_length = len(str(html))

        soup = bs4.BeautifulSoup(html,'html.parser')


        try:
            title = soup.html.head.title
            title_contents = title.contents


        except:
            title = None
        if title is None:
            try:

                title = soup.html.title
                title_contents = title.contents
            except:

                title_contents = None
        if checkheaders.getcode() != 200:
            print(str(dest_ip).rstrip('\r\n)') + ": Status Code " + checkheaders.getcode() + " Server: "+ server)
        # a = title.contents
        if 'RouterOS' in str(title_contents) and server is None:
            print(str(dest_ip).rstrip('\r\n)') + ": MikroTik RouterOS version", str(
                soup.find('body').h1.contents.pop()), "(Login Page Title)")

        elif ('D-LINK' in str(title_contents) and 'siyou server' in server) or (str(server) == "mini_httpd/1.19 19dec2003"):
            dlink_model = str(soup.find("div", {"class": "modelname"}).contents.pop())
            print(str(dest_ip).rstrip('\r\n)') + ": D-LINK Router", dlink_model)

        elif title_contents is None:
            try:
                answer = soup.find("meta", {"content": "0; url=/js/.js_check.html"})
            except Exception as e:
                answer = None
            if 'Serial' in str(server) and 'HP' in str(server):
                print(str(dest_ip).rstrip('\r\n)') + ": HP Product w/ Identifiers -- " + str(server))
            elif "js_check" in str(answer):
                get_login_html = "http://%s:%s/login.html" % (str(dest_ip).rstrip('\r\n)'), dport)
                try:
                    check_login_page = urlopen(get_login_html, timeout=5)
                    get_page = check_login_page.read()
                    if check_login_page.getcode() == 200:
                        soup2 = bs4.BeautifulSoup(get_page,'html.parser')
                        title2 = soup2.html.head.title
                        title2_contents = title2.contents
                        if "Airties" in title2_contents.pop():
                            output = (str(dest_ip).rstrip('\r\n)') + ": Airties Modem/Router")
                            primary_output(output, output_file)
                        else:
                            print(str(dest_ip).rstrip('\r\n)') + ": Device with Title "+title2)
                    else:
                        print(str(dest_ip).rstrip('\r\n)') + ": Possible  KitDuo DVR Found")
                except Exception as e:
                    print(e)


            elif 'WebServer/1.0 UPnP/1.0' in str(server):
                get_label = soup.find('label').contents
                if len(get_label) != 0:
                    for record in get_label:
                        if 'TP-LINK' in record:
                            output = (str(dest_ip).rstrip('\r\n)') + ": TP-Link Device (Unknown Model)")
                            primary_output(output, output_file)
            elif 'uc-httpd/1.0.0' in str(server):
                output = (str(dest_ip).rstrip('\r\n)') + ": Possibly a Dahua DVR")
                primary_output(output, output_file)
                #This is a fucked up signature. I"m still working on it 08/15/2021
                #print(str(dest_ip).rstrip('\r\n)') + ": Hangzhou Topvision/Taoshi based D/H/NVR or IP Camera")

            elif 'Boa/0.94.13' in str(server) and content_length == 142:
                #Verified 08/15/2021, the domain that is used pulls back to Macroview. This signature is pretty broad but until I find a better focus, I don't think anything else will work.
                output = (str(dest_ip).rstrip('\r\n)') + ": Macroview KR based CCTV Device ")
                primary_output(output, output_file)



            else:
                print(str(dest_ip).rstrip('\r\n)') + ": has server ", str(server), " and no viewable title")
        elif str('WebServer') in str(server) and "D-LINK" in title_contents:
            version_table = soup.find("table",{"id":"versionTable"})
            for row in version_table.find_all('td'):
                if "script" in str(row):
                    if "Model" in str(row):
                        grab_header = str(row.text).split(":")
                        model_name = grab_header[1].lstrip(" ")
                    elif "Hardware" in str(row):
                        grab_header = str(row.text).split(":")
                        hw_version = grab_header[1].lstrip(" ")
                    elif "Firmware" in str(row):
                        grab_header = str(row.text).split(":")
                        fw_version = grab_header[1].lstrip(" ")
            print(str(dest_ip).rstrip('\r\n)') +": D-LINK Model " + model_name + " " + hw_version + " " + fw_version)

        elif "Synology" in str(title_contents) and str("nginx") in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": Synology Device Storage Device")

        elif str(server) in str("ver2.4 rev0"):
            output = (str(dest_ip).rstrip('\r\n)') + ": Panasonic IP Camera/NVR Model: " + str(title_contents.pop()))
            primary_output(output, output_file)

        elif "Inicio" in str(title_contents):
            output = (str(dest_ip).rstrip('\r\n)') + ": Technicolor TG series modem")
            primary_output(output,output_file)

        elif str("WV-NS202A Network Camera") in str(title_contents) and server is str("HTTPD"):
            #This signature was confirmed on 08_09_2021
            output = (str(dest_ip).rstrip('\r\n)') + ": Panasonic WV-NS202A Network Camera")
            primary_output(output, output_file)

        elif str("Radiant Device Brower") in str(title_contents) and str("thttpd/2.25b 29dec2003") in str(server):
            #I have no way to verify this signature as of 08_09_2021
            output = (str(dest_ip).rstrip('\r\n)') + ": Probable Radiant RM1121 Series Monitor")
            primary_output(output, output_file)

        elif "VCS-VideoJet-Webserver" in str(server):
            #Verified on 08_09_2021
            output = (str(dest_ip).rstrip('\r\n)') + ": Bosch AutoDome Camera")
            primary_output(output, output_file)

        elif 'axhttpd/1.4.0' in str(server):
            #Verified on 08_09_2021 and added to notedeck
            output = (str(dest_ip).rstrip('\r\n)') + ": IntelBras WOM500 (Probably admin/admin) (Server string)")
            primary_output(output, output_file)

        elif 'ePMP' in str(title_contents):
            #Updated the signature on 08/09/2021 to dynamically pop the contents of the title.
            output = (str(dest_ip).rstrip('\r\n)') + ": Cambium "+title_contents.pop())
            primary_output(output, output_file)

        #Removed from signature chain on 08/09/2021, unable to verify again
        #elif 'Wimax CPE Configuration' in str(title_contents):
        #    print(str(dest_ip).rstrip('\r\n)') + ": Wimax Device (PointRed, Mediatek etc) (Server type + title)")

        elif 'NXC2500' in str(title_contents) and server == None:
            #Verified on 08/09/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": Zyxel NXC2500 (Page Title)")
            primary_output(output, output_file)

        #Removing this signature on 08/09/2021 -- unable to verify
        #elif server is not None and 'MiniServ/1.580' in str(server):
            #print(str(dest_ip).rstrip('\r\n)') + ": Multichannel Power Supply System SY4527 (Server Version)")

        elif 'IIS' in str(title_contents):
            #This is built off of the title of the webpage. I'm not sure I like it, but I'll keep it for now -- 08/09/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": "+ str(title_contents.pop()) + " Server (Page Title)")
            primary_output(str(output), output_file)

        elif 'IIS' in str(server):
            #Built off of the server string, no versioning information. Verified 08/09/2021
            output = str(dest_ip).rstrip('\r\n)') + ": " + str(server) + " Server (Server Version)"
            primary_output(output)

        elif 'Vigor' in str(title_contents):
            #Verified on 08/09/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": " + str(title_contents.pop()) + " Switch (Title)")
            primary_output(output, output_file)

        elif 'Aethra' in str(title_contents):
            #Verified 08/09/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": Aethra Telecommunications Device (Title)")
            primary_output(output, output_file)

        #I'm removing this signature on 08/09/2021
        #elif 'Industrial Ethernet Switch' in str(title_contents):
         #   print(str(dest_ip).rstrip('\r\n)') + ": Industrial Ethernet Switch (Title)")

        #Removing the following line due to some weirdness with bytes
        #elif title_contents.count(1) == 0 and "UI_ADMIN_USERNAME" in html:
        #    print(str(dest_ip).rstrip('\r\n)') + ": Greenpacket device Wimax Device (Empty title w/ Content)")

        elif 'NUUO Network Video Recorder Login' in title_contents:
            output = (str(dest_ip).rstrip('\r\n)') + ": NUOO Video Recorder (admin/admin) (Title)")
            primary_output(output, output_file)

        elif 'CDE-30364' in title_contents:
            #Verified on 08/09/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": Hitron Technologies CDE (Title)")
            primary_output(output, output_file)

        elif 'BUFFALO' in title_contents:
            #Verified 08/09/2021 -- I need to add another signature for 401s.
            output = (str(dest_ip).rstrip('\r\n)') + ": Buffalo Networking Device (Title)")
            primary_output(output, output_file)

        elif 'Netgear' in title_contents:
            #Verified on 08/09/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": Netgear Generic Networking Device (Title)")
            primary_output(output, output_file)

        elif "Index_Page" in title_contents and "Apache" in str(server):
            output = (str(dest_ip).rstrip('\r\n)') + ": Zyxel Device w/ Apache")
            primary_output(output, output_file)


        elif ('CentOS' or 'Ubuntu' or 'Debian') in str(server):
            #Verified 08/10/2021 -- A very basic signature.
            output = (str(dest_ip).rstrip('\r\n)') + ": " + str(server) + " Linux server (Server name)")
            primary_output(output, output_file)

        elif "SonicWALL" in str(server):
            #Confirmed on 08/10/2021, this will trip on anything that has Sonicwall in the server name.
            output = (str(dest_ip).rstrip('\r\n)') + ": Probable SonicWALL Network Security Appliance (Server name)")
            primary_output(output, output_file)

        #This signature needs to be moved to the 401 group.
        #elif "iGate" in title_contents:
            #print(str(dest_ip).rstrip('\r\n)') + ": iGate Router or Modem (Server name)")

        elif 'LG ACSmart' in str(title_contents):
            #Modified and removed "premium". Verified 08/10/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": LG ACSmart (admin/admin) (Server name)")
            primary_output(output, output_file)

        #Can no longer verify this signature. Removing 08/10/2021
        #elif 'IFQ360' in str(title_contents):
        #   print(str(dest_ip).rstrip('\r\n)') + ": Sencore IFQ360 Edge QAM (Title)")

        #Can no longer verify this signature
        #elif 'Tank Sentinel AnyWare' in str(title_contents):
        #    print(str(dest_ip).rstrip('\r\n)') + ": Franklin Fueling Systems Tank Sentinel System (Title)")

        elif 'Z-World Rabbit' in str(server) and "iBoot" in str(title_contents):
            #Modified this signature to be more specific. Modified and Verified 08/10/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": iBootBar (Server)")
            primary_output(output, output_file)

        elif 'Intellian Aptus Web' in str(title_contents):
            #Verified 08/09/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": Intellian Device (Title)")
            primary_output(output, output_file)

        elif 'SECURUS' in str(title_contents):
            #Verified 08/10/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": Securus DVR (Title)")
            primary_output(output, output_file)

        elif str(server) == 'uc-httpd 1.0.0' or "NETSurveillance WEB" in str(title_contents):
            #Verified 08/10/2021, this one pops out the dynamic title for resellers who set their own title.
            output = (str(dest_ip).rstrip('\r\n)') + ": XiongMai Technologies-based DVR/NVR/IP Camera w/ title "+ str(
                title_contents.pop())+ " (Server)")
            primary_output(output, output_file)

        elif 'Boa/0.93.15' in str(server):
        #Verified 08/09/2021. Shenzhen C-Data comes in a variety of different forms, however, they all have the same Boa version. The second signature pops the device name out of the login page.
            if 'Home Gateway' in str(title_contents):
                output = (str(dest_ip).rstrip('\r\n)') + ": Shenzhen C-Data Technology GPON/ONU/EPON Home Gateway Product")
                primary_output(output, output_file)

            elif str('1GE') in str(title_contents) or str('1FE') in str(title_contents):
                output = (str(dest_ip).rstrip('\r\n)') + ": Shenzhen C-Data Technology Model "+str(title_contents.pop()))
                primary_output(output, output_file)

        elif '::: Login :::' in str(title_contents) and 'Linux/2.x UPnP/1.0 Avtech/1.0' in str(server):
            #Verified 08/10/2021.  This works on a very specific subset of AvTech Cameras
            output = (str(dest_ip).rstrip('\r\n)') + ": AvTech IP Camera (admin/admin) (Title and Server)")
            primary_output(output, output_file)

        elif 'NetDvrV3' in str(title_contents):
            output = (str(dest_ip).rstrip('\r\n)') + ": NetDvrV3-based DVR (Title)")
            primary_output(output, output_file)

        elif 'Open Webif' in str(title_contents):
            #Unable to verify, but my notes have data regarding this. I will leave it in 08/10/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": Open Web Interface DVR system (OpenWebIF) (root/nopassword) (Title)")
            primary_output(output, output_file)

        #Removing this one for now, until I can verify again.
        #elif 'IVSWeb' in str(title_contents):

            #print(str(dest_ip).rstrip('\r\n)') + ": IVSWeb-based DVR (Possibly zenotinel ltd) (Title)")

        elif 'DVRDVS-Webs' in str(server) or 'Hikvision-Webs' in str(server) or 'App-webs/' in str(server):
            #Verified 08/10/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": Hikvision-Based DVR (Server)")
            primary_output(output, output_file)

        elif 'Router Webserver' in str(server):
            #Verified 08/10/2021 -- Should be noted that there is a 401 counterpart to this.
            output =  (str(dest_ip).rstrip('\r\n)') + ": TP-LINK "+ str(title_contents.pop())+ " (Title)")
            primary_output(output, output_file)

        elif '- Info' in str(title_contents) and str(server) in "httpd":
            #Verified 08/10/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": DD-WRT Device w/ Title " + str(title_contents.pop()))
            primary_output(output, output_file)

        elif "Polycom SoundPoint IP Telephone HTTPd" in str(server) and "Polycom" in str(title_contents):
            #added on 08/16/2021, pulled from DDoS data
            output = (str(dest_ip).rstrip('\r\n)') + ": Polycomm SoundPoint IP Telephone Device")
            primary_output(output, output_file)

        elif 'Samsung DVR' in str(title_contents):
            #Verified
            output = (str(dest_ip).rstrip('\r\n)') + ": Samsung DVR Unknown type (Title)")
            primary_output(output, output_file)

        elif 'IC-II' in str(title_contents) and "Hiawatha v9.2" in str(server):
            #Added and verified on 08/18/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": Legrand Vantage InFusion Controller")
            primary_output(output, output_file)

        elif "Crestron AirMedia" in str(title_contents) and "Crestron Webserver" in str(server):
            # Added and verified on 08/18/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": Crestron AirMedia Device")
            primary_output(output, output_file)

        elif "Seagate NAS" in str(title_contents) and server == None:
            # Added and verified on 08/18/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": Seagate NAS Device")
            primary_output(output, output_file)

        elif 'LaCie' in str(title_contents) and 'lighttpd' in str(server):
            # Added and verified on 08/18/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": LaCie Network Storage Device")
            primary_output(output, output_file)

        #Removing this signature until I can verify again
        #elif 'HtmlAnvView' in str(title_contents):
        #    print(str(dest_ip).rstrip('\r\n)') + ": Possible Shenzhen Baoxinsheng Electric DVR (Title)")

        elif 'ZTE corp' in str(server):
            #ZTE Devices of various types. This signature dynamically pops the title out so we can get the model number. Tested and Verified on 08/18/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": ZTE " + str(title_contents.pop())+ " Router (Title and Server)")
            primary_output(output, output_file)

        elif 'Haier Q7' in str(title_contents):
            #Tested and verified on 08/18/2021
            output = (str(dest_ip).rstrip('\r\n)') + ": Haier Router Q7 Series (Title)")
            primary_output(output, output_file)

        elif 'Cross Web Server' in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": TVT-based DVR/NVR/IP Camera (Server)")

        elif 'uhttpd/1.0.0' in str(server) and "NETGEAR" in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": "+ str(title_contents.pop())+ " (Title and server)")

        elif 'SunGuard' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": SunGuard.it Device (Title)")

        elif 'CMS Web Viewer' in str(title_contents) and (server is None or  "lighttpd/1.4.54" in str(server)):

            print(str(dest_ip).rstrip('\r\n)') + ": 3R Global DVR -- Unknown Brand")

        elif 'WEB SERVICE' in str(title_contents) and server is None:
            print(str(dest_ip).rstrip('\r\n)') + ": Dahua Product (DVR/NVR/HVR likely)")

        elif 'Brother ' in str(title_contents) and str('debut') in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": "+str(title_contents.pop()))

        elif 'Lexmark' in (str(title_contents)) and (server is None or 'Lexmark' in str(server)):
            print(str(dest_ip).rstrip('\r\n)') + ": " + str(title_contents.pop()))

        elif 'gSOAP/2.8' in str(server) and (len(title_contents) == 0 or str('IPCamera Components Download') in str(title_contents)):
            print(str(dest_ip).rstrip('\r\n)') + ": Shenzhen TVT CCTV Device (Camera or Recorder)")

        elif 'Milesight Network Camera' in str(title_contents) and server is None:
            print(str(dest_ip).rstrip('\r\n)') + ": Milesight DVR Device")

        elif 'EPSON_Linux' in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": "+str(title_contents.pop()))

        elif 'Boa' in str(server) and str('Web Client') in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Nadatel Device")

        elif str('CPPLUS DVR') in str(title_contents) and server == None:
            print(str(dest_ip).rstrip('\r\n)') + ": CP PLUS DVR")

        elif (str("ATHD DVR") in str(title_contents) or "AHD DVR" in str(title_contents)) and server == None:
            #Updated 08_08_2021 to include AHD DVR. The 554 port on these say Altasec as well.
            print(str(dest_ip).rstrip('\r\n)') + ": Altasec DVR")

        elif str("Network Video Recorder Login") in str(title_contents) and 'lighttpd' in  str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": NUUO CCTV Product")

        #This is a complex signature, due to the widespread use of Raysharp devices. It keys off of the dvrocx in the body OR the existance of the term RSVideoOCX.
        elif (str('Boa/0.94.14rc21') in str(server) and ((len(title_contents) == 0) or "WebClient" in str(title_contents))) or (len(title_contents) == 0 and server is None) :
            try:
                ocx=soup.body.findAll("object", {"name":"dvrocx"})
                if len(ocx) != 0:
                   print(str(dest_ip).rstrip('\r\n)') + ": Raysharp CCTV Device (Unknown Downstream Brand)")
            except Exception as e:
                try:
                    title_stuff = title_contents.pop()
                except Exception as e:
                    title_stuff = "None"
            try:
                comment = soup.findAll(string=lambda tag: isinstance(tag, bs4.Comment))
                if "RSVideoOcx.cab" in str(comment):
                    print(str(dest_ip).rstrip('\r\n)') + ": Raysharp CCTV Device (Unknown Downstream Brand)")
            except Exception as e:
                print(str(dest_ip).rstrip('\r\n)') + ": Raysharp CCTV Device Malformed Response Likely (Manually review)")

        elif str('Mini web server 1.0 ZXIC corp 2005') in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": Shenzhen C-Data Device w/ Model "+ title_contents.pop())

        elif str('BEWARD Network HD camera') in str(title_contents) and server == None:
            print(str(dest_ip).rstrip('\r\n)') + ": Beward IP Camera Device")

        elif str("GPON ONT") in str(title_contents) and server == None:
            print(str(dest_ip).rstrip('\r\n)') + ": VNPT GPON/iGate Device likely")

        elif str("ZK Web Server") in str(server) and len(title_contents) == 0:
            print(str(dest_ip).rstrip('\r\n)') + ": ZK Software-based Fingerprint Reader")

        elif "Keenetic Web" in  str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": KEENETIC Device")

        elif 'uc-httpd/1.0.0' in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": Hangzhou Topvision/Taoshi based D/H/NVR or IP Camera w/ Title " + str(title_contents.pop()))

        elif "Reolink" in title_contents and ("nginx" in str(server) or server == None):
            print(str(dest_ip).rstrip('\r\n)') + ": Reolink DVR Device")

        elif "Network Surveillance" in str(title_contents) and server == None:
            print(str(dest_ip).rstrip('\r\n)') + ": Shenzhen Baichuan Digital Technology CCTV Device")

        elif "Login Page" in str(title_contents) and str(server) == "httpserver":
            print(str(dest_ip).rstrip('\r\n)') + ": EP Technology Corporation CCTV Device")

        elif str(server) == "GNU rsp/1.0" :
            #verified 08/13/2021
            if "XVR LOGIN" in str(title_contents):
                print(str(dest_ip).rstrip('\r\n)') + ": Cenova XVR Product (OEM Shenzhen Milantek Co)")
            else:
                print(str(dest_ip).rstrip('\r\n)') + ": Shenzhen Milantek Co OEM Device (Unknown Downstream)")

        elif "nginx/" in str(server) and "CentOS" in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Centos Server w/ " + str(server))

        elif "nginx" in str(server) and "CentOS" not in str(title_contents):
            if "Ubuntu" in str(server):
                print(str(dest_ip).rstrip('\r\n)') + ": Ubuntu Server w/ " + str(server) + " with title w/ "+ str(title_contents.pop()))

        elif "Web Application Manager" in str(title_contents) and server is None:
            print(str(dest_ip).rstrip('\r\n)') + ": KongTop Industrial (Shenzhen) CCTV Device")

        elif "PON Home Gateway" in str(title_contents) and server is None:
            print(str(dest_ip).rstrip('\r\n)') + ": Shenzhen HDV Photoelectron Technology LTD PON Device")

        elif "Login" in str(title_contents) and server is None and "loginN4.js" in str(soup.head):
            title = str(soup.find("div", {"id": "login-title"}).contents.pop())
            print(str(dest_ip).rstrip('\r\n)') + ": Tridium Niagra Product w/ Title " + str(title))

        elif "TOTOLINK" in str(title_contents) and str(server) == "Boa/0.94.14rc21":
            print(str(dest_ip).rstrip('\r\n)') + ": Totolink Device (Modem or Router)")

        elif "SVM-R1" in str(title_contents) and "Apache" in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": Daikin HVAC SVM/VRV Controller w/ Software Version "+ str(title_contents.pop()))

        elif str(title_contents) == "welcome" and "GoAhead-Webs/2.5.0 PeerSec-MatrixSSL/3.4.2-OPEN" in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": Fiberhome ONU/OLT (HTML Title and Server Name)")

        elif ("DVR_H264 ActiveX" in  str(title_contents) or "RTDVR ActiveX" in str(title_contents))  and "thttpd/2.25b 29dec2003" in str(server):
            #Added 08_07_2021, multiple points that match including UDROCX and the name "unimo" on the title page
            print(str(dest_ip).rstrip('\r\n)') + ": Unimo AU CCTV Product")

        elif  str(server) == "lighttpd/1.4.37" and "Intelligent Digital Security System" in str(title_contents):
            #Added 08_07_2021, The "remove activex" binary has a certificate that has the domain of icctv.co.kr and the address of Ewha in Korea.
            print(str(dest_ip).rstrip('\r\n)') + ": ICCTV Korea CCTV Product (Now Ewha CNI/KTCCTV)")

        else:
            try:
                try:
                    title_stuff = title_contents.pop()
                except Exception as e:
                    title_stuff = "None"
                crap_contents = "Title on IP " + str(dest_ip).rstrip('\r\n)') + " is " + title_stuff.rstrip(
                    '\r\n)') + " and server is " + str(server)
                print(str(crap_contents))
            except Exception as e:
                if vbose is not None:
                    print(e,str(traceback.format_exc()))
                print("Title on IP", str(dest_ip).rstrip('\r\n)') + "is empty and server is" + server)
        checkheaders.close()
    except HTTPError as e:
        try:
            server = str(e.info().get('Server'))
        except:
            server = None

        auth_header = (e.headers.get('WWW-Authenticate'))


        if auth_header is not None and ("alphapd/2.1.8" in str(server)  or  "Embedthis-Appweb/3.3.1" in str(server)   or  "WebServer/2.0" in str(server)  or "RomPager/4.07 UPnP/1.0" in str(server)) and int(e.code) == 401:
            auth_header_split = auth_header.split(",")
            auth_header_realm = auth_header_split[0].split("=")
            device_model = str(auth_header_realm[1]).replace("\"","")
            print(str(dest_ip).rstrip('\r\n)') + ": D-Link Device Model ",str(device_model))
        elif auth_header is not None and (str(server) == 'PDR-M800/1.0') and int(e.code)==401:
            print(str(dest_ip).rstrip('\r\n)') + ": LiLin PDR-800 DVR")
        elif "mini_httpd/1.19 19dec2003" in str(server) and int(e.code) == 401 :
            print(str(dest_ip).rstrip('\r\n)') + ": iCatch OEM H/D/NVR Device (Server and headers)")
        elif 'Router' in str(server) and int(e.code) == 401:
            auth_header_split = auth_header.split(",")
            auth_header_realm = auth_header_split[0].split("=")
            device_model = str(auth_header_realm[1]).replace("\"", "")
            print(str(dest_ip).rstrip('\r\n)') + ": TP-Link",str(device_model))
        elif str(server) == "none" and int(e.code) == 401:
            auth_header_split = auth_header.split(",")
            auth_header_realm = auth_header_split[0].split("=")
            device_model = str(auth_header_realm[1]).replace("\"", "")
            print(str(dest_ip).rstrip('\r\n)') + ": Device model ",str(device_model))
        elif "WebServer/1.0 UPnP/1.0" in str(server)  and int(e.code) == 401:
            auth_header_split = auth_header.split(",")
            auth_header_realm = auth_header_split[0].split("=")
            device_model = str(auth_header_realm[1]).replace("\"", "")
            print(str(dest_ip).rstrip('\r\n)') + ": ZTE Device "+str(device_model))
        elif "cpe@zte.com" in str(auth_header) and int(e.code) == 401:
            print(str(dest_ip).rstrip('\r\n)') + ": ZTE ONU/ONT Device" )
        elif "everfocus" in str(auth_header) or "ELUX" in str(auth_header) or "ECOR" in str(auth_header) and int(e.code) == 401:
            if "ELUX" in str(auth_header):
                auth_header_split = auth_header.split(",")
                auth_header_realm = auth_header_split[0].split("=")
                device_model = str(auth_header_realm[1]).replace("\"", "")
                print(str(dest_ip).rstrip('\r\n)') + ": Everfocus CCTV Device Model "+ str(device_model))
            else:

                print(str(dest_ip).rstrip('\r\n)') + ": Everfocus CCTV Device (admin/111111)")
        elif str(server) == "lighttpd/1.4.32 - Android Blackeye Web Server" and int(e.code) == 401:
            print(str(dest_ip).rstrip('\r\n)') + ": Android Blackeye Web Server")
        elif str(server) == "Keil-EWEB/2.1" and int(e.code) == 401:
            print(str(dest_ip).rstrip('\r\n)') + ": Keil ARM Development Tool Web Server")
        elif "HuaweiHomeGateway" in str(auth_header) and int(e.code) == 401:
            print(str(dest_ip).rstrip('\r\n)') + ": Huawei Home Gateway Device (Probably PON)")
        elif int(e.code) == 302:
            if "/login.rsp" in str(e.headers):
                print(str(dest_ip).rstrip('\r\n)') + ": Exacq Technologies CCTV Product")


        else:
            print(str(dest_ip).rstrip('\r\n)')+ ": Server: " + str(e.info().get('Server')) + " with error " + str(e))
    except URLError as e:
        if vbose is not None:
            print(str(dest_ip).rstrip('\r\n)')+":"+str(dport)+" is not open")
    except Exception as e:
        try:
            if 'NoneType' in str(e):
                new_ip = str(dest_ip).rstrip('\r\n)')
                bashcommand = 'curl --silent rtsp://' + new_ip + ' -I -m 5| grep Server'
                # print(bashcommand)
                proc = subprocess.Popen(['bash', '-c', bashcommand], stdout=subprocess.PIPE)
                output = proc.stdout.read()
                rtsp_server = str(output).rstrip('\r\n)')
                # print(rtsp_server)
                if 'Dahua' in str(rtsp_server):
                    print(str(dest_ip).rstrip('\r\n)') + ": Dahua RTSP Server Detected (RTSP Server)")
        except Exception as t:
            print("This didn't work", t)
            pass

        if vbose is not None:
            print("Error in getheaders(): ", str(dest_ip).rstrip('\r\n)'), ":", str(e), traceback.format_exc())

        pass

def primary_output(output_string,outfile=None):
    print(output_string)

def recurse_DNS_check(dest_ip, vbose):
    myResolver = dns.resolver.Resolver()
    myResolver.nameservers = [str(dest_ip)]
    try:
        if vbose is not None:
            print("Trying: ", dest_ip)
        start = time.time()
        while time.time() < start + 3:
            myAnswers = myResolver.query("google.com", "A")
            if myAnswers:
                print(dest_ip, "is vulnerable to DNS AMP")
                break
            else:
                print(dest_ip, "is a nope")
                break
        else:
            print(dest_ip, "is a nope")
    except KeyboardInterrupt:
        print("Quitting")
        sys.exit()
    except:
        print(dest_ip, "is not vulnerable to DNS AMP")
        pass


def recurse_ssdp_check(dest_ip, vbose):
    # try:
    try:
        a = ssdp_info.get_ssdp_information(dest_ip)
        if a is None:
            print(dest_ip, "is not an SSDP reflector")
        elif a is not None:
            print(dest_ip, "is an SSDP reflector")
        elif vbose is not None and a is not None:
            print(dest_ip, "is an SSDP reflector with result", a)

    except KeyboardInterrupt:
        if KeyboardInterrupt:
            sys.exit(1)
        print("Quitting in here")
        sys.exit(0)
    except Exception as e:
        print("Encountered exception", e)



def ntp_monlist_check(dest_ip, vbose):
    try:
        a = ntp_function.NTPscan().monlist_scan(dest_ip)
        if a is None:
            print(dest_ip, "is not vulnerable to NTP monlist")
            pass
        elif a == 1:
            print(dest_ip, "is vulnerable to monlist")
    except KeyboardInterrupt:
        print("Quitting")
        sys.exit(1)
    except Exception as e:
        if vbose is not None:
            print("Error in ntp_monlist", e)
        pass


if __name__ == '__main__':
    main()
