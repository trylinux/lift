from __future__ import print_function

import traceback

import os
import subprocess
import sys

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
import pyasn
import dns.resolver

from lib import certs
from lib import ssdp_info, ntp_function


def main():
    parser = argparse.ArgumentParser(description='Low Impact Identification Tool')
    argroup = parser.add_mutually_exclusive_group(required=True)
    argroup.add_argument("-i", "--ip", help="An Ip address")
    argroup.add_argument("-f", "--ifile", help="A file of IPs")
    parser.add_argument("-p", "--port", help="A port")
    parser.add_argument("-v", "--verbose",
                        help="Not your usual verbosity. This is for debugging why specific outputs aren't working! USE WITH CAUTION")
    argroup.add_argument("-s", "--subnet", help="A subnet!")
    argroup.add_argument("-a", "--asn", help="ASN number. WARNING: This will take a while")
    parser.add_argument("-r", "--recurse", help="Test Recursion", action="store_true")
    parser.add_argument("-I", "--info", help="Get more info about operations", action="store_true")
    parser.add_argument("-S", "--ssl", help="For doing SSL checks only", action="store_true")
    parser.add_argument("-R", "--recon", help="Gather information about a given device", action="store_true")
    args = parser.parse_args()
    libpath = os.path.dirname(os.path.realpath(__file__)) + '/lib'
    asndb = pyasn.pyasn(libpath + '/ipasn.dat')
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
        if dport is 80 or 81:
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
    elif args.asn:
        for subnet in asndb.get_as_prefixes(int(args.asn)):
            try:
                for ip in netaddr.IPNetwork(str(subnet)):
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
                print("Quitting")
                sys.exit(1)
            except Exception as e:
                if args.verbose is not None:
                    print("Error occured in Subnet", e)
                    sys.exit(0)


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
            sys.exit(0)
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
    ctx.set_ciphers('ALL')
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
                if device is "ubiquiti":
                    print(str(dest_ip).rstrip('\r\n)') + ": Ubiquiti AirMax or AirFiber Device (SSL)")
                if "UBNT" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Ubiquiti AirMax or AirFiber Device (SSL)")
                elif "samsung" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Unknown Samsung Device (SSL)")
                elif "qnap" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": QNAP NAS TS series detected (SSL)")
                elif device is "hikvision":
                    print(str(dest_ip).rstrip('\r\n)') + ": Hikvision Default Cert")
                elif device is "avigilon":
                    print(str(dest_ip).rstrip('\r\n)') + ": Aviligon Gateway Default cert")
                elif device is "netgear_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": NetGear Default cert UTM  (SSL)")
                elif device is "verifone_sapphire":
                    print(str(dest_ip).rstrip('\r\n)') + ": Verifone Sapphire Device (SSL)")
                elif "Vigor" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": DrayTek Vigor Device (SSL)")
                elif device is "lifesize_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": Lifesize Product (SSL)")
                elif "filemaker" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Filemaker Secure Database Website (SSL)")
                elif device is "verizon_jungo":
                    print(str(dest_ip).rstrip('\r\n)') + ": Verizon Jungo OpenRG product (SSL/8443)")
                elif device is "canon_iradv":
                    print(str(dest_ip).rstrip('\r\n)') + ": Canon IR-ADV Login Page (SSL/8443)")
                elif "colubris" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": HPE MSM Series Device (SSL)")
                elif device is "ecessa":
                    print(str(dest_ip).rstrip('\r\n)') + ": Ecessa PowerLink Wan Optimizer (SSL)")
                elif device is "nomadix_ag_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": Nomadix AG series Gateway (SSL)")
                elif "netvanta" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": ADTRAN NetVanta Total Access Device (SSL)")
                elif "valuepoint_gwc_1" is device:
                    print(str(dest_ip).rstrip('\r\n)') + ": ValuePoint Networks Gateway Controller Series (SSL)")
                elif device is "broadcom_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": Broadcom Generic Modem (SSL)")
                elif device is "lg_nas_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": LG NAS Device (SSL)")
                elif device is "edgewater_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": EdgeWater Networks VOIP Solution (SSL)")
                elif device is "foscam_cam":
                    print(str(dest_ip).rstrip('\r\n)') + ": Foscam IPcam Client Login (SSL)")
                elif device is "lacie_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": LaCie CloudBox (SSL)")
                elif device is "huawei_hg658":
                    print(str(dest_ip).rstrip('\r\n)') + ": Huawei Home Gateway HG658d (SSL)")
                elif device is "interpeak_device":
                    print(str(dest_ip).rstrip('\r\n)') + ": Something made by interpeak (SSL)")
                elif device is "fujistu_celvin":
                    print(str(dest_ip).rstrip('\r\n)') + ": Fujitsu Celvin NAS (SSL)")
                elif device is "opengear_default_cert":
                    print(str(dest_ip).rstrip('\r\n)') + ": Opengear Management Console Default cert (SSL)")
                elif device is "zyxel_pk5001z":
                    print(str(dest_ip).rstrip('\r\n)') + ": Zyxel PK5001Z default cert (SSL)")
                elif device is "audiocodecs_8443":
                    print(str(dest_ip).rstrip('\r\n)') + ": AudioCodecs MP serices 443/8443 Default Cert (SSL)")
                elif "supermicro_ipmi" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Supermicro IPMI Default Certs (SSL)")
                elif device is "enco_player_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": Enco Enplayer Default Cert (SSL)")
                elif device is "ami_megarac":
                    print(str(dest_ip).rstrip('\r\n)') + ": AMI MegaRac Remote Management Default Cert (SSL)")
                elif device is "avocent_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": Avocent Default cert (unknown device) (SSL)")
                elif device is "ligowave_1":
                    print(str(dest_ip).rstrip('\r\n)') + ": LigoWave Default Cert (probably APC Propeller 5) (SSL)")
                elif "intelbras_wom500" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": IntelBras Wom500 (admin/admin) (SSL)")
                elif "netgear_2" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Netgear Default Cert Home Router (8443/SSL)")
                elif "buffalo_1" in device:
                    print(str(dest_ip).rstrip('\r\n)') + ": Buffalo Default Cert (443/SSL)")
                elif "digi_int_1" in device:
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
        except Exception as e:
            s.close()
            if 111 in e and ssl_only == 0:
                getheaders(dest_ip, dport, verbose, info)
            elif ("timed out" or 'sslv3' in e) and ssl_only == 0:
                getheaders(dest_ip, dport, verbose, info)
                pass
            pass
            # if verbose is not None:
            #	print( )str(dest_ip).rstrip('\r\n)') + ": had error " + str(e).rstrip('\r\n)'))
            if verbose is not None:
                print("Error in testip: " + str(e) + " " + str(dest_ip).rstrip('\r\n)'))
    except Exception as e:
        if 'gaierror' in str(e):
            pass
        else:
            if verbose is not None:
                print(e)




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
        title = soup.html.head.title
        if title is None:
            title = soup.html.title
        a = title.contents
        if 'EdgeOS' in title.contents and 'Ubiquiti' in cert:
            print(str(dest_ip).rstrip('\r\n)') + ": EdgeOS Device (SSL + Server header)")
        # if ('ubnt.com','UBNT') in cert:
        #	print(str(dest_ip).rstrip('\r\n)') + ": Ubiquity airOS Device non-default cert (SSL)")
        elif 'iR-ADV' in str(cert) and 'Catwalk' in str(title.contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Canon iR-ADV Login Page (SSL + Server header)")
        elif 'Cyberoam' in str(cert):
            print(str(dest_ip).rstrip('\r\n)') + ": Cyberoam Device (SSL)")
        elif 'TG582n' in str(cert):
            print(str(dest_ip).rstrip('\r\n)') + ": Technicolor TG582n (SSL)")
        elif 'RouterOS' in title.contents:
            print(str(dest_ip).rstrip('\r\n)') + ": MikroTik RouterOS (Login Page Title)")
        elif 'axhttpd/1.4.0' in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": IntelBras WOM500 (Probably admin/admin) (Server string)")
        elif 'ZeroShell' in str(a):
            print(str(dest_ip).rstrip('\r\n)') + ": ZeroShell Firewall")
        else:
            if ssl_only == 0:
                getheaders(dest_ip, 80, vbose, info)
            else:
                print("Title on IP", str(dest_ip).rstrip('\r\n)'), "is", str(a.pop()).rstrip(), '\r\n)', "and server is", server)
        checkheaders.close()
    except HTTPError as e:
        if vbose is not None:
            print(e)
            server = str(e.info().get('Server'))
            print(str(dest_ip).rstrip('\r\n)') + ": has HTTP status " + str(e.code)) + " and server " + str(server)
            pass
    except Exception as e:
        if dport is 443 and ssl_only == 0:
            dport = 80
            getheaders(dest_ip, dport, vbose, info)
        if vbose is not None:
            print("Error in getsslheaders: " + str(e) + str(dest_ip), traceback.format_exc())
        pass
    return


def getheaders(dest_ip, dport, vbose, info):
    if dport == 443:
        dport = 80
    try:
        hostname = "http://%s:%s" % (str(dest_ip).rstrip('\r\n)'), dport)
        checkheaders = urlopen(hostname, timeout=3)
        try:
            server = checkheaders.info().get('Server')
        except:
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
        if checkheaders.getcode() != 200: 
            print(str(dest_ip).rstrip('\r\n)') + ": Status Code " + checkheaders.getcode() + " Server: "+ server)
        # a = title.contents
        if 'RouterOS' in str(title_contents) and server is None:
            router_os_version = soup.find('body').h1.contents
            print(str(dest_ip).rstrip('\r\n)') + ": MikroTik RouterOS version", str(
                soup.find('body').h1.contents.pop()), "(Login Page Title)")
            soup = bs4.BeautifulSoup(html,'html.parser')
        if 'D-LINK' in str(title_contents) and 'siyou server' in server:
            dlink_model = str(soup.find("div", {"class": "modelname"}).contents.pop())
            print(str(dest_ip).rstrip('\r\n)') + ": D-LINK Router", dlink_model)
            soup = bs4.BeautifulSoup(html,'html.parser')
        if title_contents is None:
            answer = soup.find("meta", {"content": "0; url=/js/.js_check.html"})
            if "js_check" in str(answer):
                print(str(dest_ip).rstrip('\r\n)') + ": Possible  KitDuo DVR Found")

            elif 'WebServer/1.0 UPnP/1.0' in str(server):
                get_label = soup.find('label').contents
                if len(get_label) is not 0:
                    for record in get_label:
                        if 'TP-LINK' in record:
                            print(str(dest_ip).rstrip('\r\n)') + ": TP-Link Device (Unknown Model)")
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
            print(str(dest_ip).rstrip('\r\n)') + ": Panasonic IP Camera/NVR Model: " + str(title_contents.pop()))

        elif "Inicio" in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Technicolor TG series modem")

        elif str("WV-NS202A Network Camera") in str(title_contents) and server is str("HTTPD"):
            print(str(dest_ip).rstrip('\r\n)') + ": Panasonic WV-NS202A Network Camera")

        elif str("Radiant Device Brower") in str(title_contents) and str("thttpd/2.25b 29dec2003") in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": Radiant RM1121 Series Monitor")

        elif "VCS-VideoJet-Webserver" in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": Bosch AutoDome Camera")

        elif 'axhttpd/1.4.0' in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": IntelBras WOM500 (Probably admin/admin) (Server string)")

        elif 'ePMP' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Cambium ePMP 1000 Device (Server type + title)")

        elif 'Wimax CPE Configuration' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Wimax Device (PointRed, Mediatek etc) (Server type + title)")

        elif 'NXC2500' in str(title_contents) and server is None:
            print(str(dest_ip).rstrip('\r\n)') + ": Zyxel NXC2500 (Page Title)")

        elif server is not None and 'MiniServ/1.580' in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": Multichannel Power Supply System SY4527 (Server Version)")

        elif 'IIS' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ":", str(title_contents.pop()), "Server (Page Title)")

        elif 'Vigor' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ":", str(title_contents.pop()), "Switch (Title)")

        elif 'Aethra' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Aethra Telecommunications Device (Title)")

        elif 'Industrial Ethernet Switch' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Industrial Ethernet Switch (Title)")
        #Removing the following line due to some weirdness with bytes
        #elif title_contents.count(1) == 0 and "UI_ADMIN_USERNAME" in html:
        #    print(str(dest_ip).rstrip('\r\n)') + ": Greenpacket device Wimax Device (Empty title w/ Content)")

        elif 'NUUO Network Video Recorder Login' in title_contents:
            print(str(dest_ip).rstrip('\r\n)') + ": NUOO Video Recorder (admin/admin) (Title)")

        elif 'CDE-30364' in title_contents:
            print(str(dest_ip).rstrip('\r\n)') + ": Hitron Technologies CDE (Title)")

        elif 'BUFFALO' in title_contents:
            print(str(dest_ip).rstrip('\r\n)') + ": Buffalo Networking Device (Title)")

        elif 'Netgear' in title_contents:
            print(str(dest_ip).rstrip('\r\n)') + ": Netgear Generic Networking Device (Title)")

        elif 'IIS' in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ":", str(server), "Server (Server Version)")

        elif ('CentOS' or 'Ubuntu' or 'Debian') in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ":", str(server), "Linux server (Server name)")

        elif "SonicWALL" in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": SonicWALL Device (Server name)")

        elif "iGate" in title_contents:
            print(str(dest_ip).rstrip('\r\n)') + ": iGate Router or Modem (Server name)")

        elif 'LG ACSmart Premium' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": LG ACSmart Premium (admin/admin) (Server name)")

        elif 'IFQ360' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Sencore IFQ360 Edge QAM (Title)")

        elif 'Tank Sentinel AnyWare' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Franklin Fueling Systems Tank Sentinel System (Title)")

        elif 'Z-World Rabbit' in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": iBootBar (Server)")

        elif 'Intellian Aptus Web' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Intellian Device (Title)")

        elif 'SECURUS' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Securus DVR (Title)")

        elif 'uc-httpd' in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": XiongMai Technologies-based DVR/NVR/IP Camera w/ title", str(
                title_contents.pop()), "(Server)")

        elif '::: Login :::' in str(title_contents) and 'Linux/2.x UPnP/1.0 Avtech/1.0' in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": AvTech IP Camera (admin/admin) (Title and Server)")
        elif 'NetDvrV3' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": NetDvrV3-based DVR (Title)")
        elif 'Open Webif' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Open Web Interface DVR system (OpenWebIF) (root/nopassword) (Title)")
        elif 'IVSWeb' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": IVSWeb-based DVR (Possibly zenotinel ltd) (Title)")
        elif 'DVRDVS-Webs' in str(server) or 'Hikvision-Webs' in str(server) or 'App-webs/' in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": Hikvision-Based DVR (Server)")
        elif 'Router Webserver' in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": TP-LINK", str(title_contents.pop()), "(Title)")
        elif 'DD-WRT' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ":", str(title_contents.pop()), "Router (Title)")
        elif 'Samsung DVR' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Samsung DVR Unknown type (Title)")
        elif 'HtmlAnvView' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Possible Shenzhen Baoxinsheng Electric DVR (Title)")
        elif 'ZTE corp' in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": ZTE", str(title_contents.pop()), "Router (Title and Server)")
        elif 'Haier Q7' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": Haier Router Q7 Series (Title)")
        elif 'Cross Web Server' in str(server):
            print(str(dest_ip).rstrip('\r\n)') + ": TVT-based DVR/NVR/IP Camera (Server)")
        elif 'uhttpd/1.0.0' in str(server) and "NETGEAR" in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": ", str(title_contents.pop()), "(Title and server)")
        elif 'SunGuard' in str(title_contents):
            print(str(dest_ip).rstrip('\r\n)') + ": SunGuard.it Device (Title)")

        elif str(server) is str('VCS-VideoJet-Webserver'):
            print(str(dest_ip).rstrip('\r\n)') + ": Bosch Network Camera (Possibly AUTODOME IP starlight 7000)")
        else:
            try:
                title_contents = "Title on IP " + str(dest_ip).rstrip('\r\n)') + " is " + str(title_contents.pop()).rstrip(
                    '\r\n)') + " and server is " + server
                print(str(title_contents))
            except:
                print("Title on IP", str(dest_ip).rstrip('\r\n)'), "does not exists and server is", server)
        checkheaders.close()
    except HTTPError as e:
        server = str(e.info().get('Server'))
        auth_header = (e.headers.get('WWW-Authenticate'))
        if auth_header is not None and str(server) in "alphapd/2.1.8" and int(e.code) == 401:
           auth_header_split = auth_header.split(",")
           auth_header_realm = auth_header_split[0].split("=")
           device_model = str(auth_header_realm[1]).replace("\"","")
           print(str(dest_ip).rstrip('\r\n)') + ": D-Link Device Model ",str(device_model))
        elif "mini_httpd/1.19 19dec2003" in str(server) and int(e.code) == 401 :
            print(str(dest_ip).rstrip('\r\n)') + ": iCatch OEM H/D/NVR Device (Server and headers)")
        else: 
            print(str(dest_ip).rstrip('\r\n)')+ ": Server: " + str(e.info().get('Server')) + " with error " + str(e))
    except URLError as e:
        if vbose is not None:
            print(str(dest_ip).rstrip('\r\n)')+":"+str(dport)+" is not open")
        else:
            pass
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
