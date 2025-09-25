import logging
import subprocess
import sys
import json
import ssl
import time

from socket import socket
from urllib.request import urlopen
from urllib.error import HTTPError, URLError

import bs4
import os
# import pyasn

from lift.lib import certs
from lift.lib import ssdp_info
from lift.lib import ntp_function
from lift.lib.modules.output import Output


def ishostup(dest_ip, dport, verbose):
    response = os.system("ping -c 1 " + dest_ip)
    if response == 0:
        testips(dest_ip, dport, verbose)
    else:
        pass


def testips(dest_ip, dport, ssl_only, output_handler):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("ALL:eNULL")
    s = socket()
    s.settimeout(3)
    try:
        c = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE)
        c.connect((dest_ip, dport))
        try:
            a = c.getpeercert(True)
            b = str(ssl.DER_cert_to_PEM_cert(a))
            device = certs.getcertinfo(b)
            # if verbose is not None:
            # print("Trying: ",str(dest_ip).rstrip('\r\n)'))
            # print("device: ",device)
            if device is not None:
                if device == "ubiquiti":
                    output = (
                        str(dest_ip).rstrip("\r\n)")
                        + " | Ubiquiti AirMax or AirFiber Device (SSL)"
                    )
                    output_handler.write(output)
                if "UBNT" in device:
                    output = (
                        str(dest_ip).rstrip("\r\n)")
                        + " | Ubiquiti AirMax or AirFiber Device (SSL)"
                    )
                    output_handler.write(output)
                elif "samsung" in device:
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Unknown Samsung Device (SSL)"
                    )
                    output_handler.write(output)
                elif "qnap" in device:
                    output = (
                        str(dest_ip).rstrip("\r\n)")
                        + " | QNAP NAS TS series detected (SSL)"
                    )
                    output_handler.write(output)
                elif device == "hikvision":
                    output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Hikvision Default Cert")
                    output_handler.write(output)
                elif device == "avigilon":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Aviligon Gateway Default cert"
                    )
                    output_handler.write(output)
                elif device == "netgear_1":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | NetGear Default cert UTM  (SSL)"
                    )
                    output_handler.write(output)
                elif device == "verifone_sapphire":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Verifone Sapphire Device (SSL)"
                    )
                    output_handler.write(output)
                elif "Vigor" == device:
                    output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | DrayTek Vigor Device (SSL)")
                    output_handler.write(output)
                elif device == "lifesize_1":
                    output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Lifesize Product (SSL)")
                    output_handler.write(output)
                elif "filemaker" in device:
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Filemaker Secure Database Website (SSL)"
                    )
                    output_handler.write(output)
                elif device == "verizon_jungo":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Verizon Jungo OpenRG product (SSL/8443)"
                    )
                    output_handler.write(output)
                elif device == "canon_iradv":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Canon IR-ADV Login Page (SSL/8443)"
                    )
                    output_handler.write(output)
                elif "colubris" in device:
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | HPE MSM Series Device (SSL)"
                    )
                    output_handler.write(output)
                elif device == "ecessa":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Ecessa PowerLink Wan Optimizer (SSL)"
                    )
                    output_handler.write(output)
                elif device == "nomadix_ag_1":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Nomadix AG series Gateway (SSL)"
                    )
                    output_handler.write(output)
                elif "netvanta" in device:
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | ADTRAN NetVanta Total Access Device (SSL)"
                    )
                    output_handler.write(output)
                elif "valuepoint_gwc_1" == device:
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | ValuePoint Networks Gateway Controller Series (SSL)"
                    )
                    output_handler.write(output)
                elif device == "broadcom_1":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Broadcom Generic Modem (SSL)"
                    )
                    output_handler.write(output)
                elif device == "lg_nas_1":
                    output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | LG NAS Device (SSL)")
                    output_handler.write(output)
                elif device == "edgewater_1":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | EdgeWater Networks VOIP Solution (SSL)"
                    )
                    output_handler.write(output)
                elif device == "foscam_cam":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Foscam IPcam Client Login (SSL)"
                    )
                    output_handler.write(output)
                elif device == "lacie_1":
                    output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | LaCie CloudBox (SSL)")
                    output_handler.write(output)
                elif device == "huawei_hg658":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Huawei Home Gateway HG658d (SSL)"
                    )
                    output_handler.write(output)
                elif device == "interpeak_device":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Something made by interpeak (SSL)"
                    )
                    output_handler.write(output)
                elif device == "fujistu_celvin":
                    output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Fujitsu Celvin NAS (SSL)")
                    output_handler.write(output)

                elif device == "opengear_default_cert":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Opengear Management Console Default cert (SSL)"
                    )
                    output_handler.write(output)

                elif device == "zyxel_pk5001z":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Zyxel PK5001Z default cert (SSL)"
                    )
                    output_handler.write(output)

                elif device == "audiocodecs_8443":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | AudioCodecs MP serices 443/8443 Default Cert (SSL)"
                    )
                    output_handler.write(output)

                elif "supermicro_ipmi" in device:
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Supermicro IPMI Default Certs (SSL)"
                    )
                    output_handler.write(output)

                elif device == "enco_player_1":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Enco Enplayer Default Cert (SSL)"
                    )
                    output_handler.write(output)

                elif device == "ami_megarac":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | AMI MegaRac Remote Management Default Cert (SSL)"
                    )
                    output_handler.write(output)

                elif device == "avocent_1":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Avocent Default cert (unknown device) (SSL)"
                    )
                    output_handler.write(output)

                elif device == "ligowave_1":
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | LigoWave Default Cert (probably APC Propeller 5) (SSL)"
                    )
                    output_handler.write(output)

                elif "intelbras_wom500" == device:
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | IntelBras Wom500 (admin/admin) (SSL)"
                    )
                    output_handler.write(output)

                elif "netgear_2" == device:
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Netgear Default Cert Home Router (8443/SSL)"
                    )
                    output_handler.write(output)

                elif "buffalo_1" == device:
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Buffalo Default Cert (443/SSL)"
                    )
                    output_handler.write(output)

                elif "digi_int_1" == device:
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Digi Passport Default Cert (443/SSL)"
                    )
                    output_handler.write(output)
                elif "prtg_network_monitor_1" in device:
                    output = (
                        str(dest_ip).rstrip("\r\n)")
                        + " | Paessler PTRG Monitoring Default Cert(443/SSL)"
                    )
                    output_handler.write(output)
                elif "axentra_1" in device:
                    output = (
                        str(dest_ip).rstrip("\r\n)")
                        + " | Seagate/Axentra NAS Default Cert 863B4AB (443/SSL)"
                    )
                    output_handler.write(output)

                elif "ironport_device" in device:
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Cisco IronPort Device Default SSL (443/SSL)"
                    )
                    output_handler.write(output)

                elif "meru_net_1" in device:
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | Meru Network Management Device  (443/SSL)"
                    )
                    output_handler.write(output)

                elif "bticino_1" in device:
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                        + " | BTcinino My Home Device w/ Default Cert  (443/SSL)"
                    )
                    output_handler.write(output)
            # elif "matrix_sample_ssl_1":
            # 	print(str(dest_ip).rstrip('\r\n)') + " | Matrix SSL default server for WiMax Devices(443/SSL)")
            elif a is not None and device is None:
                getheaders_ssl(dest_ip, dport, a, ctx, ssl_only, output_handler)
            else:
                print("Something error happened")

            s.close()
        except KeyboardInterrupt:
            print("Quitting")
            sys.exit(0)
        except URLError as e:
            logging.exception(
                (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " |" + str(dport) + " is not open")
            )
        except Exception as e:
            s.close()
            if 111 in e and ssl_only == 0:
                getheaders(dest_ip, dport, output_handler)
            elif ("timed out" or "sslv3" in e) and ssl_only == 0:
                getheaders(dest_ip, dport, output_handler)
                pass
            # if verbose is not None:
            # 	print( )str(dest_ip).rstrip('\r\n)') + " | had error " + str(e).rstrip('\r\n)'))
            logging.exception("Error in testip: " + str(e) + " " + str(dest_ip).rstrip("\r\n)"))
    except Exception as e:
        if "gaierror" in str(e):
            pass
        else:
            logging.exception(e)


def getheaders_ssl(dest_ip, dport, cert, ctx, ssl_only, output_handler):
    hostname = "https://%s:%s" % (str(dest_ip).rstrip("\r\n)"), dport)
    try:
        checkheaders = urlopen(hostname, context=ctx, timeout=3)
        try:
            if ("ubnt.com", "UBNT") in cert:
                output = (
                    str(dest_ip).rstrip("\r\n)")
                    + " | Ubiquity airOS Device non-default cert (SSL)"
                )
                output_handler.write(output)
        except:
            pass
        server = checkheaders.info().get("Server")
        if not server:
            server = None
        html = checkheaders.read()

        title_contents, soup, content_length = process_html(html)
        if "EdgeOS" in str(title_contents) and "Ubiquiti" in cert:
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | EdgeOS Device (SSL + Server header)"
            )
            output_handler.write(output)
        # if ('ubnt.com','UBNT') in cert:
        # 	print(str(dest_ip).rstrip('\r\n)') + " | Ubiquity airOS Device non-default cert (SSL)")
        elif "iR-ADV" in str(cert) and "Catwalk" in str(title_contents):
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Canon iR-ADV Login Page (SSL + Server header)"
            )
            output_handler.write(output)
        elif "Cyberoam" in str(cert):
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Cyberoam Device (SSL)")
            output_handler.write(output)
        elif "TG582n" in str(cert):
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Technicolor TG582n (SSL)")
            output_handler.write(output)
        elif "RouterOS" in str(title_contents):
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | MikroTik RouterOS (Login Page Title)"
            )
            output_handler.write(output)
        elif "axhttpd/1.4.0" in str(server):
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | IntelBras WOM500 (Probably admin/admin) (Server string)"
            )
            output_handler.write(output)
        elif "ZeroShell" in str(cert):
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | ZeroShell Firewall")
            output_handler.write(output)
        elif "FIBERHOME.COM.CN" in str(cert):
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Fiberhome ONU/OLT Device (SSL Cert name)"
            )
            output_handler.write(output)
        else:
                output = (
                    "Title on IP",
                    str(dest_ip).rstrip("\r\n)"),
                    "is",
                    str(title_contents.pop()).rstrip(),
                    "\r\n)",
                    "and server is",
                    str(server),
                )
                output_handler(output)
        checkheaders.close()
    except HTTPError as e:
        if "Server" in str(e.info()):
            try:
                server = str(e.info().get("Server"))
            except:
                server = "is not available"
        else:
            server = "is not available"
        if "AkamaiGHost" in str(server):
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Akamai GHost Server")
            output_handler.write(output)
        # elif vbose is not None:
        #    try:
        #        authenticate_header = e.headers.get('WWW-Authenticate')
        #    except:
        #        authenticate_header = "noauth"
        #    print(str(dest_ip).rstrip('\r\n)') + " | has HTTP status " + str(e.code) + " and server " + str(server) + " " + authenticate_header)
        else:
            pass
    except Exception as e:
            logging.exception("Error in getsslheaders: " + str(e) + str(dest_ip))
    return


def getheaders(dest_ip, dport, output_handler):
    if dport == 443:
        dport = 80
    try:
        hostname = "http://%s:%s" % (str(dest_ip).rstrip("\r\n)"), dport)
        returned_response = urlopen(hostname, timeout=3)

        try:
            server = returned_response.info().get("Server")
        except:
            server = None
        try:
            etag = returned_response.info().get("Etag")
            #print(etag)
        except:
            etag = None
        #try:
        #    keepalive = returned_response.headers.items()
        #    print(keepalive)
        #except:
        #    keepalive = None
        html = returned_response.read()
        title_contents, soup, content_length = process_html(html)

        if returned_response.getcode() != 200:
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Status Code "
                + returned_response.getcode()
                + " Server: "
                + server
            )
            output_handler.write(output)
        # a = title.contents
        if "RouterOS" in str(title_contents) and server is None:
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | MikroTik RouterOS version " +
                str(soup.find("body").h1.contents.pop()) +
                "(Login Page Title)"
            )
            output_handler.write(output)
        elif ("D-LINK" in str(title_contents) and "siyou server" in server) or (
            str(server) == "mini_httpd/1.19 19dec2003"
        ):
            dlink_model = str(soup.find("div", {"class": "modelname"}).contents.pop())
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | D-LINK Router" + dlink_model)
            output_handler.write(output)
        elif title_contents is None:

            try:
                answer = soup.find("meta", {"content": "0; url=/js/.js_check.html"})
            except Exception as e:
                answer = None
            if "Serial" in str(server) and "HP" in str(server):
                output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                    + " | HP Product w/ Identifiers -- "
                    + str(server)
                )
                output_handler.write(output)

            elif "js_check" in str(answer):
                get_login_html = "http://%s:%s/login.html" % (
                    str(dest_ip).rstrip("\r\n)"),
                    dport
                )
                try:
                    check_login_page = urlopen(get_login_html, timeout=5)
                    get_page = check_login_page.read()
                    if check_login_page.getcode() == 200:
                        soup2 = bs4.BeautifulSoup(get_page, "html.parser")
                        title2 = soup2.html.head.title
                        title2_contents = title2.contents
                        if "Airties" in title2_contents.pop():
                            output = (
                                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Airties Modem/Router"
                            )
                            output_handler.write(output)
                        else:
                            output = (
                                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Device with Title "
                                + title2
                            )
                            output_handler.write(output)
                    else:
                        output = (
                            str(dest_ip).rstrip("\r\n)")
                            + " | Possible  KitDuo DVR Found"
                        )
                        output_handler.write(output)
                except Exception as e:
                    logging.exception(e)

            elif "WebServer/1.0 UPnP/1.0" in str(server):
                get_label = soup.find("label").contents
                if len(get_label) != 0:
                    for record in get_label:
                        if "TP-LINK " in record:
                            output = (
                                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | TP-Link Device (Unknown Model)"
                            )
                            output_handler.write(output)
            elif "uc-httpd/1.0.0" in str(server):
                output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Possibly a Dahua DVR"
                output_handler.write(output)
                # This is a fucked up signature. I"m still working on it 08/15/2021
                # print(str(dest_ip).rstrip('\r\n)') + " | Hangzhou Topvision/Taoshi based D/H/NVR or IP Camera")



            elif "Boa/0.94.13" in str(server) and content_length == 142:
                # Verified 08/15/2021, the domain that is used pulls back to Macroview. This signature is pretty broad but until I find a better focus, I don't think anything else will work.
                output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Macroview KR based CCTV Device "
                )
                output_handler.write(output)

            elif "RG/Device 10.x" in str(server):
                output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | RUIJIE Networks CPE Device (port 7547)"
                )
                output_handler.write(output)

            elif "lighttpd/1.4.28" in str(server):
                #Added 08292021 -- This was a complicated one. The web interface looks like DD-WRT, and they appear to be an upstream of Ricon. The devices have the same SSL cert serial of d605caee59a2fce9
                find_redirect = soup.find_all('script')
                if "/gui/" in str(find_redirect):
                    output = (
                            str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                            + " | Hongdian Cellular Wifi Router (e.g. H8956)"
                    )
                    output_handler.write(output)

            elif (server == "DNVRS-Webs" or server == "DVRDVS-Webs") and "doc/page/login.asp" in str(html):
                #Added 04/03/2023 YET ANOTHER FREAKING HIKVISION SIGNATURE
                output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | HikVision Device")
                output_handler.write(output)
            elif server == "nginx" and "id=\"http\" name=\"http\" value=\"5000\"" in str(html):
                # Added 04/03/2023
                output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Synology Device (HTML)")
                output_handler.write(output)

            elif (str(server) == "lighttpd/1.4.55" or str(server) == "lighttpd/1.4.37") and content_length == 399:
                #Added 11/26/2021, very specific signature to match an older model of the icctv devices. I found one that had a cert that pointed to icctv.co.kr.
                output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | ICCTV Korea CCTV Device (Now KTCCTV)"

                )
                output_handler.write(output)
            else:
                output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | has server " +
                    str(server) +
                    " and no viewable title (NOID)"
                )
                output_handler.write(output)
        elif str("WebServer") in str(server) and "D-LINK" in title_contents:
            version_table = soup.find("table", {"id": "versionTable"})
            for row in version_table.find_all("td"):
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
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                + " | D-LINK Model "
                + model_name
                + " "
                + hw_version
                + " "
                + fw_version
            )
            output_handler.write(output)

        elif "Synology" in str(title_contents) and (str("nginx") in str(server) or str("Apache") in str(server) or server == None):
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Synology Device Storage Device w/ title " + title_contents.pop())
            output_handler.write(output)

        elif str(server) is str("ver2.4 rev0"):
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Panasonic IP Camera/NVR Model: "
                + str(title_contents.pop())
            )
            output_handler.write(output)

        elif "Inicio" in str(title_contents):
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Technicolor TG series modem"
            output_handler.write(output)

        elif str("WV-NS202A Network Camera") in str(title_contents) and server is str(
            "HTTPD"
        ):
            # This signature was confirmed on 08_09_2021
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Panasonic WV-NS202A Network Camera"
            )
            output_handler.write(output)

        elif str("Radiant Device Brower") in str(title_contents) and str(
            "thttpd/2.25b 29dec2003"
        ) in str(server):
            # I have no way to verify this signature as of 08_09_2021
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Probable Radiant RM1121 Series Monitor"
            )
            output_handler.write(output)

        elif "VCS-VideoJet-Webserver" in str(server):
            # Verified on 08_09_2021
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Bosch AutoDome Camera"
            output_handler.write(output)

        elif "axhttpd/1.4.0" in str(server):
            # Verified on 08_09_2021 and added to notedeck
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | IntelBras WOM500 (Probably admin/admin) (Server string)"
            )
            output_handler.write(output)

        elif "ePMP" in str(title_contents):
            # Updated the signature on 08/09/2021 to dynamically pop the contents of the title.
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Cambium " + title_contents.pop()
            output_handler.write(output)

        # Removed from signature chain on 08/09/2021, unable to verify again
        # elif 'Wimax CPE Configuration' in str(title_contents):
        #    print(str(dest_ip).rstrip('\r\n)') + " | Wimax Device (PointRed, Mediatek etc) (Server type + title)")

        elif "NXC2500" in str(title_contents) and server == None:
            # Verified on 08/09/2021
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Zyxel NXC2500 (Page Title)"
            output_handler.write(output)

        # Removing this signature on 08/09/2021 -- unable to verify
        # elif server is not None and 'MiniServ/1.580' in str(server):
        # print(str(dest_ip).rstrip('\r\n)') + " | Multichannel Power Supply System SY4527 (Server Version)")

        elif "IIS" in str(title_contents):
            # This is built off of the title of the webpage. I'm not sure I like it, but I'll keep it for now -- 08/09/2021
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | "
                + str(title_contents.pop())
                + " Server (Page Title)"
            )
            output_handler.write(str(output))

        elif "IIS" in str(server):
            # Built off of the server string, no versioning information. Verified 08/09/2021
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | "
                + str(server)
                + " Server (Server Version)"
            )
            output_handler.write(output)

        elif "Vigor" in str(title_contents):
            # Verified on 08/09/2021
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | "
                + str(title_contents.pop())
                + " Switch (Title)"
            )
            output_handler.write(output)

        elif "Aethra" in str(title_contents):
            # Verified 08/09/2021
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Aethra Telecommunications Device (Title)"
            )
            output_handler.write(output)


        # I'm removing this signature on 08/09/2021
        # elif 'Industrial Ethernet Switch' in str(title_contents):
        #   print(str(dest_ip).rstrip('\r\n)') + " | Industrial Ethernet Switch (Title)")

        # Removing the following line due to some weirdness with bytes
        # elif title_contents.count(1) == 0 and "UI_ADMIN_USERNAME" in html:
        #    print(str(dest_ip).rstrip('\r\n)') + " | Greenpacket device Wimax Device (Empty title w/ Content)")

        elif "NUUO Network Video Recorder Login" in title_contents:
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | NUOO Video Recorder (admin/admin) (Title)"
            )
            output_handler.write(output)

        elif "CDE-30364" in title_contents:
            # Verified on 08/09/2021
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Hitron Technologies CDE (Title)"
            output_handler.write(output)

        elif "BUFFALO" in title_contents:
            # Verified 08/09/2021 -- I need to add another signature for 401s.
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Buffalo Networking Device (Title)"
            )
            output_handler.write(output)

        elif "Netgear" in title_contents:
            # Verified on 08/09/2021
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Netgear Generic Networking Device (Title)"
            )
            output_handler.write(output)

        elif "Index_Page" in title_contents and "Apache" in str(server):
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Zyxel Device w/ Apache"
            output_handler.write(output)

        elif ("CentOS" or "Ubuntu" or "Debian") in str(server):
            # Verified 08/10/2021 -- A very basic signature.
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | "
                + str(server)
                + " Linux server (Server name)"
            )
            output_handler.write(output)

        elif "SonicWALL" in str(server):
            # Confirmed on 08/10/2021, this will trip on anything that has Sonicwall in the server name.
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Probable SonicWALL Network Security Appliance (Server name)"
            )
            output_handler.write(output)

        # This signature needs to be moved to the 401 group.
        #elif "iGate" in title_contents:
        #    print(str(dest_ip).rstrip('\r\n)') + " | iGate Router or Modem (Server name)")

        elif "iGate" in str(title_contents):
            #Fixed on 04/02/23
            output = (
                str(dest_ip).rstrip('\r\n)') + ":" + str(dport) + " | iGate Network Device w/ Model Number " + str(title_contents.pop()))
            output_handler.write(output)

        elif "LG ACSmart" in str(title_contents):
            # Modified and removed "premium". Verified 08/10/2021
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | LG ACSmart (admin/admin) (Server name)"
            )
            output_handler.write(output)

        # Can no longer verify this signature. Removing 08/10/2021
        # elif 'IFQ360' in str(title_contents):
        #   print(str(dest_ip).rstrip('\r\n)') + " | Sencore IFQ360 Edge QAM (Title)")

        # Can no longer verify this signature
        # elif 'Tank Sentinel AnyWare' in str(title_contents):
        #    print(str(dest_ip).rstrip('\r\n)') + " | Franklin Fueling Systems Tank Sentinel System (Title)")

        elif "Z-World Rabbit" in str(server) and "iBoot" in str(title_contents):
            # Modified this signature to be more specific. Modified and Verified 08/10/2021
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | iBootBar (Server)"
            output_handler.write(output)

        elif "Intellian Aptus Web" in str(title_contents):
            # Verified 08/09/2021
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Intellian Device (Title)"
            output_handler.write(output)

        elif "H3C-Miniware-Webs" in str(server):
            #verified 09/24/2025
            output = (
                str(dest_ip).rstrip('\r\n)') + ":" + str(dport) + " | H3C Device with Model: " + str(title_contents.pop()))
            output_handler.write(output)


        elif "SECURUS" in str(title_contents):
            # Verified 08/10/2021
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Securus DVR (Title)"
            output_handler.write(output)

        elif str(server) == "uc-httpd 1.0.0" or "NETSurveillance WEB" in str(
            title_contents
        ):
            # Verified 08/10/2021, this one pops out the dynamic title for resellers who set their own title.
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | XiongMai Technologies-based DVR/NVR/IP Camera w/ title "
                + str(title_contents.pop())
                + " (Server)"
            )
            output_handler.write(output)

        elif "Boa/0.93.15" in str(server):
            # Verified 08/09/2021. Shenzhen C-Data comes in a variety of different forms, however, they all have the same Boa version. The second signature pops the device name out of the login page.
            if "Home Gateway" in str(title_contents):
                output = (
                    str(dest_ip).rstrip("\r\n)") + str(dport) +
                    + " | Shenzhen C-Data Technology GPON/ONU/EPON Home Gateway Product"
                )
                output_handler.write(output)

            elif str("1GE") in str(title_contents) or str("1FE") in str(title_contents):
                output = (
                    str(dest_ip).rstrip("\r\n)") + str(dport) +
                    + " | Shenzhen C-Data Technology Model "
                    + str(title_contents.pop())
                )
                output_handler.write(output)

        elif ("::: Login :::" in str(
            title_contents
        ) or "Remote Surveillance, Any time & Any where" in str(title_contents)) and "Linux/2.x UPnP/1.0 Avtech/1.0" in str(server):
            # Verified 08/10/2021.  This works on a very specific subset of AvTech Cameras
            # Updated 11/18/2021 to fix a title thing
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | AvTech IP Camera (admin/admin) (Title and Server)"
            )
            output_handler.write(output)

        elif "NetDvrV3" in str(title_contents):
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | NetDvrV3-based DVR (Title)"
            output_handler.write(output)

        elif "Open Webif" in str(title_contents):
            # Unable to verify, but my notes have data regarding this. I will leave it in 08/10/2021
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Open Web Interface DVR system (OpenWebIF) (root/nopassword) (Title)"
            )
            output_handler.write(output)

        # Removing this one for now, until I can verify again.
        # elif 'IVSWeb' in str(title_contents):

        # print(str(dest_ip).rstrip('\r\n)') + " | IVSWeb-based DVR (Possibly zenotinel ltd) (Title)")

        elif (
            "DVRDVS-Webs" in str(server)
            or "DNVRS-Webs" in str(server)
            or "Hikvision-Webs" in str(server)
            or "App-webs/" in str(server)
        ):
            # Verified 08/10/2021
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Hikvision-Based DVR (Server Only)"
            output_handler.write(output)

        elif str(server) == "web":
            #Added 08/28/2021 -- This is a very specific signature for hikvision.
            find_location = soup.find_all('script')
            if "login.asp" in str(find_location):
                output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Hikvision-Based DVR (Server)"
                output_handler.write(output)

        elif etag is not None and (str(server) == "Webs" or str(server) == 'webserver') and "/doc/page/login.asp?_" in str(html):
            #Added 04/03/2023 Yet Another HikVision signature
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | HikVision Device (Header and Script)")
            output_handler.write(output)




        elif "Router Webserver" in str(server):
            # Verified 08/10/2021 -- Should be noted that there is a 401 counterpart to this.
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | TP-LINK "
                + str(title_contents.pop())
                + " (Title)"
            )
            output_handler.write(output)

        elif "- Info" in str(title_contents) and str(server) in "httpd":
            # Verified 08/10/2021
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | DD-WRT Device w/ Title "
                + str(title_contents.pop())
            )
            output_handler.write(output)

        elif "Polycom SoundPoint IP Telephone HTTPd" in str(
            server
        ) and "Polycom" in str(title_contents):
            # added on 08/16/2021, pulled from DDoS data
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Polycomm SoundPoint IP Telephone Device"
            )
            output_handler.write(output)

        elif "Samsung DVR" in str(title_contents):
            # Verified
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Samsung DVR Unknown type (Title)"
            output_handler.write(output)

        elif "IC-II" in str(title_contents) and "Hiawatha v9.2" in str(server):
            # Added and verified on 08/18/2021
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Legrand Vantage InFusion Controller"
            )
            output_handler.write(output)

        elif "Crestron AirMedia" in str(title_contents) and "Crestron Webserver" in str(
            server
        ):
            # Added and verified on 08/18/2021
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Crestron AirMedia Device"
            output_handler.write(output)

        elif "Q330 Web Server" in str(title_contents) and server == "Q330 V1.0":
            #Added 04/02/2023
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Quanterra Q330 Seismic System"
            output_handler.write(output)

        elif etag == "194e41dc6f674afe7a35b1006c546b2e" and server is None and "Comrex ACCESS" in str(title_contents):
            #Added 04/02/2023
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Comrex Device"
            output_handler.write(output)

        elif etag == "\"1722917735:2002\"" and server is None and "WEB" in str(title_contents):

           output = (
             str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Dahua Device (Etag and Title)"
            )
           output_handler.write(output)

        elif "Barix Instreamer Instreamer" in str(title_contents) and server is None:
            #Added 04/02/2023 -- Need to grab the mac address from /menu.html. Its in a weird spot so
            # it'll take some time.

            #hostname = "http://%s:%s/menu.html" % (str(dest_ip).rstrip("\r\n)"), dport)
            #get_response = urlopen(hostname, timeout=5)
            #html = get_response.read()
            #soup = bs4.BeautifulSoup(html, "html.parser")
            #model_number = soup.find('td', {'class': 'sws_home_right_table_style2'}).contents.pop()

            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Barix InStreamer Device"
            output_handler.write(output)

        #elif "Carrier"

        elif "Seagate NAS" in str(title_contents) and server == None:
            # Added and verified on 08/18/2021
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Seagate NAS Device"
            output_handler.write(output)

        elif "LaCie" in str(title_contents) and "lighttpd" in str(server):
            # Added and verified on 08/18/2021
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | LaCie Network Storage Device"
            output_handler.write(output)

        # Removing this signature until I can verify again
        # elif 'HtmlAnvView' in str(title_contents):
        #    print(str(dest_ip).rstrip('\r\n)') + " | Possible Shenzhen Baoxinsheng Electric DVR (Title)")

        elif "ZTE corp" in str(server):
            # ZTE Devices of various types. This signature dynamically pops the title out so we can get the model number. Tested and Verified on 08/18/2021
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | ZTE "
                + str(title_contents.pop())
                + " Router (Title and Server)"
            )
            output_handler.write(output)
        elif "\"222-79252\"" in etag and "Hydra/0.1.8" in str(server):
            try:
                hostname = "http://%s:%s/cgi-bin/dispatcher.cgi?cmd=0" % (str(dest_ip).rstrip("\r\n)"), dport)
                get_response = urlopen(hostname, timeout=5)
                html = get_response.read()
                title_contents, soup, content_length = process_html(html)
                model_number = str(title_contents.pop())
                output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Zyxel " + model_number
            except Exception as e:
                logging.exception(e)
                output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Zyxel Networking Device (Etag, Title, Server"

            output_handler.write(output)

        elif "SyncThru Web Service" in str(title_contents) and server is None:
            # Fixed on 08/20/2021 -- Found that the iframe has it's own URL. This pulls that URL and grabs the relevant info. Other information that could be found includes mac address and support email
            try:
                hostname = "http://%s:%s/sws.application/home/homeDeviceInfo.sws" % (str(dest_ip).rstrip("\r\n)"), dport)
                get_response = urlopen(hostname, timeout=5)
                html = get_response.read()
                soup = bs4.BeautifulSoup(html, "html.parser")
                model_number = soup.find('td', {'class':'sws_home_right_table_style2'}).contents.pop()
                output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Samsung SyncThru Printer Model " + model_number
            except Exception as e:
                logging.exception(e)
                output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Samsung SyncThru Printer"
            output_handler.write(output)

        elif "Haier Q7" in str(title_contents):
            # Tested and verified on 08/18/2021
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Haier Router Q7 Series (Title)"
            output_handler.write(output)

        elif "Web Image Monitor" in str(title_contents) and "Web-Server/3.0" in str(
            server
        ):
            # Added 08/19/2021; Need to
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Ricoh Printer Product w/ Web Image Monitor"
            )
            output_handler.write(output)

        elif "Cross Web Server" in str(server):
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | TVT-based DVR/NVR/IP Camera (Server)"
            )
            output_handler.write(output)

        elif "uhttpd/1.0.0" in str(server) and "NETGEAR" in str(title_contents):
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | "
                + str(title_contents.pop())
                + " (Title and server)"
            )
            output_handler.write(output)

        elif "SunGuard" in str(title_contents):
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | SunGuard.it Device (Title)")
            output_handler.write(output)



        elif "CMS Web Viewer" in str(title_contents) and (
            server is None or "lighttpd/1.4.54" in str(server)
        ):
            # Verified 08/19/2021
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | 3R Global DVR -- Unknown Brand"
            output_handler.write(output)

        elif "WEB SERVICE" in str(title_contents) and server is None:
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Dahua Product (DVR/NVR/HVR likely)"
            )
            output_handler.write(output)

        elif "Brother " in str(title_contents) and str("debut") in str(server):
            # Verified 08/19/2021 -- Pops the model out
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | " + str(title_contents.pop())
            output_handler.write(output)

        elif "Lexmark" in (str(title_contents)) and (
            server is None or "Lexmark" in str(server)
        ):
            # Verified 08/19/2021 -- Pops out the model
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | " + str(title_contents.pop())
            output_handler.write(output)

        elif "gSOAP/2.8" in str(server) and (
            len(title_contents) == 0
            or str("IPCamera Components Download") in str(title_contents)
        ):
            # Verified 08/19/2021 -- The XML produced by going to port 80 has a link to the TVT website and the correct WSD
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Shenzhen TVT CCTV Device (Camera or Recorder)"
            )
            output_handler.write(output)

        elif "Milesight Network Camera" in str(title_contents) and server is None:
            # Verified 08/19/2021
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Milesight Network Camera"
            output_handler.write(output)

        elif "EPSON_Linux" in str(server):
            # Verified 08/19/2021, pops the model out
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | " + str(title_contents.pop())
            output_handler.write(output)

        elif ("Boa" in str(server) or "ulwsd/1.0.1-20140331" in str(server))  and str("Web Client") in str(title_contents):
            # Verified 08/19/2021: The file ums_plugin.exe contains the domain nadatel.com
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Nadatel Device"
            output_handler.write(output)

        elif str("CPPLUS DVR") in str(title_contents) and server == None:
            # Verified 08/19/2021
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | CP PLUS DVR"
            output_handler.write(output)

        elif (
            str("ATHD DVR") in str(title_contents) or "AHD DVR" in str(title_contents)
        ) and server == None:
            # Updated 08_08_2021 to include AHD DVR. The 554 port on these say Altasec as well.
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Altasec DVR"
            output_handler.write(output)

        elif str("Network Video Recorder Login") in str(
            title_contents
        ) and "lighttpd" in str(server):
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | NUUO CCTV Product"
            output_handler.write(output)

        # This is a complex signature, due to the widespread use of Raysharp devices. It keys off of the dvrocx in the body OR the existance of the term RSVideoOCX.
        elif (
            str("Boa/0.94.14rc21") in str(server)
            and ((len(title_contents) == 0) or "WebClient" in str(title_contents))
        ) or (len(title_contents) == 0 and server is None):
            try:
                ocx = soup.body.findAll("object", {"name": "dvrocx"})
                if len(ocx) != 0:
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ':' + str(dport) +
                        + " | Raysharp CCTV Device (Unknown Downstream Brand)"
                    )
                    output_handler.write(output)
            except:
                try:
                    title_stuff = title_contents.pop()
                except:
                    title_stuff = "None"
            try:
                comment = soup.findAll(string=lambda tag: isinstance(tag, bs4.Comment))
                if "RSVideoOcx.cab" in str(comment):
                    output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport) +
                        + " | Raysharp CCTV Device (Unknown Downstream Brand)"
                    )
                    output_handler.write(output)
            except:
                output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport) +
                    + " | Raysharp CCTV Device Malformed Response Likely (Manually review)"
                )
                output_handler.write(output)

        elif content_length == 79 and str(server) == "lighttpd/1.4.28":
            find_redirect = soup.findAll('script')
            if "/gui/status_main.cgi" in find_redirect:
                output = (
                        str(dest_ip).rstrip("\r\n)") + ":" + str(dport) +
                        + " | Hongdian Cellular Wifi Router (e.g. H8956)"
                )
                output_handler.write(output)

        elif str("Mini web server 1.0 ZXIC corp 2005") in str(server):
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Shenzhen C-Data Device w/ Model "
                + title_contents.pop()
            )
            output_handler.write(output)

        elif str("BEWARD Network HD camera") in str(title_contents) and server == None:
            #Verified on 08/20/2021
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Beward IP Camera Device")
            output_handler.write(output)

        elif str("GPON ONT") in str(title_contents) and server == None:
            #Verified on 08/20/2021
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | VNPT GPON/iGate Device likely")
            output_handler.write(output)

        elif str("ZK Web Server") in str(server) and len(title_contents) == 0:
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | ZK Software-based Fingerprint Reader"
            )
            output_handler.write(output)

        elif "Keenetic Web" in str(title_contents):
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | KEENETIC Device")
            output_handler.write(output)

        elif "uc-httpd/1.0.0" in str(server):
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Hangzhou Topvision/Taoshi based D/H/NVR or IP Camera w/ Title "
                + str(title_contents.pop())
            )
            output_handler.write(output)

        elif "Reolink" in title_contents and ("nginx" in str(server) or server == None):
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Reolink DVR Device")
            output_handler.write(output)

        elif "Network Surveillance" in str(title_contents) and server == None:
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Shenzhen Baichuan Digital Technology CCTV Device"
            )
            output_handler.write(output)

        elif "Login Page" in str(title_contents) and str(server) == "httpserver":
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | EP Technology Corporation CCTV Device"
            )
            output_handler.write(output)

        elif str(server) == "GNU rsp/1.0":
            # verified 08/13/2021
            if "XVR LOGIN" in str(title_contents):
                output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                    + " | Cenova XVR Product (OEM Shenzhen Milantek Co)"
                )
            else:
                output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                    + " | Shenzhen Milantek Co OEM Device (Unknown Downstream)"
                )
            output_handler.write(output)

        elif "nginx/" in str(server) and "CentOS" in str(title_contents):
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Centos Server w/ " + str(server))
            output_handler.write(output)

        elif "nginx" in str(server) and "CentOS" not in str(title_contents):
            if "Ubuntu" in str(server):
                output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                    + " | Ubuntu Server w/ "
                    + str(server)
                    + " with title w/ "
                    + str(title_contents.pop())
                )
                output_handler.write(output)

        elif "Web Application Manager" in str(title_contents) and server is None:
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | KongTop Industrial (Shenzhen) CCTV Device"
            )
            output_handler.write(output)

        elif "PON Home Gateway" in str(title_contents) and server is None:
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Shenzhen HDV Photoelectron Technology LTD PON Device"
            )
            output_handler.write(output)

        elif (
            "Login" in str(title_contents)
            and server is None
            and "loginN4.js" in str(soup.head)
        ):
            title = str(soup.find("div", {"id": "login-title"}).contents.pop())
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Tridium Niagra Product w/ Title "
                + str(title)
            )
            output_handler.write(output)

        elif "TOTOLINK" in str(title_contents) and str(server) == "Boa/0.94.14rc21":
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Totolink Device (Modem or Router)")
            output_handler.write(output)

        elif "SVM-R1" in str(title_contents) and "Apache" in str(server):
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Daikin HVAC SVM/VRV Controller w/ Software Version "
                + str(title_contents.pop())
            )
            output_handler.write(output)

        elif str(
            title_contents
        ) == "welcome" and "GoAhead-Webs/2.5.0 PeerSec-MatrixSSL/3.4.2-OPEN" in str(
            server
        ):
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Fiberhome ONU/OLT (HTML Title and Server Name)"
            )
            output_handler.write(output)

        elif (
            "DVR_H264 ActiveX" in str(title_contents)
            or "RTDVR ActiveX" in str(title_contents)
        ) and "thttpd/2.25b 29dec2003" in str(server):
            # Added 08_07_2021, multiple points that match including UDROCX and the name "unimo" on the title page
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Unimo AU CCTV Product")
            output_handler.write(output)

        elif (str(
            server
        ) == "lighttpd/1.4.37" and "Intelligent Digital Security System" in str(
            title_contents)
        ):
            # Added 08_07_2021, The "remove activex" binary has a certificate that has the domain of icctv.co.kr and the address of Ewha in Korea.
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | ICCTV Korea CCTV Product (Now Ewha CNI/KTCCTV)"
            )
            output_handler.write(output)
        elif "Ubiquiti" in str(title_contents) and (server == "lighttpd/1.4.39" or server == "lighttpd/1.4.54"):
            #added 09052021 -- Makes a second request to grab the API info page and pulls the model number.
            url = "http://%s:%s/api/info/public?include_langs=true&lang=" % (str(dest_ip).rstrip("\r\n)"), dport)
            get_response = urlopen(url, timeout=5)
            json_unload = json.loads(get_response.read())
            model_number = json_unload['product_name']
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Ubiquiti "
                + str(model_number)
            )
            output_handler.write(output)
        elif "Linksys Smart Wifi" in str(title_contents) and server == "lighttpd/1.4.39":
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Linksys Smart Wifi Router (Belkin Era)"
            )
            output_handler.write(output)
        elif "Net Video Browser" in str(title_contents) and server == "Boa/0.94.13":
            #Added 09/09/2021 -- The object to download the "plugin" is named Tiandyvideo
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Tiandy Technologies CCTV Device"
            )
            output_handler.write(output)

        elif "Login cgicc form" in str(title_contents) and server == "Boa/0.94.13":
            #Added 09/09/2021 -- The banner is very obvious on this one. Unknown if it's an OEM.
            #Updated: Yeah it's an OEM....Need to figure out which one.
            #Updated: Later 09/09/2021 -- Found it. It's Pravis.
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Pravis Technologies CCTV Device (OEM)"
            )
            output_handler.write(output)

        elif "Boa/0.92o" in str(server) and "AXIS" in str(title_contents):
            #Added 09/09/2021 -- This might fail but I don't think anything besides Axis uses 0.92o
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Axis Network Device w/ Model Number " + str(title_contents.pop())
            )
            output_handler.write(output)

        elif "Ruckus Wireless Admin" in str(title_contents) and str(server) == "GoAhead-Webs":
            #Added 09/29/2021
            output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                    + " | Ruckus Wireless Device "
            )
            output_handler.write(output)

        elif str(server) == "ulwsd/1.0.1-20140331" and str(title_contents) == "Web Client":
            #Added 04/21/2022
            output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                    + " | SpecoTech IP Device "
            )
            output_handler.write(output)
        elif (str(server)) == "micro_httpd" and "Eltex" in str(title_contents):
            #Added 06/10/2022
            get_model = title_contents.pop().split()
            output = (
                    str(dest_ip).rstrip("\r\n)")
                    + " | Eltex " + get_model.pop()
            )
            output_handler.write(output)


        #elif str(server) == "KwikNet Web Server" and "Danfoss" in str(title_contents):
        #    #Added 11/19/2021
        #    output = (
        #            str(dest_ip).rstrip("\r\n)")
        #            + " |  "
        #   )
        #   output_handler.write(output)
        elif  "Web Client Pro" in str(title_contents) and "lighttpd" in str(server):
            #Added 11/24/2021, domain dvrdomain.com tied to this. See additional notes.
            output = (
                    str(dest_ip).rstrip("\r\n)")
                    + " | Ctring OEM CCTV Product (Server and Title) "
            )
            output_handler.write(output)

        elif "Redirecting..." in str(title_contents) and str(server) == "Apache":
            output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                    + " | Mitel MiCollab Interface"
            )
            output_handler.write(output)
        elif "Boa/0.94.14rc21" in str(server) and "main page" in str(title_contents):
            #Added 06/12/2022
            output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                    + " | Digital Watchdog CCTV Device"
            )
            output_handler.write(output)



        else:
            try:
                try:
                    title_stuff = title_contents.pop()
                except:
                    title_stuff = "None"
                crap_contents = (

                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                    + " | Title is "
                    + title_stuff.rstrip("\r\n)")
                    + " and server is "
                    + str(server)
                    + " (NOID)"
                )
                output_handler.write(str(crap_contents))
            except:
                # logging.exception(e)
                output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Title is empty and server is" + str(server) + " (NOID)"
                )
                output_handler.write(output)
        returned_response.close()
    except HTTPError as e:
        try:
            server = str(e.info().get("Server"))
        except:
            server = None


        auth_header = e.headers.get("WWW-Authenticate")

        if (
            auth_header is not None
            and (
                "alphapd/2.1.8" in str(server)
                or "Embedthis-Appweb/3.3.1" in str(server)
                or "WebServer/2.0" in str(server)
                or "RomPager/4.07 UPnP/1.0" in str(server)
            )
            and int(e.code) == 401
        ):
            auth_header_split = auth_header.split(",")
            auth_header_realm = auth_header_split[0].split("=")
            device_model = str(auth_header_realm[1]).replace('"', "")
            if "DSL-" in device_model:
                device_model_specific = 'D-Link Model ' + str(device_model)
            elif "EchoLife" in device_model:
                device_model_specific = 'Huawei EchoLife Model ' + str(device_model)
            else:
                device_model_specific = "Device Model (Multiple Possible Vendors) " + str(device_model)
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | " + device_model_specific

            )
            output_handler.write(output)
        elif (
            auth_header is not None
            and (str(server) == "PDR-M800/1.0")
            and int(e.code) == 401
        ):
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | LiLin PDR-800 DVR")
            output_handler.write(output)
        elif "mini_httpd/1.19 19dec2003" in str(server) and int(e.code) == 401:
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | iCatch OEM H/D/NVR Device (Server and headers)"
            )
            output_handler.write(output)
        elif "SERCOMM CPE Authentication" in str(auth_header):
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Sercomm CPE Device"
            )
            output_handler.write(output)

        elif "Router" in str(server) and int(e.code) == 401:
            auth_header_split = auth_header.split(",")
            auth_header_realm = auth_header_split[0].split("=")
            device_model = str(auth_header_realm[1]).replace('"', "")
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | TP-Link" + str(device_model))
            output_handler.write(output)
        elif str(server) == "none" and int(e.code) == 401:
            auth_header_split = auth_header.split(",")
            auth_header_realm = auth_header_split[0].split("=")
            device_model = str(auth_header_realm[1]).replace('"', "")
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Device model " + str(device_model))
            output_handler.write(output)
        elif "WebServer/1.0 UPnP/1.0" in str(server) and int(e.code) == 401:
            auth_header_split = auth_header.split(",")
            auth_header_realm = auth_header_split[0].split("=")
            device_model = str(auth_header_realm[1]).replace('"', "")
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | ZTE Device " + str(device_model))
            output_handler.write(output)
        elif "cpe@zte.com" in str(auth_header) and int(e.code) == 401:
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | ZTE ONU/ONT Device")
            output_handler.write(output)
        elif "WSTL CPE 1.0" in str(server) and int(e.code) == 401:
            #Added 04/03/2023 -- Frontier seems to have a lot of them
            auth_header_split = auth_header.split(",")
            auth_header_realm = auth_header_split[0].split("=")
            device_model = str(auth_header_realm[1]).replace('"', "")
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Westell CPE Device")
            output_handler.write(output)
        elif "uhttpd/1.0.0" in str(server) and "NETGEAR Orbi" in str(auth_header) and int(e.code) == 401:
            #Added 08/29/2021 -- The Auth header says Netgear ORBI
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Netgear Orbi " )
            output_handler.write(output)
        elif ("RidgeWave" in str(auth_header) or "BEC" in str(auth_header) or "MX-" in str(auth_header)) and int(e.code) == 401 and str(server) == "Boa/0.94.13":
            #added 09/08/2021 -- Pulls model number from auth header.
            auth_header_split = auth_header.split(",")
            auth_header_realm = auth_header_split[0].split("=")
            device_model = str(auth_header_realm[1]).replace('"', "")
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | BEC Model " + str(device_model))
            output_handler.write(output)
        elif "DSL-" in str(auth_header) and int(e.code) == 401 and str(server) == "Boa/0.94.13":
            #Added 09/09/2021 -- Pulls router number from auth header
            auth_header_split = auth_header.split(",")
            auth_header_realm = auth_header_split[0].split("=")
            device_model = str(auth_header_realm[1]).replace('"', "")
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Asus " + str(device_model))
            output_handler.write(output)
        elif "DCS-" in str(auth_header) and int(e.code) == 401 and (str(server) == "Boa/0.94.13" or str(server) == "alphapd"):
            #Added 09/09/2021 -- Pulls model number from auth header
            auth_header_split = auth_header.split(",")
            auth_header_realm = auth_header_split[0].split("=")
            device_model = str(auth_header_realm[1]).replace('"', "")
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | D-LINK " + str(device_model))
            output_handler.write(output)
        elif "Westermo MRD" in str(auth_header) and int(e.code) == 401 and str(server) == "GoAhead-Webs":
            #Added 09/15/2021 -- Pulls model number from auth header
            auth_header_split = auth_header.split(",")
            auth_header_realm = auth_header_split[0].split("=")
            device_model = str(auth_header_realm[1]).replace('"', "")
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | " + str(device_model))
            output_handler.write(output)
        elif "E5300B" in str(auth_header) and int(e.code) == 401 and str(server) == "Vitesse Web Server":
            #Added 02/27/2021 -- Might be a wide signature
            auth_header_split = auth_header.split(",")
            auth_header_realm = auth_header_split[0].split("=")
            device_model = str(auth_header_realm[1]).replace('"', "")
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Ubiquoss " + str(device_model))
            output_handler.write(output)

        elif str(server) == "Zscaler/6.1" and int(e.code) == 403:
            #Added 05/20/2022 -- Zscaler Proxies
            output = str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Zscaler Proxy w/ 403"
            output_handler.write(output)




        #elif "nginx" in str(server) and int(e.code) == 401:
           # print("hi")

        elif (
            "everfocus" in str(auth_header)
            or "ELUX" in str(auth_header)
            or "ECOR" in str(auth_header)
            and int(e.code) == 401
        ):
            if "ELUX" in str(auth_header):
                auth_header_split = auth_header.split(",")
                auth_header_realm = auth_header_split[0].split("=")
                device_model = str(auth_header_realm[1]).replace('"', "")
                output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                    + " | Everfocus CCTV Device Model "
                    + str(device_model)
                )

            else:

                output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport)
                    + " | Everfocus CCTV Device (admin/111111)"
                )
            output_handler.write(output)
        elif (
            str(server) == "lighttpd/1.4.32 - Android Blackeye Web Server"
            and int(e.code) == 401
        ):
            output = (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Android Blackeye Web Server")
            output_handler.write(output)
        elif str(server) == "Keil-EWEB/2.1" and int(e.code) == 401:
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Keil ARM Development Tool Web Server"
            )
            output_handler.write(output)
        elif "HuaweiHomeGateway" in str(auth_header) and int(e.code) == 401:
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Huawei Home Gateway Device (Probably PON)"
            )
            output_handler.write(output)

        elif "Amped" in str(auth_header) and int(e.code) == 401 and str(server) == "Boa/0.94.14rc21":
            #Added 09/09/2021 -- model number can be found manually here 00_00_00_userpassreq.html, its not behind the 401
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Amped Wireless Network Device (likely router)"
            )
            output_handler.write(output)




        elif int(e.code) == 302:
            if "/login.rsp" in str(e.headers):
                output = (
                    str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Exacq Technologies CCTV Product"
                )
                output_handler.write(output)


        elif int(e.code) == 401:
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Server: "
                + str(e.info().get("Server"))
                + " with auth header "
                + str(auth_header)
                + " (NOID) "
            )
            output_handler.write(output)

        else:
            output = (
                str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " | Server: "
                + str(e.info().get("Server"))
                + " with error "
                + str(e)
                + " (NOID) "

            )
            output_handler.write(output)
    except URLError as e:
        logging.exception(
            (str(dest_ip).rstrip("\r\n)") + ":" + str(dport) + " |" + str(dport) + " is not open")
        )
    except Exception as e:
        try:
            if "NoneType" in str(e):
                new_ip = str(dest_ip).rstrip("\r\n)")
                bashcommand = "curl --silent rtsp://" + new_ip + " -I -m 5| grep Server"
                # print(bashcommand)
                proc = subprocess.Popen(
                    ["bash", "-c", bashcommand], stdout=subprocess.PIPE
                )
                output = proc.stdout.read()
                rtsp_server = str(output).rstrip("\r\n)")
                # print(rtsp_server)
                if "Dahua" in str(rtsp_server):
                    output = (
                        str(dest_ip).rstrip("\r\n)")
                        + " | Dahua RTSP Server Detected (RTSP Server)"
                    )
                    output_handler.write(output)
        except Exception as t:
            if "timeout" in str(t):
                logging.exception(
                    "Error in getheaders(): ", str(dest_ip).rstrip("\r\n)"), " |", str(t)
                )
            else:
                pass

def process_html(html):
    # Moved to separate function 08/20/2021
    content_length = len(str(html))

    soup = bs4.BeautifulSoup(html, "html.parser")

    try:
        title = soup.html.head.title
        title_contents = title.contents

    except:
        try:

            title = soup.html.title
            title_contents = title.contents
        except:

            title_contents = None
    return title_contents, soup, content_length


def recurse_dns_check(dest_ip, vbose):
    import dns.resolver
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
        logging.exception("Encountered exception", e)


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
        pass
