'''This module provides dictionaries for looking up a device's description
given its headers.
'''
'''
TODO design logic for searching on this list of tuples
(title, server, description)

For example instead of using this as the description in our tuple 
    str(dest_ip).rstrip('\r\n)') + ":",str(a.pop()), "Server (Page Title)" 
we should use
  result = "%(dest_ip)s: %(title)s Server (Page Title)"
and later when printing, we can just substitute like this 
print result % {"dest_ip": dest_ip, "title": title, "server": server}
'''

title_server_description = (
if 'RouterOS' in str(a) and server is None:
    router_os_version = soup.find('body').h1.contents
    "MikroTik RouterOS version",str(soup.find('body').h1.contents.pop()), "(Login Page Title)"
# soup = BeautifulSoup.BeautifulSoup(html)
if 'D-LINK' in str(a) and 'siyou server' in server:
    dlink_model = str(soup.find("div",{"class": "modelname"}).contents.pop())
    "D-LINK Router", dlink_model
    soup = BeautifulSoup.BeautifulSoup(html)
elif 'axhttpd/1.4.0' in str(server):
    "IntelBras WOM500 (Probably admin/admin) (Server string)"
elif 'ePMP' in str(a):
    "Cambium ePMP 1000 Device (Server type + title)"
elif 'Wimax CPE Configuration' in str(a):
    "Wimax Device (PointRed, Mediatek etc) (Server type + title)"
elif 'NXC2500' in str(a) and server is None:
    "Zyxel NXC2500 (Page Title)"
elif 'MiniServ/1.580' in server:
    "Multichannel Power Supply System SY4527 (Server Version)"
elif 'IIS' in str(a):
    print str(dest_ip).rstrip('\r\n)') + ":",str(a.pop()), "Server (Page Title)" # "%(dest_ip)s: %(title)s Server (Page Title)"
elif 'Vigor' in str(a):
    print str(dest_ip).rstrip('\r\n)') + ":",str(a.pop()), "Switch (Title)"
elif 'Aethra' in str(a):
    "Aethra Telecommunications Device (Title)"
elif 'Industrial Ethernet Switch' in str(a):
    "Industrial Ethernet Switch (Title)"
elif a.count(1) == 0 and "UI_ADMIN_USERNAME" in html:
    "Greenpacket device Wimax Device (Empty title w/ Content)"
elif 'NUUO Network Video Recorder Login' in a:
    "NUOO Video Recorder (admin/admin) (Title)"
elif 'CDE-30364' in a:
    "Hitron Technologies CDE (Title)"
elif 'BUFFALO' in a:
    "Buffalo Networking Device (Title)"
elif 'Netgear' in a:
    "Netgear Generic Networking Device (Title)"
elif 'IIS' in server:
    print str(dest_ip).rstrip('\r\n)') + ":",str(server), "Server (Server Version)"
elif ('CentOS' or 'Ubuntu' or 'Debian') in str(server):
    print str(dest_ip).rstrip('\r\n)') + ":",str(server), "Linux server (Server name)"
elif "SonicWALL" in str(server):
    "SonicWALL Device (Server name)"
elif "iGate" in a:
    "iGate Router or Modem (Server name)"
elif 'LG ACSmart Premium' in str(a):
    "LG ACSmart Premium (admin/admin) (Server name)"
elif 'IFQ360' in str(a):
    "Sencore IFQ360 Edge QAM (Title)"
elif 'Tank Sentinel AnyWare' in str(a):
    "Franklin Fueling Systems Tank Sentinel System (Title)"
elif 'Z-World Rabbit' in str(server):
    "iBootBar (Server)"
elif 'Intellian Aptus Web' in str(a):
    "Intellian Device (Title)"
elif 'SECURUS' in str(a):
    "Securus DVR (Title)"
elif 'uc-httpd' in str(server):
    "XiongMai Technologies-based DVR/NVR/IP Camera w/ title", str(a.pop()), "(Server)"
elif '::: Login :::' in str(a) and 'Linux/2.x UPnP/1.0 Avtech/1.0' in server:
    "AvTech IP Camera (admin/admin) (Title and Server)"
elif 'NetDvrV3' in str(a):
    "NetDvrV3-based DVR (Title)"
elif 'Open Webif' in str(a):
    "Open Web Interface DVR system (OpenWebIF) (root/nopassword) (Title)"
elif 'IVSWeb' in str(a):
    "IVSWeb-based DVR (Possibly zenotinel ltd) (Title)"
elif 'DVRDVS-Webs' in server or 'Hikvision-Webs' in server or 'App-webs/' in server:
        "Hikvision-Based DVR (Server)"
elif 'Router Webserver' in str(server):
    "TP-LINK", str(a.pop()), "(Title)"
elif 'DD-WRT' in str(a):
    print str(dest_ip).rstrip('\r\n)') + ":", str(a.pop()), "Router (Title)"
elif 'Samsung DVR' in str(a):
    "Samsung DVR Unknown type (Title)"
elif 'HtmlAnvView' in str(a):
    "Possible Shenzhen Baoxinsheng Electric DVR (Title)"
elif 'ZTE corp' in str(server):
    "ZTE", str(a.pop()), "Router (Title and Server)"
elif 'Haier Q7' in str(a):
    "Haier Router Q7 Series (Title)"
elif 'Cross Web Server' in str(server):
    "TVT-based DVR/NVR/IP Camera (Server)"
elif 'uhttpd/1.0.0' in str(server) and "NETGEAR" in str(a):
    "", str(a.pop()), "(Title and server)"
)
