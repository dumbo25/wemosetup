#! /usr/bin/env python3
"""
The primary use of this script is to find WeMos that lost connection or are
not responding to discover on Amazon Alexa App. However, this script does a
lot more. It is based on a python script written by Vadim Kantorov.

Vadim's python script using the discover command gives the most consistent
results for WeMo devices on my home network. I run the script on a MacBook
running OS X 11.4.

I was late to the WeMo party, and I hunted for a script that could do what I
needed. Vadim's script out perfoms nmap, arp and various python and bash scripts
on my network. With nmap and arp, only ~1/2 of my WeMo devices are found. My
assumption is this caused by the various network segments. This script finds all
my WeMo devices.

In addition, the script helped me debug several issues with my network and my
WeMo configurations.

My network has two switches and two Wi-Fi access points directly connected to an
AT&T fiber gateway (Gb). Each WeMo connected to a secondary switch or Wi-Fi AP.
So, my network has multiple network segments. A network segment makes it a bit
harder to consistently find all the devices.

During the setup process, every WeMo switch has the same IP Address 10.22.22.1
I am not certain, but I believe Vadim's script was developed to setup a WeMo
device from a linux command line.

I use the WeMo app and not the vadim script to setup new, or to setup after
reboot or after factory reset. Vadim's script also supports WeMo bridges, which
I don't have.

So, I am modifying Vadim's script to meet my needs. Hopefully, without breaking
his features.

Modules or Tools that must be installed for script to work:
    python3 be installed using python.org package installation
    pip3 - I forgot how this was installed, perahps homebrew ???
    pip3 install requests
    pydoc doesn't work on f-strings, but pydoc3 does:
        pydoc3 ./<filename>

References:
    Original Author: Vadim Kantorov
    Original Source: https://github.com/vadimkantorov/wemosetup

My Guidelines for pythonic code:
    https://sites.google.com/site/cartwrightraspberrypiprojects/home/footer/pythonic
"""

############################# <- 80 Characters -> ##############################
#
# This style of commenting is called a garden bed and it is frowned upon by
# those who know python. But, I like it. I use a garden bed at the top to track
# my to do list as I work on the code, and then mark the completed To Dos.
#
# Within the code, To Dos include a comment with ???, which makes it easy for
# me to find
#
# Once the To Do list is more-or-less complete, I move the completed items into
# comments, docstrings or help within the code. Next, I remove the completed
# items.
#
# To Do List:
#          ??? STOPPED HERE ???
#   b) add database module (see wemo-db.py)
#   c) add cve (security issues related to wemo)
#   d) add stats
#   e) the same function name is used twice: discover_devices
#   f) change snake_function_names to camelCase
#
#   u) add tests to ensure everything works
#   w) run pylint
#   x) run pydoc3 ./vadim.py
#   y) update git hub with mylog.py changes
#   z) check vadim.py into to git hub
#
# Do later or not at all:
#
# Won't Do:
#
# Completed:
#   - Added data command: returns MAC address, friendly name, model, hw version,
#     serial number
#   - Added a feature to discover command to show rogue DHCP IP addresses
#   - Added commands to turn WeMo On and Of
#   - Added find command to list WeMo(s) by Friendly Name
#     Case insensitive. Partial matching
#   - Added status command to return if WeMo is on or off
#   - Discover uses my home LAN's broadcast IP address = 192.168.1.255
#   - Added bridge command (to replace discover). The bridge command uses the
#     default WeMo device setup IP Address: 10.22.22.1
#   - Shortened bridge commands. For example, shortened getEndDevices to "get"
#   - Replaced print with logPrint
#   - Added docstrings
#   - Add a counter of devices found during discover
#   - Added more information to help and usage
#     - I am guessing at the function of add, remove, get and reset, since I
#       do not have a WeMo bridge
#   - Discover and Toggle commands work
#   - Replaced tabs with 4 spaces, because I use nano editor, and it switches
#     tabs to spaces on cut & paste
#   - Confirm all commands work. I don't have a WeMo bridge
#     - Without a bridge, bridge commands error out. Fix so appropriate
#       error message is provided
#   - Expanded help to explain each network command, bridge command, and
#     argument.
#   - in searching for a script to help debug my WeMo issue, I found a simple
#     curl call, which I thought was interesting and used that in the data
#     command. My WeMo issue was caused by a rogue DHCP server
#
# A recommendation on the web was to use static IP addresses for WeMos.
# I tried static addresses but my ISP's Gateway will only accept 20 static IP
# addresses. To eliminate the static IP addresses, I had to factory reset the
# gateway.
#
############################# <- 80 Characters -> ##############################

# Built-in Python3 Modules
import io
import re
import sys
import time
import base64
import argparse
import subprocess
import itertools
import socket
import http.client
import urllib.request
import xml.dom.minidom

# Modules that must be installed (pip3)
import requests

# My Modules (from github)
# pylint reports; C0413: Import "from mylog import MyLog" should be placed at
# the top of the module. However, I am not sure how to fix this issue. 
# sys.path.append is required for me to import my module
sys.path.append("..")
from mylog import MyLog
from wemo_db import WemoDB

# Global Veriables (FirstUpper or CapWord)
Database = None

# Global Constatnts (ALL CAPS)

# Classes
class SsdpDevice:
    """ The Simple Service Discovery Protocol (SSDP) is used by WeMos to advertise
        and discover network services, such as WeMo devices.
    """

    def __init__(self, setup_xml_url, timeout = 5):
        try:
            with urllib.request.urlopen(setup_xml_url, timeout = timeout) as r:
                setup_xml_response = r.read().decode()

        except  ConnectionResetError:
            logger.logPrint("ERROR", "Connection Reset Error. Try again.")
            sys.exit()

        self.host_port = re.search(r'//(.+):(\d+)/', setup_xml_url).groups()
        parsed_xml = xml.dom.minidom.parseString(setup_xml_response)
        self.friendly_name = parsed_xml.getElementsByTagName('friendlyName')[0].firstChild.data
        self.udn = parsed_xml.getElementsByTagName('UDN')[0].firstChild.data
        self.services = {elem.getElementsByTagName('serviceType')[0].firstChild.data : elem.getElementsByTagName('controlURL')[0].firstChild.data for elem in parsed_xml.getElementsByTagName('service')}

    def soap(self, service_name, method_name, response_tag = None, args = {}, timeout = 30):
        """ Simple Object Access Protocol exchanges messages with a WeMo device
            using the device's webservice.
        """

        try:
            service_type, control_url = [(service_type, control_url) for service_type, control_url in self.services.items() if service_name in service_type][0]
            service_url = 'http://{}:{}/'.format(*self.host_port) + control_url.lstrip('/')
            request_body = f'''<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:{method_name} xmlns:u="{service_type}">''' 
            request_body += ''.join(itertools.starmap('<{0}>{1}</{0}>'.format, args.items())) + f'''  </u:{method_name}></s:Body></s:Envelope>'''
            request_headers = {
                'Content-Type' : 'text/xml; charset="utf-8"',
                'SOAPACTION' : f'"{service_type}#{method_name}"',
                'Content-Length': len(request_body),
                'HOST' : '{}:{}'.format(*self.host_port)
            }
            # original code; changing to use with
            # response = urllib.request.urlopen(urllib.request.Request(service_url, request_body.encode(), headers = request_headers), timeout = timeout).read().decode():
            a = urllib.request.Request(service_url, request_body.encode(), headers = request_headers)
            with urllib.request.urlopen(a, timeout = timeout) as r:
                response = r.read().decode()
                if response_tag:
                    response = xml.dom.minidom.parseString(response).getElementsByTagName(response_tag)[0].firstChild.data
                return response

        except Exception as e:
            # pylint flags above with: W0703: Catching too general exception
            # I added the try/except because this was rarely failing because
            # of timeouts and other issues, which I don't recall. urlib.requests
            # identifies the exceptions it raises: e.g., urllib.error.URLError
            # However, xml.dom.minimdom does not do so adequately. So, I think
            # it is better to miss a pylint issue then to have the app fail.

            logger.logPrint("ERROR", "Soap call failed, likely missing a WeMo bridge")
            logger.logPrint("ERROR", "Exception = " + str(e))
            sys.exit()

    @staticmethod
    def discover_devices(service_type, timeout = 5, retries = 1, mx = 3):
        """ Discover WeMo devices using multicast SSDP host address
        """
        host_port = ("239.255.255.250", 1900)
        message = "\r\n".join([
            'M-SEARCH * HTTP/1.1',
            'HOST: {0}:{1}',
            'MAN: "ssdp:discover"',
            'ST: {service_type}','MX: {mx}','',''])
        socket.setdefaulttimeout(timeout)

        setup_xml_urls = []
        for _ in range(retries):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(message.format(*host_port, service_type = service_type, mx = mx).encode(), host_port)
            while True:
                try:
                    fake_socket = io.BytesIO(sock.recv(1024))
                    fake_socket.makefile = lambda *args, **kwargs: fake_socket
                    response = http.client.HTTPResponse(fake_socket)
                    response.begin()
                    setup_xml_urls.append(response.getheader('location'))
                except socket.timeout:
                    break
        return setup_xml_urls

    def __str__(self):
        """ redefine str to return the friendly name, host and port of a WeMo device
        """
        return '{} ({}:{})'.format(self.friendly_name, *self.host_port)

class WemoDevice(SsdpDevice):
    """ WeMo Device Class
    """
    def __init__(self, host, port):
        SsdpDevice.__init__(self, f'http://{host}:{port}/setup.xml')

    @staticmethod
    def discover_devices(*args, **kwargs):
        """ return a found WeMo device
        """
        return [re.search(r'//(.+):(\d+)/', setup_xml_url).groups() for setup_xml_url in SsdpDevice.discover_devices(service_type = 'urn:Belkin:service:basicevent:1', *args, **kwargs)]

    @staticmethod
    def encrypt_wifi_password(password, meta_array):
        """ Encrypt Wi-FI password
        """

        keydata = meta_array[0][0:6] + meta_array[1] + meta_array[0][6:12]
        salt, iv = keydata[0:8], keydata[0:16]
        assert len(salt) == 8 and len(iv) == 16

        # MacBook errors out on 'hex' not being valid
        #    "LookupError: 'hex' is not a text encoding; use codecs.encode() to handle arbitrary codecs"
        #    Using iv.encode errors out with:
        #        "LookupError: 'hex' is not a text encoding; use codecs.encode() to handle arbitrary codecs"
        #    Using codec.encode errors out with:
        #        "NameError: name 'codec' is not defined"
        #    ??? man page for openssl on MacBook says -pass is deprecated and should use -k

        # pylint shows:  R1732: Consider using 'with' for resource-allocating operations
        # not sure how to fix statement below without breaking the functionality
        stdout = subprocess.Popen(['openssl', 'enc', '-aes-128-cbc', '-md', 'md5', '-S', salt.encode('hex'), '-iv', iv.encode('hex'),
            '-pass', 'pass:' + keydata], stdin = subprocess.PIPE, stdout = subprocess.PIPE).communicate(password)

        encrypted_password = base64.b64encode(stdout[16:]) # removing 16byte magic and salt prefix inserted by OpenSSL
        encrypted_password += hex(len(encrypted_password))[2:] + ('0' if len(password) < 16 else '') + hex(len(password))[2:]
        return encrypted_password

    @staticmethod
    def generate_auth_code(device_id, private_key):
        """ Generate authentication code
        """

        expiration_time = int(time.time()) + 200

        # original code, changing for R1732: Consider using 'with' for resource-allocating operations
        # stdout, stderr = subprocess.Popen(['openssl', 'sha1', '-binary', '-hmac', private_key], stdin = subprocess.PIPE, stdout = subprocess.PIPE).communicate(f'{device_id}\n\n{expiration_time}')
        # auth_code = "SDU {}:{}:{}".format(device_id, base64.b64encode(stdout).strip(), expiration_time)
        # return auth_code

        with subprocess.Popen(['openssl', 'sha1', '-binary', '-hmac', private_key], stdin = subprocess.PIPE, stdout = subprocess.PIPE) as p:
            p.communicate(f'{device_id}\n\n{expiration_time}')
            auth_code = "SDU {}:{}:{}".format(device_id, base64.b64encode(stdout).strip(), expiration_time)
            return auth_code

    @staticmethod
    def prettify_device_state(state):
        """ Change 0s and 1s to ons and offs
        """
        return 'on' if state == 1 else 'off' if state == 0 else f'unknown ({state})'

# function definitions
def on(host, port):
    """ Turn a WeMo device on
    """

    logger.logPrint("INFO", "\nTurn " + str(host) + " On\n")

    cmd="curl -0 -A '' -X POST -H 'Accept: ' -H 'Content-type: text/xml; charset=\"utf-8\"' -H \"SOAPACTION: \\\"urn:Belkin:service:basicevent1#SetBinaryState\\\"\" --data '<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:SetBinaryState xmlns:u=\"urn:Belkin:service:basicevent:1\"><BinaryState>1</BinaryState></u:SetBinaryState></s:Body></s:Envelope>' -s http://" + str(host) + ":" + str(port) + "/upnp/control/basicevent1"

    logger.logPrint("DEBUG", "cmd = [" + cmd + "]")
    subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

def off(host, port):
    """ Turn a We Mo device off
    """

    logger.logPrint("INFO", "\nTurn " + str(host) + " Off\n")

    cmd="curl -0 -A '' -X POST -H 'Accept: ' -H 'Content-type: text/xml; charset=\"utf-8\"' -H \"SOAPACTION: \\\"urn:Belkin:service:basicevent1#SetBinaryState\\\"\" --data '<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:SetBinaryState xmlns:u=\"urn:Belkin:service:basicevent:1\"><BinaryState>0</BinaryState></u:SetBinaryState></s:Body></s:Envelope>' -s http://" + str(host) + ":" + str(port) + "/upnp/control/basicevent1"

    logger.logPrint("DEBUG", "cmd = [" + cmd + "]")
    subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

def status(host, port):
    """ Get status of WeMo device
    """

    cmd="curl -0 -A '' -X POST -H 'Accept: ' -H 'Content-type: text/xml; charset=\"utf-8\"' -H \"SOAPACTION: \\\"urn:Belkin:service:basicevent1#GetBinaryState\\\"\" --data '<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:GetBinaryState xmlns:u=\"urn:Belkin:service:basicevent:1\" /></s:Body></s:Envelope>' -s http://" + str(host) + ":" + str(port) + "/upnp/control/basicevent1" + " | grep '<BinaryState'"

    logger.logPrint("DEBUG", "\ncmd = [" + cmd + "]")
    response = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    if "1" in str(response):
        logger.logPrint("INFO", str(host) + " is On\n")
    if "0" in str(response):
        logger.logPrint("INFO", str(host) + " is Off\n")

def data(host, port):
    """ Get the data for a WeMo device
    """

    logger.logPrint("INFO", "\nData for WeMo device:\n")

    # url for setup.xml API
    # This url can also be run from a linux curl command or from a browser:
    #   http://<ip-address>:<port>/setup.xml
    url = "http://" + host + ":" + str(port) + "/setup.xml"

    # creating HTTP response object from given url
    try:
        resp = requests.get(url)
    except requests.exceptions.ConnectionError:
        logger.logPrint("ERROR", "Connection error: bad IP address or port: [" + host + ", " + str(port) + "]")
        sys.exit()

    # saving the xml file
    with open('wemo.xml', 'wb') as f:
        f.write(resp.content)

    # Open XML document using minidom parser
    DOMTree = xml.dom.minidom.parse("wemo.xml")
    device = DOMTree.documentElement

    friendlyName = device.getElementsByTagName("friendlyName")[0]
    logger.logPrint("INFO", " - Friendly Name: %s" % friendlyName.childNodes[0].data)

    modelName = device.getElementsByTagName("modelName")[0]
    logger.logPrint("INFO", " - Model Name:    %s" % modelName.childNodes[0].data)

    hwVersion = device.getElementsByTagName("hwVersion")[0]
    logger.logPrint("INFO", " - HW Version:    %s" % hwVersion.childNodes[0].data)

    serialNumber = device.getElementsByTagName("serialNumber")[0]
    logger.logPrint("INFO", " - Serial Number: %s" % serialNumber.childNodes[0].data)

    macAddress = device.getElementsByTagName("macAddress")[0]
    logger.logPrint("INFO", " - MAC Address:   %s" % macAddress.childNodes[0].data)

    hkSetupCode = device.getElementsByTagName("hkSetupCode")[0]
    logger.logPrint("INFO", " - Setup Code:    %s" % hkSetupCode.childNodes[0].data)

    # <UPC>, <brightness> and <binaryState> are not meaningful

    logger.logPrint("INFO", "\n")

def getData(host, port):
    """ Get Data for a WeMo device
    """

    logger.logPrint("DEBUG", "\nMAC for WeMo device:\n")

    # url for setup.xml API
    # This url can also be run from a linux curl command or from a browser:
    #   http://<ip-address>:<port>/setup.xml
    url = "http://" + host + ":" + str(port) + "/setup.xml"

    # creating HTTP response object from given url
    try:
        resp = requests.get(url)
    except requests.exceptions.ConnectionError:
        logger.logPrint("ERROR", "Connection error: bad IP address or port: [" + host + ", " + str(port) + "]")
        return None

    # saving the xml file
    with open('wemo.xml', 'wb') as f:
        f.write(resp.content)

    # Open XML document using minidom parser
    DOMTree = xml.dom.minidom.parse("wemo.xml")
    device = DOMTree.documentElement

    ma = device.getElementsByTagName("macAddress")[0]
    macAddress = ma.childNodes[0].data

    fn = device.getElementsByTagName("friendlyName")[0]
    friendlyName = fn.childNodes[0].data

    mn = device.getElementsByTagName("modelName")[0]
    modelName = mn.childNodes[0].data

    hw = device.getElementsByTagName("hwVersion")[0]
    hwVersion = hw.childNodes[0].data

    sn = device.getElementsByTagName("serialNumber")[0]
    serialNumber = sn.childNodes[0].data

    m = device.getElementsByTagName("macAddress")[0]
    macAddress = ma.childNodes[0].data

    c = device.getElementsByTagName("hkSetupCode")[0]
    setUpCode = c.childNodes[0].data

    return [macAddress, friendlyName, modelName, hwVersion, serialNumber, setUpCode]


def find(name):
    """ Find a WeMo device using the Friendly Name

        The name is case insensitive

        The name matches partial strings - so it may find multiple matches
    """

    logger.logPrint("INFO", "\n")

    found = False

    # simplified version of discover to find WeMo by Friendly Name
    # host_ports is a list of IP address and WeMo Port
    host_ports = set(WemoDevice.discover_devices() + [('192.168.1.255', str(port)) for port in range(49151, 49156)])

    logger.logPrint("DEBUG", host_ports)

    discovered_devices = []
    for host, port in sorted(host_ports):
        try:
            discovered_devices.append(WemoDevice(host, port))
        except urllib.error.URLError:
            continue

    for device in discovered_devices:
        if name.lower() in str(device).lower():
            if not found:
                logger.logPrint("INFO", "Friendly Name:" if discovered_devices else "Friendly name not found")
            logger.logPrint("INFO", " - " + str(device))
            found = True

    if found:
        logger.logPrint("INFO", " ")
    return discovered_devices

def display():
    Database.printAllData()

def discoverToList(device):
    """ Splits apart the discover string into its constituent parts
        and puts the elements in a list

        Example:
            device = Friendly Name (192.168.1.97:49153)
            tuple = ['Friendly Name', '192.168.1.97', '49153']
    """
    x = device.find('(') 
    y = device.find(':')
    z = len(device) - 1
    fn = device[:x-1]
    ip = device[x+1:y]
    port = device[y+1:z]
    return [fn, ip, port]

def discover():
    """ Discover dWeMo evices on the network
    """

    firstRogue = True
    # My broadcast IP address is 192.168.1.255
    # host_ports is a list of IP address and WeMo Port
    host_ports = set(WemoDevice.discover_devices() + [('192.168.1.255', str(port)) for port in range(49151, 49156)])

    logger.logPrint("DEBUG", host_ports)

    discovered_devices = []
    for host, port in sorted(host_ports):
        try:
            discovered_devices.append(WemoDevice(host, port))
        except urllib.error.URLError:
            if str(host)[0:9] != "192.168.1":
                if firstRogue:
                    logger.logPrint("WARNING", "There is a Rogue DHCP Server on your network")
                    logger.logPrint("INFO", '''
On a MacBook, open two terminals windows.
In 1st Terminal run this command:
    $ sudo tcpdump -nelt udp port 68 | grep -i "boot.*reply"
    Password: <your-macbook-password>

    Once the second window is opened and its command is run something like the following should appear in Terminal 1
        tcpdump: data link type PKTAP
        tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
        listening on pktap, link-type PKTAP (Apple DLT_PKTAP), capture size 262144 bytes
        58:19:f8:bf:fb:a0 > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 459: 192.168.1.254.67 > 255.255.255.255.68: BOOTP/DHCP, Reply, length 417
        b8:27:eg:82:5d:26 > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 342: 172.24.220.1.67 > 255.255.255.255.68: BOOTP/DHCP, Reply, length 300
    My DHCP server should be 192.16.1.64-253. So, the last one is rogue and serving 172.24.220.xxx

In 2nd Terminal, run the following command:
    $ sudo nmap --script broadcast-dhcp-discover -e en0

From the 1st terminal copy the first 2 or 3 octets from the MAC Address (b8:27, or b8:27:eg)
    Open a browser, and enter
        https://www.wireshark.org/tools/oui-lookup.html 
    Put the 2 - 3 octets and press find

    In the above case, b8:27 matches a raspberry pi. So, one of my raspberry pis is serving DHCP
''')
                firstRogue = False

            if str(host) != "192.168.1.255":
                logger.logPrint("INFO", " -  " + str(host))
            continue

    logger.logPrint("INFO", "Discovered:" if discovered_devices else "No devices discovered")
    n = 0
    for device in discovered_devices:
        logger.logPrint("INFO", " - " + str(device))
        l = discoverToList(str(device))
        Database.addRowDiscover(l[0], l[1], l[2])
        n += 1

    logger.logPrint("INFO", "Devices Found = " + str(n) + "\n")
    return discovered_devices

def mac():
    error = True
    rows = Database.getDiscover()
    for row in rows:
        l = getData(row[2], row[3])
        if l != None:
            error = False
            macAddress = l[0]
            # row[2] = ipAddress, row[3] = Port
            if macAddress != None:
                Database.addMacDiscover(macAddress, row[2], row[3])
            Database.addRowData(l[0], l[1], l[2], l[3], l[4], l[5])

    if error:
        logger.logPrint("INFO", "No data found. Need to run discover command before mac command")

def bridge():
    """ Original script is used with a WeMo bridge
    """

    # 10.22.22.1 is the default IP Address when a WeMo device is in setup mode
    # host_ports is a list of IP address and WeMo Port
    host_ports = set(WemoDevice.discover_devices() + [('10.22.22.1', str(port)) for port in range(49151, 49156)])
    discovered_devices = []
    for host, port in sorted(host_ports):
        try:
            discovered_devices.append(WemoDevice(host, port))
        except urllib.error.URLError:
            continue

    logger.logPrint("INFO", "Discovered:" if discovered_devices else "No devices discovered")
    n = 0
    for device in discovered_devices:
        logger.logPrint("INFO", " - " + str(device))
        n += 1

    logger.logPrint("INFO", "Devices Found = " + str(n) + "\n")
    return discovered_devices

def connectHomeNetwork(host, port, ssid, password, timeout = 10):
    """ Connect to home Wi-Fi network
    """

    device = WemoDevice(host, port)
    aps = [ap for ap in device.soap('WiFiSetup', 'GetApList', 'ApList').split('\n') if ap.startswith(ssid + '|')]
    if len(aps) > 1:
        logger.logPrint("INFO", f'Discovered {len(aps)} networks with SSID "{ssid}", using the first available..."')
    elif len(aps) == 0:
        logger.logPrint("INFO", f'Could not find network "{ssid}". Try again.')
        return

    # ??? what happens if len(aps) == 1

    channel, auth_mode, encryption_mode = re.match(r'.+\|(.+)\|.+\|(.+)/(.+),', aps[0]).groups()
    meta_array = device.soap('metainfo', 'GetMetaInfo', 'MetaInfo').split('|')
    connect_status = device.soap('WiFiSetup', 'ConnectHomeNetwork', 'PairingStatus', args = {
        'ssid' : ssid, 'auth' : auth_mode,
        'password' : device.encrypt_wifi_password(password, meta_array),
        'encrypt' : encryption_mode, 'channel'  : channel})

    time.sleep(timeout)

    network_status = device.soap('WiFiSetup', 'GetNetworkStatus', 'NetworkStatus')
    close_status = device.soap('WiFiSetup', 'CloseSetup', 'status')
    logger.logPrint("INFO", f'Device failed to connect to the network: ({connect_status}, {network_status}). Try again.' if network_status not in ['1', '3'] or close_status != 'success' else f'Device {device} connected to network "{ssid}"')

def getEndDevices(device = None, host = None, port = None, list_type = 'PAIRED_LIST'):
    """ Get End Devices
    """

    device = device or WemoDevice(host, port)
    end_devices_decoded = device.soap('bridge', 'GetEndDevices', 'DeviceLists', args = {'DevUDN' : device.udn, 'ReqListType' : list_type}).replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"')
    end_devices = {str(elem.getElementsByTagName('DeviceID')[0].firstChild.data) : {'' : None, '1' : 1, '0' : 0}[elem.getElementsByTagName('CurrentState')[0].firstChild.data.split(',')[0]] for elem in xml.dom.minidom.parseString(end_devices_decoded).getElementsByTagName('DeviceInfo')} if end_devices_decoded != '0' else {}
    if host is not None and port is not None:
        logger.logPrint("INFO", f'End devices of {device}:' if end_devices else 'No end devices of {device} were found')
        for device_id, state in sorted(end_devices.items()):
            logger.logPrint("INFO", ' - {}, state: {}'.format(device_id, device.prettify_device_state(state)))
    return end_devices

def addEndDevices(host, port, timeout = 10):
    """ Add End Devices
    """

    device = WemoDevice(host, port)

    device.soap('bridge', 'OpenNetwork', args = {'DevUDN' : device.udn})
    time.sleep(timeout)

    scanned_bulb_device_ids = getEndDevices(device, list_type = 'SCAN_LIST').keys()
    if scanned_bulb_device_ids:
        device.soap('bridge', 'AddDeviceName', args = {'DeviceIDs' : ','.join(scanned_bulb_device_ids), 'FriendlyNames' : ','.join(scanned_bulb_device_ids)})
        time.sleep(timeout)

    paired_bulb_device_ids = getEndDevices(device, list_type = 'PAIRED_LIST').keys()
    device.soap('bridge', 'CloseNetwork', args = {'DevUDN' : device.udn})

    logger.logPrint("INFO", 'Paired bulbs: ', sorted(set(scanned_bulb_device_ids) & set(paired_bulb_device_ids)))

def removeEndDevices(host, port, timeout = 10):
    """ Remove End Devices
    """

    device = WemoDevice(host, port)

    device.soap('bridge', 'OpenNetwork', args = {'DevUDN' : device.udn})
    time.sleep(timeout)

    scanned_bulb_device_ids = getEndDevices(device, list_type = 'PAIRED_LIST').keys()
    if scanned_bulb_device_ids:
        device.soap('bridge', 'RemoveDevice', args = {'DeviceIDs' : ','.join(scanned_bulb_device_ids), 'FriendlyNames' : ','.join(scanned_bulb_device_ids)})
        time.sleep(timeout)

    paired_bulb_device_ids = getEndDevices(device, list_type = 'PAIRED_LIST').keys()
    device.soap('bridge', 'CloseNetwork', args = {'DevUDN' : device.udn})

    logger.logPrint("INFO", 'Bulbs removed:', sorted(scanned_bulb_device_ids), 'bulbs left:', sorted(paired_bulb_device_ids))

def resetEndDevices(host, port, timeout = 30):
    """ Reset End Devices
    """

    removeEndDevices(host, port, timeout = timeout)
    addEndDevices(host, port, timeout = timeout)

def toggle(host, port):
    """ Toggle a Wemo device. If it is on turn it off and vice versa.
    """

    device = WemoDevice(host, port)
    if 'Bridge' in device.friendly_name:
        bulbs = getEndDevices(device, list_type = 'PAIRED_LIST')
        new_binary_state = 1 - int(bulbs.items()[0][1] or 0)
        device.soap('bridge', 'SetDeviceStatus', args = {'DeviceStatusList' :
            ''.join(['<?xml version="1.0" encoding="utf-8"?>'] +
            ['''<DeviceStatus><IsGroupAction>NO</IsGroupAction><DeviceID available="YES">{}</DeviceID><CapabilityID>{}</CapabilityID><CapabilityValue>{}</CapabilityValue></DeviceStatus>'''.format(bulb_device_id, 10006, new_binary_state) for bulb_device_id in bulbs.keys()]
            ).replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
            })
    else:
        new_binary_state = 1 - int(device.soap('basicevent', 'GetBinaryState', 'BinaryState') == '1')
        device.soap('basicevent', 'SetBinaryState', args = {'BinaryState' : new_binary_state})

    logger.logPrint("INFO", '{} toggled to: {}'.format(device, device.prettify_device_state(new_binary_state)))

def ifttt(host, port, device_id):
    """ Pair with If-This-Than-That (IFTTT)
    """

    device = WemoDevice(host, port)
    parse_xml = lambda resp, fields: [doc.getElementsByTagName(field)[0].firstChild.data for doc in [xml.dom.minidom.parseString(resp)] for field in fields]
    error = lambda status: f'{device} failed to enable IFTTT: status code {status}'

    home_id, private_key, remote_access_status = parse_xml(device.soap('remoteaccess', 'RemoteAccess', args = {'DeviceId' : device_id, 'DeviceName' : device_id, 'dst' : 0, 'HomeId' : '', 'MacAddr' : '', 'pluginprivateKey' : '', 'smartprivateKey' : '', 'smartUniqueId' : '', 'numSmartDev' : ''}), ['homeId', 'smartprivateKey', 'statusCode'])
    if remote_access_status != 'S':
        logger.logPrint("ERROR", error(remote_access_status))
        return

    auth_code = device.generate_auth_code(device_id, private_key)

    i = urllib.request.Request(f'https://api.xbcs.net:8443/apis/http/plugin/generatePin/{home_id}/IFTTT', headers = {'Content-Type' : 'application/xml', 'Authorization' : auth_code})
    with urllib.request.urlopen(i) as i2:
        activation_code, generate_pin_status = parse_xml(i2.read().decode(), ['activationCode', 'status'])
        if generate_pin_status != '0':
            logger.logPrint("ERROR", error(generate_pin_status))
            return

    logger.logPrint("INFO", 'Navigate to the following address to complete')
    logger.logPrint("INFO", 'pairing:')
    logger.logPrint("INFO", f'https://ifttt.com/wemo_activate?wemopin={activation_code}&done_url=wemo://status=0')
    logger.logPrint("INFO", '\nand run the following JavaScript code when you get')
    logger.logPrint("INFO", 'to the webpage that says you need to open it from the WeMo app:')
    logger.logPrint("INFO", 'document.getElementById("WeMoAppMobileData").innerHTML = JSON.stringify({' + f'uniqueId:"{device_id}", homeId:"{home_id}", signature:"{auth_code}"' + '}); doSubmit(1);')

def main(logger):
    global Database

    # Original script failed, with -h or --help or no options
    # Optional arguments, like -h or --help don't work where options have Required = True set
    # help text should be limited to 80characters
    if ("--help" in sys.argv) or ("--h" in sys.argv) or ("-h" in sys.argv) or (len(sys.argv) == 1):
        logger.logPrint("INFO", '''
\033[1mNAME\033[0m
     vadim -- vadim setups a new WeMo device, or controls WeMo devices on a home
              network or on a WeMo bridge. WeMo devices can be toggled on or off.
              Vadim can list all WeMos on a network. It identifies rogue DHCP
              servers. Vadim adds, removes, lists or resets WeMo devices on a
              WeMo bridge. Pairs with IFTTT.

\033[1mSYNOPSIS\033[0m
     python3 vadim.py command [-options]

\033[1mDESCRIPTION\033[0m
     WeMo devices include smart plugs, light switches, dimmers and 3-way
     switches on 802.11n Wi-Fi.

     When in setup mode, the default IP Address for the device is 10.22.22.1.

     As of JUL2021, my WeMos were having trouble staying connecting to my home
     network. Vadim simplifies finding WeMo devices that have lost connection.
     In addition, my WeMo issue was related to a rogue DHCP server. Vadim's
     discover command can identify rogue DHCP servers.

     The following WeMo bridge and/or setup commands are available. All options
     listed for a command are required:

         add --ip <ip> --port <p>
             Add a device to a WeMo bridge

         bridge
             List the friendly name, IP address and port of all WeMo devices on
             a WeMo Bridge or home network

         connect --ip <ip> --port <p> --ssid <wifi-ssid> --password <pswd>
             Connect a WeMo device to the home Wi-Fi network

         get --ip <ip> --port <p>
             List devices on WeMo bridge

         remove --ip <ip> --port <p>
             Remove devices from a WeMo bridge

         reset --ip <ip> --port <p>
             Reset WeMos (remove  and add all devices from WeMo bridge

     The following WeMo general purpose commands are available. A bridge is not
     required. All options listed for a command are required:

         data --ip <ip> --port <p>
             Lists all of the data for a WeMo's IP Address and Port found through
             discover command

         discover
             List the friendly name, IP address and port of all WeMo devices on
             home network.

             If a rogue DHCP server is on the network, then discover will
             identify it and list the rogue IP Addresses used by WeMos

             On my network, a rogue DHCP server was causing WeMos to lose
             connection

             Creates a database and stores IP Address, Port and Friendly Name.

         display
             Lists the WeMo data stored in the data and discover tables joined 
             on MAC Address

         find --name <friendly-name>
             Find IP and Mac Address of a WeMo's Friendly Name

             Enclose Friendly Names with embedded spaces in quotes

             Find matches on any substring of the Friendly Name and find is case
             insensitive. So, -name light, will match any Friendly Name
             containing Light or light

         ifttt --ip <ip> --port <p> --imei <imei>
             Pair with IFTTT (will ask to follow a web link and then execute
             JavaScript from DevTools console), imei may be an arbitrary number

         mac
             Adds MAC Address to the discover table in the database.

             Requires discover to be run first

         off --ip <ip> --port <p>
             Turn WeMo off

         on --ip <ip> --port <p>
             Turn WeMo on

         status --ip <ip> --port <p>
             Returns whether WeMo is on or off

        toggle --ip <ip> --port <p>
             Turn WeMo on or off

     The options above are defined as:

       --ip <ip>           IP Address of device

       --name              Friendly name of WEMO

       --password <pswd>   Password for home Wi-Fi

       --port <p>          Port WeMo device listens on. Usually, in the range
                           49151..49156. 49152 and 49153 are most common

       --ssid <wifi-ssid>  SSID used by 802.11n home Wi-Fi

''')
    else:
        Database = WemoDB(logger, 'vadim.db')
        Database.initializeWemoDB()

        common = argparse.ArgumentParser(add_help = False)
        common.add_argument('--ip', required = True, dest = 'host')
        common.add_argument('--port', required = True, type = int)

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        # network commands
        subparsers.add_parser('bridge').set_defaults(func = discover)
        subparsers.add_parser('display').set_defaults(func = display)
        subparsers.add_parser('data', parents = [common]).set_defaults(func = data)
        subparsers.add_parser('discover').set_defaults(func = discover)
        subparsers.add_parser('mac').set_defaults(func = mac)
        subparsers.add_parser('off', parents = [common]).set_defaults(func = off)
        subparsers.add_parser('on', parents = [common]).set_defaults(func = on)
        subparsers.add_parser('status', parents = [common]).set_defaults(func = status)
        subparsers.add_parser('toggle', parents = [common]).set_defaults(func = toggle)

        # bridge commands
        subparsers.add_parser('get', parents = [common]).set_defaults(func = getEndDevices)
        subparsers.add_parser('add', parents = [common]).set_defaults(func = addEndDevices)
        subparsers.add_parser('remove', parents = [common]).set_defaults(func = removeEndDevices)
        subparsers.add_parser('reset', parents = [common]).set_defaults(func = resetEndDevices)

        c = subparsers.add_parser('find')
        c.add_argument('--name', required = True)
        c.set_defaults(func = find)

        c = subparsers.add_parser('connect', parents = [common])
        c.add_argument('--ssid', required = True)
        c.add_argument('--password', required = True)
        c.set_defaults(func = connectHomeNetwork)

        c = subparsers.add_parser('ifttt', parents = [common])
        c.add_argument('--imei', required = True, type = int, dest = 'device_id')
        c.set_defaults(func = ifttt)

        aargs = vars(parser.parse_args())
        c = aargs.pop('func')
        c(**aargs)

if __name__ == '__main__':
    logger = MyLog()
    logger.setLevel("INFO")
    logger.setOutput("CONSOLE")
    logger.openOutput()

    main(logger)
