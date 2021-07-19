#! /usr/bin/env python3
#
# Author: Vadim Kantorov
# Source: https://github.com/vadimkantorov/wemosetup

# Vadim's python script using the discover command gives the most consistent
# results for WeMo devices on my home network using a MacBook running OS X 11.4.
#
# This script out perfoms nmap, arp and various python and bash scripts. With
# nmap and arp, only ~1/2 of my WeMo devices are found. This script finds all
# but one, even when this device has not lost connection to the network.
#
# My network has two switches and two Wi-Fi access points directly connected
# to an AT&T gateway.
#
# The script requires:
#   python3 be installed using python.org package installation
#   pip3 - I forgot how this was installed, perahps homebrew ???
#   pip3 install requests
#
# During the setup process, every WeMo switch has the same IP Address 10.22.22.1
# Vadim's script was developed to setup a WeMo device from a linux command line.
#
# I use the WeMo app and not this script to setup new, or to setup after reboot
# or after factory reset.
#
# My primary use is to find WeMos that lost connection and are not responding
# to the discover command.
#
# So, I am making changes to the script to meet my needs.
#
# To Do list (??? are things to do):
#   - ??? I really like the coding style, but I don't really understand
#     everything
#     so I am going to add more comments
#   - ??? Confirm all commands work. I don't have a WeMo bridge
#     - ??? without a bridge, bridge commands error out. Fix so appropriate
#       error message is provided
#   - add 2nd discover which uses 10.10... for bridge
# Completed:
#   - Add data command: returns MAC address, friendly name, model, hw version,
#     serial number
#   - Add a counter of devices found during discover
#   - Add more information to help and usage
#     - I am guessing at the function of add, remove, get and reset, since I
#       do not have a WeMo bridge
#   - Discover and Toggle commands work
#   - Shortened bridge commands. For example, shortened getenddevices to get
#   - Changed discover to bridge command. The bridge command uses the default
#     WeMo device setup IP Address: 10.22.22.1
#   - Discover uses my home LAN's broadcast IP address = 192.168.1.255
#   - Replaced tabs with 4 spaces, because I use nano editor, and it switches
#     tabs to spaces on cut & paste

import os
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
import csv
import requests


class SsdpDevice:
    def __init__(self, setup_xml_url, timeout = 5):
        setup_xml_response = urllib.request.urlopen(setup_xml_url, timeout = timeout).read().decode()
        self.host_port = re.search(r'//(.+):(\d+)/', setup_xml_url).groups()
        parsed_xml = xml.dom.minidom.parseString(setup_xml_response)
        self.friendly_name = parsed_xml.getElementsByTagName('friendlyName')[0].firstChild.data
        self.udn = parsed_xml.getElementsByTagName('UDN')[0].firstChild.data
        self.services = {elem.getElementsByTagName('serviceType')[0].firstChild.data : elem.getElementsByTagName('controlURL')[0].firstChild.data for elem in parsed_xml.getElementsByTagName('service')}

    def soap(self, service_name, method_name, response_tag = None, args = {}, timeout = 30):
        try:
            service_type, control_url = [(service_type, control_url) for service_type, control_url in self.services.items() if service_name in service_type][0]
            service_url = 'http://{}:{}/'.format(*self.host_port) + control_url.lstrip('/')
            request_body = f'''<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
 <s:Body>
  <u:{method_name} xmlns:u="{service_type}">
   ''' + ''.join(itertools.starmap('<{0}>{1}</{0}>'.format, args.items())) + f'''
  </u:{method_name}>
 </s:Body>
</s:Envelope>'''
            request_headers = {
                'Content-Type' : 'text/xml; charset="utf-8"',
                'SOAPACTION' : f'"{service_type}#{method_name}"',
                'Content-Length': len(request_body),
                'HOST' : '{}:{}'.format(*self.host_port)
            }
            response = urllib.request.urlopen(urllib.request.Request(service_url, request_body.encode(), headers = request_headers), timeout = timeout).read().decode()
            if response_tag:
                response = xml.dom.minidom.parseString(response).getElementsByTagName(response_tag)[0].firstChild.data
            return response
        except:
            print("Error: Soap call failed, likely missing a WeMo bridge")
            exit(0)

    @staticmethod
    def discover_devices(service_type, timeout = 5, retries = 1, mx = 3):
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
        return '{} ({}:{})'.format(self.friendly_name, *self.host_port)

class WemoDevice(SsdpDevice):
    def __init__(self, host, port):
        SsdpDevice.__init__(self, f'http://{host}:{port}/setup.xml')

    @staticmethod
    def discover_devices(*args, **kwargs):
        return [re.search(r'//(.+):(\d+)/', setup_xml_url).groups() for setup_xml_url in SsdpDevice.discover_devices(service_type = 'urn:Belkin:service:basicevent:1', *args, **kwargs)]

    def encrypt_wifi_password(self, password, meta_array):
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
        # original 2 lines of code:
        # stdout, stderr = subprocess.Popen(['openssl', 'enc', '-aes-128-cbc', '-md', 'md5', '-S', salt.encode('hex'), '-iv', iv.encode('hex'),
        #    '-pass', 'pass:' + keydata], stdin = subprocess.PIPE, stdout = subprocess.PIPE).communicate(password)
        stdout, stderr = subprocess.Popen(['openssl', 'enc', '-aes-128-cbc', '-md', 'md5', '-S', salt.encode(), '-iv', iv.encode(),
            '-pass', 'pass:' + keydata], stdin = subprocess.PIPE, stdout = subprocess.PIPE).communicate(password)

        encrypted_password = base64.b64encode(stdout[16:]) # removing 16byte magic and salt prefix inserted by OpenSSL
        encrypted_password += hex(len(encrypted_password))[2:] + ('0' if len(password) < 16 else '') + hex(len(password))[2:]
        return encrypted_password

    def generate_auth_code(self, device_id, private_key):
        expiration_time = int(time.time()) + 200
        stdout, stderr = subprocess.Popen(['openssl', 'sha1', '-binary', '-hmac', private_key], stdin = subprocess.PIPE, stdout = subprocess.PIPE).communicate(f'{device_id}\n\n{expiration_time}')
        auth_code = "SDU {}:{}:{}".format(device_id, base64.b64encode(stdout).strip(), expiration_time)
        return auth_code

    def prettify_device_state(self, state):
        return 'on' if state == 1 else 'off' if state == 0 else f'unknown ({state})'

def data (host, port):
    print()
    print('Data for WeMo device:')
    print()

    # url for setup.xml API
    # This url can also be run from a linux curl command or from a browser:
    #   http://<ip-address>:<port>/setup.xml
    url = "http://" + host + ":" + str(port) + "/setup.xml"

    # creating HTTP response object from given url
    resp = requests.get(url)

    # saving the xml file
    with open('wemo.xml', 'wb') as f:
        f.write(resp.content)

    # Open XML document using minidom parser
    DOMTree = xml.dom.minidom.parse("wemo.xml")
    device = DOMTree.documentElement

    friendlyName = device.getElementsByTagName("friendlyName")[0]
    print (" - Friendly Name: %s" % friendlyName.childNodes[0].data)

    modelName = device.getElementsByTagName("modelName")[0]
    print (" - Model Name:    %s" % modelName.childNodes[0].data)

    hwVersion = device.getElementsByTagName("hwVersion")[0]
    print (" - HW Version:    %s" % hwVersion.childNodes[0].data)

    serialNumber = device.getElementsByTagName("serialNumber")[0]
    print (" - Serial Number: %s" % serialNumber.childNodes[0].data)

    macAddress = device.getElementsByTagName("macAddress")[0]
    print (" - MAC Address:   %s" % macAddress.childNodes[0].data)

    hkSetupCode = device.getElementsByTagName("hkSetupCode")[0]
    print (" - Setup Code:    %s" % hkSetupCode.childNodes[0].data)

    # <UPC>, <brightness> and <binaryState> are not meaningful

    print()


def discover():
    print()
    print('Discovered WeMo devices:')
    print()

    firstRogue = True
    # My broadcast IP address is 192.168.1.255
    # host_ports is a list of IP address and WeMo Port
    host_ports = set(WemoDevice.discover_devices() + [('192.168.1.255', str(port)) for port in range(49151, 49156)])

    # print(host_ports)

    discovered_devices = []
    for host, port in sorted(host_ports):
        try:
            discovered_devices.append(WemoDevice(host, port))
        except urllib.error.URLError:
            if "192.168.1" != str(host)[0:9]:
                if firstRogue:
                    print(' *** WARNING: There is a Rogue DHCP Server on your network ')
                    print('''
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

            if "192.168.1.255" != str(host):
                print(' -  ' + str(host))
            continue

    print('Discovered:' if discovered_devices else 'No devices discovered')
    n = 0
    for device in discovered_devices:
        print(' - ' + str(device))
        n += 1

    print('Devices Found = ' + str(n))
    print()
    return discovered_devices

def bridge():
    print()
    print('Discovered WeMo devices, perhaps on a bridge:')
    print()

    # 10.22.22.1 is the default IP Address when a WeMo device is in setup mode
    # host_ports is a list of IP address and WeMo Port
    host_ports = set(WemoDevice.discover_devices() + [('10.22.22.1', str(port)) for port in range(49151, 49156)])
    discovered_devices = []
    for host, port in sorted(host_ports):
        try:
            discovered_devices.append(WemoDevice(host, port))
        except urllib.error.URLError:
            continue

    print('Discovered:' if discovered_devices else 'No devices discovered')
    n = 0
    for device in discovered_devices:
        print(' - ' + str(device))
        n += 1

    print('Devices Found = ' + str(n))
    print()
    return discovered_devices

def connecthomenetwork(host, port, ssid, password, timeout = 10):
    device = WemoDevice(host, port)
    aps = [ap for ap in device.soap('WiFiSetup', 'GetApList', 'ApList').split('\n') if ap.startswith(ssid + '|')]
    if len(aps) == 0:
        print(f'Could not find network "{ssid}". Try again.')
        return
    elif len(aps) > 1:
        print(f'Discovered {len(aps)} networks with SSID "{ssid}", using the first available..."')

    channel, auth_mode, encryption_mode = re.match(r'.+\|(.+)\|.+\|(.+)/(.+),', aps[0]).groups()
    meta_array = device.soap('metainfo', 'GetMetaInfo', 'MetaInfo').split('|')
    connect_status = device.soap('WiFiSetup', 'ConnectHomeNetwork', 'PairingStatus', args = {
        'ssid' : ssid, 'auth' : auth_mode,
        'password' : device.encrypt_wifi_password(password, meta_array),
        'encrypt' : encryption_mode, 'channel'  : channel})

    time.sleep(timeout)

    network_status = device.soap('WiFiSetup', 'GetNetworkStatus', 'NetworkStatus')
    close_status = device.soap('WiFiSetup', 'CloseSetup', 'status')
    print(f'Device failed to connect to the network: ({connect_status}, {network_status}). Try again.' if network_status not in ['1', '3'] or close_status != 'success' else f'Device {device} connected to network "{ssid}"')

def getenddevices(device = None, host = None, port = None, list_type = 'PAIRED_LIST'):
    device = device or WemoDevice(host, port)
    end_devices_decoded = device.soap('bridge', 'GetEndDevices', 'DeviceLists', args = {'DevUDN' : device.udn, 'ReqListType' : list_type}).replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"')
    end_devices = {str(elem.getElementsByTagName('DeviceID')[0].firstChild.data) : {'' : None, '1' : 1, '0' : 0}[elem.getElementsByTagName('CurrentState')[0].firstChild.data.split(',')[0]] for elem in xml.dom.minidom.parseString($
    if host != None and port != None:
        print(f'End devices of {device}:' if end_devices else 'No end devices of {device} were found')
        for device_id, state in sorted(end_devices.items()):
            print(' - {}, state: {}'.format(device_id, device.prettify_device_state(state)))
    return end_devices

def addenddevices(host, port, timeout = 10):
    device = WemoDevice(host, port)

    device.soap('bridge', 'OpenNetwork', args = {'DevUDN' : device.udn})
    time.sleep(timeout)

    scanned_bulb_device_ids = getenddevices(device, list_type = 'SCAN_LIST').keys()
    if scanned_bulb_device_ids:
        device.soap('bridge', 'AddDeviceName', args = {'DeviceIDs' : ','.join(scanned_bulb_device_ids), 'FriendlyNames' : ','.join(scanned_bulb_device_ids)})
        time.sleep(timeout)

    paired_bulb_device_ids = getenddevices(device, list_type = 'PAIRED_LIST').keys()
    device.soap('bridge', 'CloseNetwork', args = {'DevUDN' : device.udn})

    print('Paired bulbs: ', sorted(set(scanned_bulb_device_ids) & set(paired_bulb_device_ids)))

def removeenddevices(host, port, timeout = 10):
    device = WemoDevice(host, port)

    device.soap('bridge', 'OpenNetwork', args = {'DevUDN' : device.udn})
    time.sleep(timeout)

    scanned_bulb_device_ids = getenddevices(device, list_type = 'PAIRED_LIST').keys()
    if scanned_bulb_device_ids:
        device.soap('bridge', 'RemoveDevice', args = {'DeviceIDs' : ','.join(scanned_bulb_device_ids), 'FriendlyNames' : ','.join(scanned_bulb_device_ids)})
        time.sleep(timeout)

    paired_bulb_device_ids = getenddevices(device, list_type = 'PAIRED_LIST').keys()
    device.soap('bridge', 'CloseNetwork', args = {'DevUDN' : device.udn})

    print('Bulbs removed:', sorted(scanned_bulb_device_ids), 'bulbs left:', sorted(paired_bulb_device_ids))

def resetenddevices(host, port, timeout = 30):
    removeenddevices(host, port, timeout = timeout)
    addenddevices(host, port, timeout = timeout)

def toggle(host, port):
    device = WemoDevice(host, port)
    if 'Bridge' in device.friendly_name:
        bulbs = getenddevices(device, list_type = 'PAIRED_LIST')
        new_binary_state = 1 - int(bulbs.items()[0][1] or 0)
       device.soap('bridge', 'SetDeviceStatus', args = {'DeviceStatusList' :
            ''.join(['<?xml version="1.0" encoding="utf-8"?>'] +
            ['''<DeviceStatus><IsGroupAction>NO</IsGroupAction><DeviceID available="YES">{}</DeviceID><CapabilityID>{}</CapabilityID><CapabilityValue>{}</CapabilityValue></DeviceStatus>'''.format(bulb_device_id, 10006, new_binary$
            ).replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
            })
    else:
        new_binary_state = 1 - int(device.soap('basicevent', 'GetBinaryState', 'BinaryState') == '1')
        device.soap('basicevent', 'SetBinaryState', args = {'BinaryState' : new_binary_state})

    print('{} toggled to: {}'.format(device, device.prettify_device_state(new_binary_state)))

def ifttt(host, port, device_id):
    device = WemoDevice(host, port)
    parse_xml = lambda resp, fields: [doc.getElementsByTagName(field)[0].firstChild.data for doc in [xml.dom.minidom.parseString(resp)] for field in fields]
    error = lambda status: f'{device} failed to enable IFTTT: status code {status}'

    home_id, private_key, remote_access_status = parse_xml(device.soap('remoteaccess', 'RemoteAccess', args = {'DeviceId' : device_id, 'DeviceName' : device_id, 'dst' : 0, 'HomeId' : '', 'MacAddr' : '', 'pluginprivateKey' : '', '$
    if remote_access_status != 'S':
        print(error(remote_access_status))
        return

    auth_code = device.generate_auth_code(device_id, private_key)
    activation_code, generate_pin_status = parse_xml(urllib.request.urlopen(urllib.request.Request(f'https://api.xbcs.net:8443/apis/http/plugin/generatePin/{home_id}/IFTTT', headers = {'Content-Type' : 'application/xml', 'Authori$
    if generate_pin_status != '0':
        print(error(generate_pin_status))
        return

    print('Navigate to the following address to complete pairing:')
    print(f'https://ifttt.com/wemo_activate?wemopin={activation_code}&done_url=wemo://status=0')
    print()
    print('and run the following JavaScript code when you get to the webpage that says you need to open it from the WeMo app:')
    print('document.getElementById("WeMoAppMobileData").innerHTML = JSON.stringify({' + f'uniqueId:"{device_id}", homeId:"{home_id}", signature:"{auth_code}"' + '}); doSubmit(1);')

if __name__ == '__main__':
    # Original script failed, with -h or --help or no options
    # Optional arguments, like -h or --help don't work where options have Required = True set
    # help text should be limited to 80characters
    if ("--help" in sys.argv) or ("--h" in sys.argv) or ("-h" in sys.argv) or (len(sys.argv) == 1):
     print('''\033[1mNAME\033[0m
     wemosetup -- wemosetup can be used to setup a new WeMo device, or it can be
       used to examine or control WeMo devices on a home network or on a WeMo
       bridge. WeMo devices can be toggled on or off. Lists WeMos on network. Adds,
       removes, lists or resets WeMo devices on a WeMo bridge. Pairs with IFTTT.

\033[1mSYNOPSIS\033[0m
     python3 wemosetup.py command [-options]

\033[1mDESCRIPTION\033[0m
     WeMo devices include smart plugs, light switches, dimmers and 3-way switches
     on 802.11n Wi-Fi.

     When in setup mode, the default IP Address for the device is 10.22.22.1.

     As of JUL2021, WeMos have trouble staying connecting to a home network. Tools
     like this simplify finding WeMo devices that have lost connection.

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
          home network

       ifttt --ip <ip> --port <p> --imei <imei>
          Pair with IFTTT (will ask to follow a web link and then execute
          JavaScript from DevTools console), imei may be an arbitrary number

       toggle --ip <ip> --port <p>
          Turn WeMo on or off

     The options above are defined as:

       --ip <ip>    IP Address of device

       --password <pswd>   Password for home Wi-Fi

       --port <p>      Port WeMo device listens on. Usually, in the range
          49151..49156. 49152 and 49153 are most common

       --ssid <wifi-ssid>  SSID used by 802.11n home Wi-Fi

''')
    else:
        common = argparse.ArgumentParser(add_help = False)
        common.add_argument('--ip', required = True, dest = 'host')
        common.add_argument('--port', required = True, type = int)

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        # network commands
        subparsers.add_parser('bridge').set_defaults(func = discover)
        subparsers.add_parser('data', parents = [common]).set_defaults(func = data)
        subparsers.add_parser('discover').set_defaults(func = discover)
        subparsers.add_parser('toggle', parents = [common]).set_defaults(func = toggle)

        # bridge commands
        subparsers.add_parser('get', parents = [common]).set_defaults(func = getenddevices)
        subparsers.add_parser('add', parents = [common]).set_defaults(func = addenddevices)
        subparsers.add_parser('remove', parents = [common]).set_defaults(func = removeenddevices)
        subparsers.add_parser('reset', parents = [common]).set_defaults(func = resetenddevices)

        cmd = subparsers.add_parser('connect', parents = [common])
        cmd.add_argument('--ssid', required = True)
        cmd.add_argument('--password', required = True)
        cmd.set_defaults(func = connecthomenetwork)

        cmd = subparsers.add_parser('ifttt', parents = [common])
        cmd.add_argument('--imei', required = True, type = int, dest = 'device_id')
        cmd.set_defaults(func = ifttt)

        args = vars(parser.parse_args())
        cmd = args.pop('func')
        cmd(**args)
