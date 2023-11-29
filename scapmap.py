#!/usr/bin/env python
import argparse
from argparse import RawDescriptionHelpFormatter
from Resources import HostDiscovery, PortScanner, GetDomainCert, WebScrapper

parser = argparse.ArgumentParser(usage='use "python %(prog)s --help" for more information',formatter_class=RawDescriptionHelpFormatter, 
description=''' 
 _____                                       
/  ___|                                      
\ `--.  ___ __ _ _ __  _ __ ___   __ _ _ __  
 `--. \/ __/ _` | '_ \| '_ ` _ \ / _` | '_ \ 
/\__/ / (_| (_| | |_) | | | | | | (_| | |_) |
\____/ \___\__,_| .__/|_| |_| |_|\__,_| .__/ 
                | |                   | |    
                |_|                   |_|    

Welcome to Scapmap! Port scanner and host discovery application (like nmap) written in python based on scapmap library.

Prerequisites:
>OS: Works fine on both Windows and Linux distributions
>Python version: Tested on Python 3.9.7 but should work on other too
>Scapy version: Tested on 2.4.5, older versions can have some problems

Examples of use:
This application allows you to use different scans and discovery in 1 command on 1 host or multiple of them.
If you see a lot of 'Protocol open OR filtered' that means that whole traffic was cutted by a target or just host is down, check it with discovery functions like ARPing.

Ping whole subnet, in -ICMPing we are providing
>python scapmap.py -ip 192.168.0.1/24 -ICMPing
We can also specific icmp code like 13 te get timestamps
>python scapmap.py -ip 192.168.0.1/24 -ICMPing 13

Scan ports with TCP SYN, FIN, Xmas on range 80-139
>python scapmap.py -ip 192.168.1.254 -p 80-139 -SYN -FIN -Xmas
There is a chance to see a lot of 'Filtered' even if host is not filtering traffic, we can change timeout time and set specific_result flag to see less and more proper results (but if host is not filtering traffic only in SYN we can see less results, cause 'port  closed' in my opinion is specific result).
>python scapmap.py -ip 192.168.1.254 -p 80-139 -SYN -FIN -Xmas --timeout 1 --specific_result

We can also combine host discovery and port scans
>python scapmap.py -ip 192.168.1.254/30 -p 80 -ARPing -SYN -UDP -IProt -Custom 'F S R' --timeout 0.01 --specific_result
'''
)

parser.add_argument('-ip', '--ipaddress', metavar='[ip address]', default='127.0.0.1', help="Input ip data in normal string format ex '127.0.0.1' you can do it with range like '127.0.0.1-2' or '127.0.0.1/24'")
parser.add_argument('-p', '--ports', metavar='[port number]', default='80', help="Input number of port like '80' or in range '10-80' or by a list '10,20,30'")
parser.add_argument('-web', '--website', metavar='[website]', help="Input full website name with https/http and port if service is not in default port")
parser.add_argument('--ICMPing', metavar='icmp code', nargs='?', type=int, default=None, const=8, help="Performing typical ICMP ping")
parser.add_argument('--ARPing', action='store_true',  help="Performing ARP ping")
parser.add_argument('--Trace', action='store_true',  help="Perfroming Traceroute")
parser.add_argument('--SYN', action='store_true', help="Performing TCP SYN scan")
parser.add_argument('--FIN', action='store_true', help="Performing TCP FIN scan")
parser.add_argument('--Xmas', action='store_true', help="Performing TCP XMAS scan")
parser.add_argument('--ACK', action='store_true', help="Performing TCP ACK scan")
parser.add_argument('--Null', action='store_true', help="Performing TCP NULL scan")
parser.add_argument('--Window', action='store_true', help="Performing TCP Window scan")
parser.add_argument('--Maimon', action='store_true', help="Performing TCP Maimom scan")
parser.add_argument('--CustomTCPScan', metavar='[tcp flags]', help="Input flags by a spaces with only 1 letter ex.\"F S R\" or \"FIN SYN RST\". If you want to input more than 1 flag you neet them to stay between \"\"")
parser.add_argument('--UDP', action='store_true', help="Performing UDP scan")
parser.add_argument('--IProt', action='store_true', help="Performing IP Protocol scan")
parser.add_argument('--specific_result', action='store_true', help="Optional parameter to display only specific answers like 'port open' not like 'port open or filtered'")
parser.add_argument('--grab_banner', action='store_true', help="Optional parameter to display service banner")
parser.add_argument('--certinfo', action='store_true', help="Display infomration of domain cert")
parser.add_argument('--getcert', action='store_true', help="Get cert in pem format")
parser.add_argument('--scrapwebsite', action='store_true', help="Scrap website")
parser.add_argument('--collectlinks', metavar='[depth]', default=-1, type=int, help="Get links(href) from website with specific depth")
parser.add_argument('--noverify', action='store_false', help="Get links(href) from website with specific depth")
parser.add_argument('--diffdomain', action='store_false', help="Get links(href) from website with specific depth")
parser.add_argument('--timeout', metavar='[seconds]', default=0.1, type=float, help="Parameter to set timeout who decides how long app will wait for the answer from the target")
parser.add_argument('--retry', metavar='[number of retries]', default=1, type=int, help="Parameter who decides how many retries app will do if answer exceed timeout time")
args = parser.parse_args()
disc_dict={'ICMPing':args.ICMPing, 'ARPing':args.ARPing, 'Trace':args.Trace}
host_dict={'SYN':args.SYN, 'FIN':args.FIN, 'Xmas':args.Xmas, 'ACK':args.ACK, 'Null':args.Null, 'Window':args.Window, 
            'Maimon':args.Maimon, 'Custom':args.CustomTCPScan, 'UDP':args.UDP, 'IProt':args.IProt}

if args.website != 'None':
    if args.certinfo == True:
        GetDomainCert(args.website).get_domain_cert_info()
    if args.getcert == True:
        GetDomainCert(args.website).get_domain_raw_cert()
    if args.scrapwebsite == True:
        WebScrapper(args.website, args.noverify).download_page_with_attachments()
    if args.collectlinks >= 0:
        WebScrapper(args.website, args.noverify).collect_links(args.collectlinks, args.diffdomain)


for element in disc_dict:
    if disc_dict[element] == False or disc_dict[element] == None:
        continue
    else:
        HostDiscovery(targets=args.ipaddress, discovery_type=element, icmp_type=args.ICMPing, timeout=args.timeout, retry=args.retry).discovery_scanner()
        print('\n')

for element in host_dict:
    if host_dict[element] == False or host_dict[element] == None:
        continue
    else:
        if element in ['SYN', 'FIN', 'Xmas', 'ACK', 'Null', 'Window', 'Maimon']:
            PortScanner(targets=args.ipaddress, ports=args.ports, type_tcp=element, set_flags=args.CustomTCPScan, 
                        specific_result=args.specific_result, grab_banner = args.grab_banner, timeout=args.timeout, retry=args.retry).scanner()
            print('\n')
        else:
            PortScanner(targets=args.ipaddress, ports=args.ports, type_scan=element, set_flags=args.CustomTCPScan, 
                            specific_result=args.specific_result, grab_banner = args.grab_banner, timeout=args.timeout, retry=args.retry).scanner()
            print('\n')