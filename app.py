import argparse
from HostDiscovery import HostDiscovery
from PortScanner import PortScanner

parser = argparse.ArgumentParser()
parser.add_argument('-ip', '--ipaddress', metavar='[ip address]', required=True, help="Input ip data in normal string format ex '127.0.0.1' you can do it with range like '127.0.0.1-2' or '127.0.0.1/24'")
parser.add_argument('-p', '--ports', metavar='[port number]', help="Input number of port like '80' or in range '10-80' or by a list '10,20,30'")
parser.add_argument('-ICMPing', metavar='[icmp code]', type=int, help="Performing typical ICMP ping")
parser.add_argument('-ARPing', action='store_true',  help="Performing ARP ping")
parser.add_argument('-Trace', action='store_true',  help="Perfroming Traceroute")
parser.add_argument('-DomainInfo', action='store_true', help="Get dns domain info")
parser.add_argument('-SYN', action='store_true', help="Performing TCP SYN scan")
parser.add_argument('-FIN', action='store_true', help="Performing TCP FIN scan")
parser.add_argument('-Xmas', action='store_true', help="Performing TCP XMAS scan")
parser.add_argument('-ACK', action='store_true', help="Performing TCP ACK scan")
parser.add_argument('-Null', action='store_true', help="Performing TCP NULL scan")
parser.add_argument('-Window', action='store_true', help="Performing TCP Window scan")
parser.add_argument('-Maimon', action='store_true', help="Performing TCP Maimom scan")
parser.add_argument('-Custom', '--custom_tcp_scan', metavar='[tcp flags]', help="Input flags by a spaces with only 1 letter ex.'F S R' or 'FIN SYN RST'. If you want to input more than 1 flag you neet them to stay between ''(aposthrophes)")
parser.add_argument('-UDP', action='store_true', help="Performing UDP scan")
parser.add_argument('-IProt', action='store_true', help="Performing IP Protocol scan")
parser.add_argument('--specific_result', action='store_false', help="Optional parameter to display every interpreted answers like 'port open or filtered'")
parser.add_argument('--timeout', metavar='[seconds]', default=0.1, type=float, help="Parameter to set timeout who decides how long app will wait for the answer from the target")
parser.add_argument('--retry', metavar='[number of retries]', default=0, type=int, help="Parameter who decides how many retries app will do if answer exceed timeout time")
args = parser.parse_args()
disc_dict={'ICMPing':args.ICMPing, 'ARPing':args.ARPing, 'Trace':args.Trace, 'DomainInfo':args.DomainInfo}
host_dict={'SYN':args.SYN, 'FIN':args.FIN, 'Xmas':args.Xmas, 'ACK':args.ACK, 'Null':args.Null, 'Window':args.Window, 
            'Maimon':args.Maimon, 'Custom':args.custom_tcp_scan, 'UDP':args.UDP, 'IProt':args.IProt}


if args.ICMPing != None or args.ARPing == True or args.Trace == True or args.DomainInfo == True:
    for element in disc_dict:
        if disc_dict[element] == False or disc_dict[element] == None:
            continue
        else:
            HostDiscovery(targets=args.ipaddress, discovery_type=element, icmp_type=args.ICMPing, timeout=args.timeout, retry=args.retry).discovery_scanner()
else:
    for element in host_dict:
        if host_dict[element] == False or host_dict[element] == None:
            continue
        else:
            if element in ['SYN', 'FIN', 'Xmas', 'ACK', 'Null', 'Window', 'Maimon']:
                PortScanner(targets=args.ipaddress, ports=args.ports, type_tcp=element, set_flags=args.custom_tcp_scan, 
                            specific_result=args.specific_result, timeout=args.timeout, retry=args.retry).scanner()
            else:
                PortScanner(targets=args.ipaddress, ports=args.ports, type_scan=element, set_flags=args.custom_tcp_scan, 
                            specific_result=args.specific_result, timeout=args.timeout, retry=args.retry).scanner()

#https://www.writethedocs.org/guide/writing/beginners-guide-to-docs/