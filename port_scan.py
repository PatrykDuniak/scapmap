import sys
import random
import time   
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import IP, UDP, TCP, ICMP, report_ports, IPTools
from scapy.sendrecv import sniff, send, sendp, sr1, sr
from scapy.layers.l2 import Ether
from scapy.compat import raw
from scapy.volatile import RandShort

#https://nmap.org/man/pl/man-port-scanning-techniques.html
#https://github.com/cptpugwash/Scapy-port-scanner/blob/master/port_scanner.py

#TCPflagsToSend
FIN = 1 #0x01
SYN = 2 #0x02
RST = 4 #0x04
PSH = 8 #0x08
ACK = 10 #0x10
URG = 20 #0x20
ECE = 40 #0x40
CWR = 80 #0x80

#ICMPcode
#0 - echo reply
#3 - destination unreachable
#8 - echo request


def ping(targets, ports):
    print("ICMP ping on: %s:%s" %(targets, ports))
    ans = sr1(IP(dst=targets)/ICMP())
    print(ans[ICMP].code)


def scan_tcp_syn(targets, ports):
    print("Scan TCP SYN on: %s:%s" %(targets, ports))
    source_port=RandShort()
    ans = sr1(IP(dst=targets)/TCP(sport=source_port, dport=ports, flags=2),timeout=5, verbose=0)
    if ans == None:
        return 'Not responding'

    if ans[TCP].flags == 18:
        return 'Port open, not filtered [SYN(2)+ACK(16)]'
    elif ans[TCP].flags == 20:
        return 'Port closed, propably not filtered [SYN(2)+RST(16)]'
    elif ans[ICMP].flags in [1,2,3,9,10,13]:
        return 'Filtered, ICMP unreachable error'
    else:
        return 'Filtered'
        

def scan_udp(targets, ports):
    print("Scan UDP on: %s:%s" %(targets, ports))
    source_port=RandShort()
    ans = sr1(IP(dst=targets)/UDP(sport=source_port, dport=ports),timeout=5, verbose=0)

    if ans == None:
        return 'Port open OR filtered OR not responding'

    if ans.haslayer(UDP):
        return 'Port open, not filtered [Got UDP packet]'

    elif ans[ICMP].code == 3:
        return 'Port closed, not filtered'

    elif ans[ICMP].code in [1,2,9,10,13]:
        return 'Filtered, ICMP unreachable error'

    else:
        return 'Filtered'
        
        
def scan_tcp_null(targets, ports):
    print("Scan TCP NULL on: %s:%s" %(targets, ports))
    source_port=RandShort()
    ans = sr1(IP(dst=targets)/TCP(sport=source_port, dport=ports, flags=0),timeout=5, verbose=0)
    
    if ans == None:
        return 'Port open OR filtered OR not responding'
        
    if ans[TCP].flags == 4:
        return 'Port closed'
    
    if ans[ICMP].code in [1, 2, 3, 9, 10, 13]:
        return 'Filtered'
    
    else:
        return 'Error'
    

def scan_tcp_fin(targets, ports):
    print("Scan TCP FIN on: %s:%s" %(targets, ports))
    source_port=RandShort()
    ans = sr1(IP(dst=targets)/TCP(sport=source_port, dport=ports, flags=1),timeout=5, verbose=0)
    
        


if __name__ == "__main__":
    random.seed(time.time())
    targets='192.168.1.3'
    ports=80
    ping(targets, ports)
    #print(scan_tcp_syn(targets, ports))
    print(scan_udp(targets, ports))
    #print(scan_tcp_null(targets, ports))
    