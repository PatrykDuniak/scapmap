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

#Tcp Flags
#Urgent Pointer 32
#ACK            16
#Push            8
#Reset           4
#SYN             2
#FIN             1

#ICMPcode
#0 - echo reply
#3 - destination unreachable
#8 - echo request


def ping(targets):
    print("ICMP ping on: %s" %(targets))
    ans = sr1(IP(dst=targets)/ICMP(), verbose=False)
    try:
        return ans[ICMP].code
    except:
        return -1 

def scan_tcp_syn(targets, ports):
    print("Scan TCP SYN on: %s:%s" %(targets, ports))
    
    if ping(targets) != 0:
        return 'Not responding'
    
    source_port=RandShort()
    ans = sr1(IP(dst=targets)/TCP(sport=source_port, dport=ports, flags=2),timeout=5, verbose=False)
    
    
    if ans == None:
        return 'Filtered'

    elif ans[TCP].flags == 18:
        return 'Port open, not filtered [SYN(2)+ACK(16)]'

    elif ans[TCP].flags == 20:
        return 'Port closed, propably not filtered [RST(4)+ACK(16)]'

    elif ans[ICMP].flags in [1,2,3,9,10,13]:
        return 'Filtered, ICMP unreachable error'

    else:
        return 'Error'
        

def scan_udp(targets, ports):
    print("Scan UDP on: %s:%s" %(targets, ports))
    
    if ping(targets) != 0:
        return 'Not responding'
    
    source_port=RandShort()
    ans = sr1(IP(dst=targets)/UDP(sport=source_port, dport=ports),timeout=30, verbose=False)
    
    if ans == None:
        return 'Port open OR filtered'

    elif ans.haslayer(UDP):
        return 'Port open, not filtered [Got UDP packet]'

    elif ans[ICMP].code == 3:
        return 'Port closed, not filtered'

    elif ans[ICMP].code in [1,2,9,10,13]:
        return 'Filtered, ICMP unreachable error'

    else:
        return 'Filtered'
        
        
def scan_tcp_null(targets, ports):
    print("Scan TCP NULL on: %s:%s" %(targets, ports))
    
    if ping(targets) != 0:
        return 'Not responding'
    
    source_port=RandShort()
    ans = sr1(IP(dst=targets)/TCP(sport=source_port, dport=ports, flags=0),timeout=5, verbose=False)

    if ans == None:
        return 'Port open OR filtered'
        
    elif ans[TCP].flags == 20:
        return 'Port closed [RST(4)+ACK(16)]'
    
    elif ans[ICMP].code in [1, 2, 3, 9, 10, 13]:
        return 'Filtered ICMP unreachable error '
    
    else:
        return 'Error'
    

def scan_tcp_fin(targets, ports):
    print("Scan TCP FIN on: %s:%s" %(targets, ports))

    if ping(targets) != 0:
        return 'Not responding'

    source_port=RandShort()
    ans = sr1(IP(dst=targets)/TCP(sport=source_port, dport=ports, flags=1),timeout=5, verbose=False)
    

    if ans == None:
        return 'Port open OR filtered'
        
    elif ans[TCP].flags == 20:
        return 'Port closed [RST(4)+ACK(16)]'
    
    elif ans[ICMP].code in [1, 2, 3, 9, 10, 13]:
        return 'Filtered ICMP unreachable error '
    
    else:
        return 'Error'


def scan_tcp_xmas(targets, ports):
    print("Scan TCP Xmas on: %s:%s" %(targets, ports))
    
    if ping(targets) != 0:
        return 'Not responding'
    
    source_port=RandShort()
    ans = sr1(IP(dst=targets)/TCP(sport=source_port, dport=ports, flags=41),timeout=5, verbose=False)
    
    if ans == None:
        return 'Port open OR filtered'
        
    elif ans[TCP].flags == 20:
        return 'Port closed [RST(4)+ACK(16)]'
    
    elif ans[ICMP].code in [1, 2, 3, 9, 10, 13]:
        return 'Filtered ICMP unreachable error '
    
    else:
        return 'Error'
        

def scan_tcp_ack(targets, ports):
    print("Scan TCP ACK on: %s:%s" %(targets, ports))
    
    if ping(targets) != 0:
        return 'Not responding'

    source_port=RandShort()
    ans = sr1(IP(dst=targets)/TCP(sport=source_port, dport=ports, flags=16),timeout=5, verbose=False)

    if ans == None:
        return 'Filtered'

    elif ans[TCP].flags == 4:
        return 'Not filtered open/closed'

    elif ans[ICMP].code in [1, 2, 3, 9, 10, 13]:
        return 'Filtered ICMP unreachable error' 

    else:
        return 'Error'


def scan_tcp_window(targets, ports):
    print("Scan TCP window on: %s:%s" %(targets, ports))
    
    if ping(targets) != 0:
        return 'Not responding'
    
    source_port=RandShort()
    ans = sr1(IP(dst=targets)/TCP(sport=source_port, dport=ports, flags=16),timeout=5, verbose=False)
    
    if ans == None:
        return 'Filtered'

    elif ans[TCP].flags == 4:

        if ans[TCP].window > 0:
            return 'Not filtered open'

        elif ans[TCP].window == 0:
            return 'Not filtered open/closed'

    elif ans[ICMP].code in [1, 2, 3, 9, 10, 13]:
        return 'Filtered ICMP unreachable error' 

    else:
        return 'Error'
    
   
def scan_tcp_maimon(targets, ports):
    print("Scan TCP Xmas on: %s:%s" %(targets, ports))
    
    if ping(targets) != 0:
        return 'Not responding'
    
    source_port=RandShort()
    ans = sr1(IP(dst=targets)/TCP(sport=source_port, dport=ports, flags=17),timeout=5, verbose=False)
    
    if ans == None:
        return 'Port open OR filtered'

    elif ans[TCP].flags == 4:
        return 'Port closed'

    elif ans[ICMP].code in [1, 2, 3, 9, 10, 13]:
        return 'Filtered ICMP unreachable error' 

    else:
        return 'Error'



if __name__ == "__main__":
    random.seed(time.time())
    targets='192.168.1.254'
    ports=80
    #print(scan_tcp_syn(targets, ports))
    #print(scan_udp(targets, ports))
    #print(scan_tcp_null(targets, ports))
    #print(scan_tcp_fin(targets, ports))
    #print(scan_tcp_xmas(targets, ports))
    #print(scan_tcp_ack(targets,ports))
    print(scan_tcp_window(targets, ports))

    



#https://nmap.org/man/pl/man-port-scanning-techniques.html

#Tcp Flags
#Urgent Pointer 32
#ACK            16
#Push            8
#Reset           4
#SYN             2
#FIN             1

#ICMPcode
#0 - echo reply
#3 - destination unreachable
#8 - echo request