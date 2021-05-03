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

def tcp_calc_flag(set_flags):
    flag_value=0
    flags= { 1 : ['FIN', 'F'],
             2 : ['SYN', 'S'],
             4 : ['RST', 'R'],
             8 : ['PSH', 'P'],
             16: ['ACK', 'A'],
             32: ['URG', 'U']}

    for word in set_flags.split(' '):
        for item in flags.items():
            if(word in item[1]):
                flag_value+=item[0]

    return flag_value

def scan_tcp_syn(ans, targets, ports):
    
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
        
def scan_tcp_null_fin_xmas(ans, targets, ports):

    if ans == None:
        return 'Port open OR filtered'
        
    elif ans[TCP].flags == 20:
        return 'Port closed [RST(4)+ACK(16)]'
    
    elif ans[ICMP].code in [1, 2, 3, 9, 10, 13]:
        return 'Filtered ICMP unreachable error '
    
    else:
        return 'Error'
    
def scan_tcp_ack(ans, targets, ports):

    if ans == None:
        return 'Filtered'

    elif ans[TCP].flags == 4:
        return 'Not filtered open/closed'

    elif ans[ICMP].code in [1, 2, 3, 9, 10, 13]:
        return 'Filtered ICMP unreachable error' 

    else:
        return 'Error'

def scan_tcp_window(ans, targets, ports):

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
    
def scan_tcp_maimon(ans, targets, ports):

    if ans == None:
        return 'Port open OR filtered'

    elif ans[TCP].flags == 4:
        return 'Port closed'

    elif ans[ICMP].code in [1, 2, 3, 9, 10, 13]:
        return 'Filtered ICMP unreachable error' 

    else:
        return 'Error'


def scan_tcp(targets, ports, type_scan, set_flags):
    
    pick={'SYN'    : [scan_tcp_syn,            2],
          'Null'   : [scan_tcp_null_fin_xmas,  0],
          'FIN'    : [scan_tcp_null_fin_xmas,  1],
          'Xmas'   : [scan_tcp_null_fin_xmas, 41],
          'ACK'    : [scan_tcp_ack,           16],
          'Window' : [scan_tcp_window,        16],
          'Maimon' : [scan_tcp_maimon,        17]}
    
    
    print("Scan TCP %s on: %s:%s" %(type_scan, targets, ports))

    #if ping(targets) != 0:
        #return 'Not responding'

    source_port=RandShort()
    ans = sr1(IP(dst=targets)/TCP(sport=source_port, dport=ports, flags=pick.get(type_scan)[1]),timeout=1, verbose=False)
    return pick[type_scan][0](ans, targets, ports)
    

def scan_udp(targets, ports):
    print("Scan UDP on: %s:%s" %(targets, ports))
    
    #if ping(targets) != 0:
        #return 'Not responding'
    
    source_port=RandShort()
    ans = sr1(IP(dst=targets)/UDP(sport=source_port, dport=ports),timeout=1, verbose=False)
    
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



if __name__ == "__main__":
    random.seed(time.time())
    targets='192.168.1.254'
    ports=80
    type_scan='FIN'
    set_flags='A'

    print(scan_tcp(targets, ports, type_scan, set_flags))


#https://nmap.org/man/pl/man-port-scanning-techniques.html

#Tcp Flags
#URG(Urgent)            32
#ACK(Acknowledgement)   16
#PSH(Push)               8
#RST(Reset)              4
#SYN(Synchronization)    2
#FIN(Finish)             1

#ICMPcode
#0 - echo reply
#3 - destination unreachable
#8 - echo request