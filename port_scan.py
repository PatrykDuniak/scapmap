import sys
import time   
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import IP, UDP, TCP, ICMP, report_ports, IPTools
from scapy.sendrecv import sniff, send, sendp, sr1, sr, srp
from scapy.layers.l2 import Ether, ARP
from scapy.compat import raw
from scapy.volatile import RandShort

class PortScanner():
    scan_output = {
        #(1,2,3,9,10,13) : 'Filtered, ICMP unreachable error'
        'Null' :   { None : 'Port open OR filtered', 20 : 'Port closed [RST(4)+ACK(16)]'},
        
        'FIN' :    { None : 'Port open OR filtered', 20 : 'Port closed [RST(4)+ACK(16)]'},
        
        'Xmas' :   { None : 'Port open OR filtered', 20 : 'Port closed [RST(4)+ACK(16)]'},

        'SYN':     { None : 'Filtered', 18 : 'Port open, not filtered [SYN(2)+ACK(16)]', 
                     20 : 'Port closed, propably not filtered [RST(4)+ACK(16)]'},

        'ACK' :    { None : 'Filtered', 4 : 'Not filtered open/closed'},
        
        'Window' : { None : 'Filtered', 4 : ['Not filtered open', 'Not filtered open/closed']},

        'Maimon' : { None : 'Port open OR filtered', 4 : 'Port closed'}}

    def __init__(self, targets, ports, type_scan, set_flags):
        self.__targets = targets
        self.__ports = ports
        self.__type_scan = type_scan
        self.__set_flags = set_flags

    def __tcp_calc_flag(self):
        flag_value=0
        flags= {1 : ['FIN', 'F'],
                2 : ['SYN', 'S'],
                4 : ['RST', 'R'],
                8 : ['PSH', 'P'],
                16: ['ACK', 'A'],
                32: ['URG', 'U']}

        for word in self.__set_flags.split(' '):
            for item in flags.items():
                if(word in item[1]):
                    flag_value+=item[0]

        return flag_value

    def scan_tcp(self):
        pick={'SYN' : 2,  'Null' : 0, 'FIN' : 1, 'Xmas' : 41,
              'ACK' : 16, 'Window' : 16,  'Maimon' : 17}
        
        print("Scan TCP %s on: %s:%s" %(self.__type_scan, self.__targets, self.__ports))
        source_port=RandShort()

        ans = sr1(IP(dst=self.__targets)/TCP(sport=source_port, dport=self.__ports, flags=pick.get(self.__type_scan)),timeout=2, retry=2, verbose=False)
        
        try:
            print(self.scan_output.get(self.__type_scan).get(ans[TCP].flags))
        except (TypeError, AttributeError):
            if ans == None:
                print(self.scan_output.get(self.__type_scan).get(None))
            else:
                print('Filtered, ICMP unreachable error')
                
    def scan_udp(self):
        print("Scan UDP on: %s:%s" %(self.__targets, self.__ports))
        
        source_port=RandShort()
        ans = sr1(IP(dst=self.__targets)/UDP(sport=source_port, dport=self.__ports),timeout=2, retry=2, verbose=False)
        
        if ans == None:
            print('Port open OR filtered')

        elif ans.haslayer(UDP):
            print('Port open, not filtered [Got UDP packet]')

        elif ans[ICMP].code == 3:
            print('Port closed, not filtered')

        elif ans[ICMP].code in [1,2,9,10,13]:
            print('Filtered, ICMP unreachable error')

        else:
            print('Filtered')

    def scan_ip_protocol(self): #https://www.eit.lth.se/ppplab/IPHeader.htm
        print("Scan IP Protocol on: %s" %(self.__targets))

        for x in range (0, 255):
            ans = 0
            ans = sr1(IP(dst=self.__targets, proto=x),timeout=2, retry=2, verbose=False)
            
            print("For %d:  " %(x), end = '')

            if ans == None:
                print('Protocol open OR filtered')

            elif ans[ICMP].code == 2:
                print('Protocol closed, not filtered')

            elif ans[ICMP].code in [1,3,9,10,13]:
                print('Filtered, ICMP unreachable error')

            else:
                print('Protocol open')


def ping(targets):
    print("ICMP ping on: %s" %(targets))
    ans = sr1(IP(dst=targets)/ICMP(), verbose=False)
    try:
        return ans[ICMP].code
    except:
        return -1 


if __name__ == "__main__":
    targets="192.168.1.254"
    ports=80
    type_scan="SYN"
    set_flags="A"
    port_scanner = PortScanner(targets, ports, type_scan, set_flags)
    print(port_scanner.scan_tcp())
    print(port_scanner.scan_udp())
    print(port_scanner.scan_ip_protocol())


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