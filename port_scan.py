import sys
import time   
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import IP, UDP, TCP, ICMP, report_ports, IPTools
from scapy.sendrecv import sniff, send, sendp, sr1, sr, srp
from scapy.layers.l2 import Ether, ARP
from scapy.compat import raw
from scapy.volatile import RandShort


class IPinterpreter():
    def __init__(self, targets):
        self._targets = targets
        self.__scope_value=''

    def IPcalc(self):
        self.__ipchecker()
        self.__scope_value = self._targets.split('.')[-1]
        if len(self.__scope_value)==1:
            return self._targets  
        elif '-' in self.__scope_value:
            self._targets = self._targets.split('.')
            self.__scope_value = self.__scope_value.split('-')
            return self.__scopeNetwork()
        elif '/' in self.__scope_value:
            self.__scope_value = self.__scope_value.split('/')
            try:
                self.__scope_value = list(map(int, self.__scope_value))
                self._targets = self._targets.split('.')
            except:
                print('Wrong Input')
                return 0
            return self.__subnetCalc()

    def __scopeNetwork(self):
        self._targets.append('.'.join(self._targets[0:3])+'.'+self.__scope_value[0])
        self._targets.append('.'.join(self._targets[0:3])+'.'+self.__scope_value[1])
        self._targets=self._targets[-2:]
        return self._targets
            
    def __subnetCalc(self):
        subnets=[]
        ip_range=['','']
        self._targets[3]=self._targets[3].split('/')[0]
        hosts=0

        for oct in range(1, 5):
            if(self.__scope_value[1] < 8*oct):
                hosts=2**(8-(self.__scope_value[1]-8*(oct-1)))
                subnets.append(0)
                for ip in range(256//hosts):
                    subnets.append((hosts*(ip+1)))
                for inx in range(len(subnets)):
                    if int(self._targets[oct-1]) in range(subnets[inx], subnets[inx+1]):
                        for step in range(0,4):
                            if (oct-1)==step:
                                ip_range[0]+=str(subnets[inx]+1)+'.'
                                ip_range[1]+=str(subnets[inx+1]-1)+'.'
                                break
                            else:
                                ip_range[0]+=self._targets[step]+'.'
                                ip_range[1]+=self._targets[step]+'.'
                        break
                
                for _ in range(4-ip_range[0].count('.')):
                    ip_range[0]+='1.'
                    if(ip_range[1].count('.')==3):
                        ip_range[1]+='254.'
                    else:
                        ip_range[1]+='255.'

                ip_range[0]=ip_range[0][:-1]
                ip_range[1]=ip_range[1][:-1]
                break

        self._targets=ip_range
        return self._targets
        
    def __ipchecker(self):
        test=self._targets
        if test.count('.')!=3:
            print('Not proper IP format')
            exit()
        test=test.split('.')
        for text in range(len(test)-1):
            try:
                text=int(text)
                if text not in range(0,256):
                    print('Number out of range')
                    exit()
            except:
                print('Not number')
                exit()
        try:
            test[3]=int(test[3])
        except:
            if ('-' not in test[3]) and ('/' not in test[3]):
                print('Only using - and / to setting range')
                exit()
            if ('-') in test[3]:
                test[3]=test[3].split('-')
                try:
                    test[3][0] = int(test[3][0])
                    test[3][1] = int(test[3][1])
                    if test[3][0] not in range(0, 255) or test[3][1] not in range(0, 255) or test[3][0] > test[3][1]:
                        print('Last oct number out of range or wrong range')
                        exit()
                except:
                    print('Propably not number')
                    exit()
            else:
                test[3]=test[3].split('/')
                try:
                    test[3][0] = int(test[3][0])
                    test[3][1] = int(test[3][1])
                    if test[3][0] not in range(0, 255) or test[3][1] not in range(1, 31):
                        print('Last oct number out of range or wrong subnet number')
                except:
                    print('Propably not number')
                    exit()





class PortScanner(IPinterpreter):
    scan_dict = {
        #(1,2,3,9,10,13) : 'Filtered, ICMP unreachable error'
        'Null' :   { None : 'Port open OR filtered', 20 : 'Port closed [RST(4)+ACK(16)]'},
        
        'FIN' :    { None : 'Port open OR filtered', 20 : 'Port closed [RST(4)+ACK(16)]'},
        
        'Xmas' :   { None : 'Port open OR filtered', 20 : 'Port closed [RST(4)+ACK(16)]'},

        'SYN':     { None : 'Filtered', 18 : 'Port open, not filtered [SYN(2)+ACK(16)]', 
                     20 : 'Port closed, propably not filtered [RST(4)+ACK(16)]'},

        'ACK' :    { None : 'Filtered', 4 : 'Not filtered open/closed'},
        
        'Window' : { None : 'Filtered', 4 : ['Not filtered, open', 'Not filtered open/closed']},

        'Maimon' : { None : 'Port open OR filtered', 4 : 'Port closed'}}

    def __init__(self, targets, ports, type_scan, type_tcp = 'SYN', set_flags = 0):
        super().__init__(targets)
        self.__ports = ports
        self.__type_scan = type_scan
        self.__set_flags = set_flags
        self.__type_tcp = type_tcp

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
        
        print("Scan TCP %s on: %s:%s" %(self.__type_tcp, self._targets, self.__ports))

        source_port=RandShort()
        ans=sr1(IP(dst=self._targets)/TCP(sport=source_port, dport=self.__ports, flags=pick.get(self.__type_tcp)),timeout=1, retry=1, verbose=False)
    
        try:
            if self.__type_scan != 'Window':
                print(self.scan_dict.get(self.__type_tcp).get(ans[TCP].flags))
            else:
                if ans[TCP].window > 0:
                    print(self.scan_dict.get(self.__type_tcp).get(ans[TCP].flags)[0])
                else:
                    print(self.scan_dict.get(self.__type_tcp).get(ans[TCP].flags)[1])
        except (TypeError, AttributeError):
            if ans == None:
                print(self.scan_dict.get(self.__type_tcp).get(None))
            else:
                print('Filtered, ICMP unreachable error')

    def scan_udp(self):
        print("Scan UDP on: %s:%s" %(self._targets, self.__ports))
        
        source_port=RandShort()
        ans = sr1(IP(dst=self._targets)/UDP(sport=source_port, dport=self.__ports),timeout=2, retry=2, verbose=False)
        
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
        print("Scan IP Protocol on: %s" %(self._targets))

        for x in range (0, 255):
            ans = 0
            ans = sr1(IP(dst=self._targets, proto=x),timeout=2, retry=2, verbose=False)
            
            print("For %d:  " %(x), end = '')

            if ans == None:
                print('Protocol open OR filtered')

            elif ans[ICMP].code == 2:
                print('Protocol closed, not filtered')

            elif ans[ICMP].code in [1,3,9,10,13]:
                print('Filtered, ICMP unreachable error')

            else:
                print('Protocol open')

    def scan_tcp_custom(self):
        flag_value=self.__tcp_calc_flag()
        source_port=RandShort()
        ans=sr1(IP(dst=self._targets)/TCP(sport=source_port, dport=self.__ports, flags=flag_value),timeout=2, retry=2, verbose=False)

        try:
            ans.show()
        except (TypeError, AttributeError):
            print('Any packet received')

    def scanner(self):
        base=''
        scan_type = { 'TCP' : self.scan_tcp, 'UDP' : self.scan_udp, 'IP' : self.scan_ip_protocol, 'Custom' : self.scan_tcp_custom}
        self._targets=range_ip=self.IPcalc()
        if type(range_ip) == str:
            scan_type.get(self.__type_scan)()
        else:
            range_ip[0] = range_ip[0].split('.')
            range_ip[1] = range_ip[1].split('.')
            for oct in range(4):
                if range_ip[0][oct] == range_ip[1][oct]:
                    continue
                else:
                    if oct == 3:
                        for ip in range(int(range_ip[0][oct]), int(range_ip[1][oct])+1):
                            self._targets=range_ip[0][0]+'.'+range_ip[0][1]+'.'+range_ip[0][2]+'.'+str(ip)
                            scan_type.get(self.__type_scan)()
                    else:
                        for set in range(0, oct):
                                base+=range_ip[0][set]+'.'
                        for ip in range(int(range_ip[0][oct]), int(range_ip[1][oct])):
                            if base.count('.')==0:
                                for x in range(1, 255):
                                    for y in range(1, 255):
                                        for z in range(1, 255):
                                            self._targets=str(ip)+'.'+str(x)+'.'+str(y)+'.'+str(z)
                                            scan_type.get(self.__type_scan)()
                            elif base.count('.')==1:
                                for x in range(1, 255):
                                    for y in range(1, 255):
                                        self._targets=base+str(ip)+'.'+str(x)+'.'+str(y)
                                        scan_type.get(self.__type_scan)
                            else:
                                for x in range(1, 255):
                                    self._targets=base+str(ip)+'.'+str(x)
                                    scan_type.get(self.__type_scan)()

   
if __name__ == "__main__":
    targets="192.168.1.1/32"
    ports=80
    type_scan="TCP"
    set_flags="A"

    port_scanner = PortScanner(targets, ports, type_scan)
    port_scanner.scanner()




    
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