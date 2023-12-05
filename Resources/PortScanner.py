import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.sendrecv import sr1
from scapy.volatile import RandShort
from .IPinterpreter import IPinterpreter
import socket
import re
from datetime import datetime

class PortScanner(IPinterpreter):
    #Dictionary with interpretation of specific TCP scans
    #For example:
    #Null : { None : 'Port open OR filtered', 20 : 'Port closed [RST(4)+ACK(16)]'}
    #Means:
    #For TCP scan NULL (flag = 0) if we can't get any answers (None) that means port is open or filtered (we cant say for sure)
    #                          or if we can get answer with the flag set to 20 (RST(4)+ACK(16) in tcp frame that means this port is closed
    scan_dict = {
        'Null' :   { None : 'Port open OR filtered', 20 : 'Port closed [RST(4)+ACK(16)]'},
        
        'FIN' :    { None : 'Port open OR filtered', 20 : 'Port closed [RST(4)+ACK(16)]'},
        
        'Xmas' :   { None : 'Port open OR filtered', 20 : 'Port closed [RST(4)+ACK(16)]'},

        'SYN':     { None : 'Filtered', 18 : 'Port open, not filtered [SYN(2)+ACK(16)]', 
                       20 : 'Port closed, propably not filtered [RST(4)+ACK(16)]'},

        'ACK' :    { None : 'Filtered', 4 : 'Not filtered open/closed'},       
        
        'Window' : { None : 'Filtered', 4 : { 0: 'Not filtered closed', 1:'Not filtered, open'}},

        'Maimon' : { None : 'Port open OR filtered', 4 : 'Port closed'}}

    def __init__(self, targets, ports, type_scan = 'TCP', type_tcp = 'SYN', set_flags = 0, 
                 specific_result=True, grab_banner = False, timeout=0.1, retry=0):
        #Inherit class of interpreting ip address given in string for example 192.168.0.32/28
        super().__init__(targets)
        self.__ports = ports
        self.__type_scan = type_scan
        self.__type_tcp = type_tcp
        self.__set_flags = set_flags
        self.__specific_result = specific_result  #displaying or not unclear answers like 'open or filtered'
        self.__grab_banner = grab_banner
        self.__timeout = timeout
        self.__retry = retry

    #Changing ports given in string to proper format for this program
    def portInterpreter(self):
        if type(self.__ports) == int:
            pass 
        elif '-' in self.__ports:     #interpreter for ports given in range (string) like 80-100
            self.__ports=self.__ports.split('-')
            try:
                self.__ports = list(map(int, self.__ports))
            except:
                print('Propably not number')
                exit()
            if (self.__ports[0] <= self.__ports[1] and ((self.__ports[0] in range(0, 65536)) and (self.__ports[1] in range(0, 65536)))):    #filter unreal ports  
                self.__ports.append(True)
            else:
                print('Wrong ports range')
                exit()
        elif ',' in self.__ports:    #interpreter for ports given 1 by 1 like 80,120,130 
            self.__ports=self.__ports.split(',')
            try:
                self.__ports = list(map(int, self.__ports))
            except:
                print('Propably not number')
                exit()
            for check in self.__ports:
                if check not in range(0, 65536):
                    print('Wrong ports range format')
                    exit()
            self.__ports.append(False)
        else:
            try:
                self.__ports=int(self.__ports)
            except:
                print('Wrong ports range format')
                exit()

    #Call different types of scans with loops for diffrent ports 
    def portFor(self):
        self.portInterpreter()
        temp_list=self.__ports
        scan_type = { 'TCP' : self.scan_tcp, 'UDP' : self.scan_udp, 'IProt' : self.scan_ip_protocol, 'Custom' : self.scan_tcp_custom}
        
        if type(self.__ports) == int:
            scan_type.get(self.__type_scan)()
            if self.__grab_banner == True:
                print(self.retBanner())

        elif self.__ports[-1] == True:
            for port in range(temp_list[0], temp_list[1]+1):
                self.__ports=port
                scan_type.get(self.__type_scan)()
                if self.__grab_banner == True:
                    print(self.retBanner())

        elif self.__ports[-1] == False:
            for port in temp_list[:-1]:
                self.__ports=port
                scan_type.get(self.__type_scan)()
                if self.__grab_banner == True:
                    print(self.retBanner())
        else:
            print('Error')
            exit()

    #Interpreting flags given in string like 'FIN' or 'F' to numbers 
    def tcp_calc_flag(self):
        flag_value=0
        flags= {1 : ['FIN', 'F'],
                2 : ['SYN', 'S'],
                4 : ['RST', 'R'],
                8 : ['PSH', 'P'],
                16: ['ACK', 'A'],
                32: ['URG', 'U']}

        try:
            for word in self.__set_flags.split(' '):
                for item in flags.items():
                    if(word in item[1]):
                        flag_value+=item[0]
        except:
            print('Wrong flags')

        return flag_value

    #Calling different types of TCP scans
    def scan_tcp(self):
        pick={'SYN' : 2,  'Null' : 0, 'FIN' : 1, 'Xmas' : 41,
              'ACK' : 16, 'Window' : 16,  'Maimon' : 17}

        if self.__specific_result == False:
            print("Scan TCP %s on: %s:%s" %(self.__type_tcp, self._targets, self.__ports))

        #calling Scapy function sr1(send and receive 1)
        ans=sr1(IP(dst=self._targets)/TCP(sport=RandShort(), dport=self.__ports, flags=pick.get(self.__type_tcp)), timeout=self.__timeout, retry=self.__retry, verbose=False)
        #analyze answers from Scapy function and printing results
        if self.__specific_result == True:
            try:
                if self.__type_tcp == 'SYN':
                    if ans[TCP].flags == 18:
                        print("Scan TCP %s on: %s:%s" %(self.__type_tcp, self._targets, self.__ports))
                        print(self.scan_dict.get(self.__type_tcp).get(ans[TCP].flags))

                elif self.__type_tcp != 'Window':
                    if ans[TCP].flags in [4,18,20]:
                        print("Scan TCP %s on: %s:%s" %(self.__type_tcp, self._targets, self.__ports))
                        print(self.scan_dict.get(self.__type_tcp).get(ans[TCP].flags))

                elif ans[TCP].window > 0:
                    print("Scan TCP %s on: %s:%s" %(self.__type_tcp, self._targets, self.__ports))
                    print(self.scan_dict[self.__type_tcp][ans[TCP].flags][1])

                elif ans[TCP].window == 0:
                    print("Scan TCP %s on: %s:%s" %(self.__type_tcp, self._targets, self.__ports))
                    print(self.scan_dict[self.__type_tcp][ans[TCP].flags][0])

                else:
                    print(ans.show())

            except:
                pass

        else:
            try:
                if self.__type_tcp != 'Window':
                    print(self.scan_dict.get(self.__type_tcp).get(ans[TCP].flags))
                else:
                    if ans[TCP].window == 0:
                        print(self.scan_dict[self.__type_tcp][ans[TCP].flags][0])
                    else:
                        print(self.scan_dict[self.__type_tcp][ans[TCP].flags][1])

            except (TypeError, AttributeError):
                if ans == None:
                    print(self.scan_dict.get(self.__type_tcp).get(None))

                else:
                    print('Filtered, ICMP unreachable error')

    #Calling UDP scan
    def scan_udp(self):
        if self.__specific_result == False:
            print("Scan UDP on: %s:%s" %(self._targets, self.__ports))
        
        #calling Scapy function sr1(send and receive 1)
        ans = sr1(IP(dst=self._targets)/UDP(sport=RandShort(), dport=self.__ports),timeout=self.__timeout, retry=self.__retry, verbose=False)
        
        #analyze answers from Scapy function and printing results
        if self.__specific_result == True:
            try:
                if ans.haslayer(UDP):
                    print("Scan UDP on: %s:%s" %(self._targets, self.__ports))
                    print('Port open, not filtered [Got UDP packet]')
                elif ans[ICMP].code == 3:
                    print("Scan UDP on: %s:%s" %(self._targets, self.__ports))
                    print('Port closed, not filtered')
            except:
                pass
        else:
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

    #Calling IP protocol (setting flags) scan
    def scan_ip_protocol(self): #https://www.eit.lth.se/ppplab/IPHeader.htm
        print("Scan IP Protocol on: %s" %(self._targets))

        #There are 134 diffrent protocols from 0 to 134 like OSPF(89) or VRRP(112)
        for x in range (0, 134):
            ans = 0 #clearing variable

            #calling Scapy function sr1(send and receive 1)
            ans = sr1(IP(dst=self._targets, proto=x),timeout=self.__timeout, retry=self.__retry, verbose=False)
            
            print("For %d:  " %(x), end = '')

            if ans == None:
                print('Protocol open OR filtered')

            elif ans[ICMP].code == 2:
                print('Protocol closed, not filtered')

            elif ans[ICMP].code in [1,3,9,10,13]:
                print('Filtered, ICMP unreachable error')

            else:
                print('Protocol open')

    #Calling tcp scan with open to set flags and displaying whole frame
    def scan_tcp_custom(self):
        flag_value=self.tcp_calc_flag()

        print("Scan TCP with custom flags:%s on: %s:%s" %(self.__set_flags, self._targets, self.__ports))

        #calling Scapy function sr1(send and receive 1)
        ans=sr1(IP(dst=self._targets)/TCP(sport=RandShort(), dport=self.__ports, flags=flag_value),timeout=self.__timeout, retry=self.__retry, verbose=False)

        try:
            #Hard to predict answer with random flag value so its better display whole frame
            ans.show()

        except (TypeError, AttributeError):
            print('Any packet received')

    #Get banner with socket
    def retBanner(self):
        socket.setdefaulttimeout(10)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data = {22:f'SSH-2.0-MySSHClient\r\n', 80:f'GET / HTTP/1.1\r\nHost: {self._targets}\r\n\r\n', 443:f'GET / HTTP/1.1\r\nHost: {self._targets}\r\n\r\n',
                21:f'SYST\r\n', 8080:f'GET / HTTP/1.1\r\nHost: {self._targets}\r\n\r\n'}
        try:
            sock.connect((self._targets, self.__ports))
            sock.send(data[self.__ports].encode())
            banner = sock.recv(2048)
            sock.close()
            if self.__ports == 80 or self.__ports == 443 or self.__ports == 8080:
                pattern = re.compile(r"^Server:.*", re.MULTILINE)
                banner = pattern.findall(banner.decode('utf-8'))
                return banner[0]
            return banner.decode('utf-8')
        except:
            return 'Cant grab banner'
        
    #main function to scan 
    def scanner(self):
        print('Scanning started...'+datetime.now().strftime("%H:%M:%S"))
        base='' #operation on octets in IP address to iterate range
        self._targets=range_ip=self.IPcalc() #change string range of IP address to first and last address
        temp_port = self.__ports

        try:
            if type(range_ip) == str:   #if IPcalc didn't change anything that means it is single address
                self.portFor()

            else:
                range_ip[0] = range_ip[0].split('.')    #spliting IP address to list with octets 
                range_ip[1] = range_ip[1].split('.')    
                
                for oct in range(4):
                    if range_ip[0][oct] == range_ip[1][oct]:    
                        continue 

                    else:
                        if oct == 3:   #last octet
                            for ip in range(int(range_ip[0][oct]), int(range_ip[1][oct])+1):  #calculate range and enumarate by every address
                                self._targets=range_ip[0][0]+'.'+range_ip[0][1]+'.'+range_ip[0][2]+'.'+str(ip)
                                self.__ports = temp_port
                                self.portFor()

                        #usually we are going to scan to max /24, with more address process is more complicated
                        else:
                            for set in range(0, oct):     
                                    base+=range_ip[0][set]+'.'

                            for ip in range(int(range_ip[0][oct]), int(range_ip[1][oct])):
                                if base.count('.')==0:
                                    for x in range(1, 255):
                                        for y in range(1, 255):
                                            for z in range(1, 255):
                                                self._targets=str(ip)+'.'+str(x)+'.'+str(y)+'.'+str(z)
                                                self.__ports = temp_port
                                                self.portFor()

                                elif base.count('.')==1:
                                    for x in range(1, 255):
                                        for y in range(1, 255):
                                            self._targets=base+str(ip)+'.'+str(x)+'.'+str(y)
                                            self.__ports = temp_port
                                            self.portFor()

                                else:
                                    for x in range(1, 255):
                                        self._targets=base+str(ip)+'.'+str(x)
                                        self.__ports = temp_port
                                        self.portFor()
            
        except:
            print("Error in iteration of hosts")
            pass                                    

        print('Scanning ended...'+datetime.now().strftime("%H:%M:%S"))
