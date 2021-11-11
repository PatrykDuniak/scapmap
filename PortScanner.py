import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.sendrecv import sr1
from scapy.volatile import RandShort
from IPinterpreter import IPinterpreter

class PortScanner(IPinterpreter):
    scan_dict = {
        'Null' :   { None : 'Port open OR filtered', 20 : 'Port closed [RST(4)+ACK(16)]'},
        
        'FIN' :    { None : 'Port open OR filtered', 20 : 'Port closed [RST(4)+ACK(16)]'},
        
        'Xmas' :   { None : 'Port open OR filtered', 20 : 'Port closed [RST(4)+ACK(16)]'},

        'SYN':     { None : 'Filtered', 18 : 'Port open, not filtered [SYN(2)+ACK(16)]', 
                     20 : 'Port closed, propably not filtered [RST(4)+ACK(16)]'},

        'ACK' :    { None : 'Filtered', 4 : 'Not filtered open/closed'},
        
        'Window' : { None : 'Filtered', 4 : ['Not filtered, open', 'Not filtered open/closed']},

        'Maimon' : { None : 'Port open OR filtered', 4 : 'Port closed'}}

    def __init__(self, targets, ports, type_scan, type_tcp = 'SYN', set_flags = 0, cert_result=True):
        super().__init__(targets)
        self.__ports = ports
        self.__type_scan = type_scan
        self.__set_flags = set_flags
        self.__type_tcp = type_tcp
        self.__cert_result = cert_result

    def __portInterpreter(self):
        try:
            if '-' in self.__ports:
                self.__ports=self.__ports.split('-')
                try:
                    self.__ports = list(map(int, self.__ports))
                except:
                    print('Propably not number')
                    exit()
                if (self.__ports[0] <= self.__ports[1] and ((self.__ports[0] in range(0, 65536)) and (self.__ports[1] in range(0, 65536)))):
                    self.__ports.append(True)
                else:
                    print('Wrong ports range')
                    exit()
            elif ',' in self.__ports:
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
        except:
            pass

    def __portFor(self):
        self.__portInterpreter()
        temp_list=self.__ports
        scan_type = { 'TCP' : self.__scan_tcp, 'UDP' : self.__scan_udp, 'IP' : self.__scan_ip_protocol, 'Custom' : self.__scan_tcp_custom}
        
        if type(self.__ports) == int:
            scan_type.get(self.__type_scan)()
        elif self.__ports[-1] == True:
            for port in range(temp_list[0], temp_list[1]+1):
                self.__ports=port
                scan_type.get(self.__type_scan)()
        elif self.__ports[-1] == False:
            for port in temp_list[:-1]:
                self.__ports=port
                scan_type.get(self.__type_scan)()
        else:
            print('Error')
            exit()

    def __tcp_calc_flag(self):
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

    def __scan_tcp(self):
        pick={'SYN' : 2,  'Null' : 0, 'FIN' : 1, 'Xmas' : 41,
              'ACK' : 16, 'Window' : 16,  'Maimon' : 17}
        #if self.__cert_result == False:
        print("Scan TCP %s on: %s:%s" %(self.__type_tcp, self._targets, self.__ports))

        source_port=RandShort()
        ans=sr1(IP(dst=self._targets)/TCP(sport=source_port, dport=self.__ports, flags=pick.get(self.__type_tcp)),timeout=1, retry=1, verbose=False)

        if ans is None:
            print(self.scan_dict.get(self.__type_tcp).get(None))
        
        elif self.__cert_result == True:
            try:
                if self.__type_tcp == 'SYN':
                    if ans[TCP].flags in [18, 20]:
                        
                        print(self.scan_dict.get(self.__type_tcp).get(ans[TCP].flags))
                elif self.__type_tcp != 'Window':
                    if ans[TCP].flags in [4,18,20]:
                        
                        print(self.scan_dict.get(self.__type_tcp).get(ans[TCP].flags))
                elif ans[TCP].window > 0:
                    
                    print(self.scan_dict.get(self.__type_tcp).get(ans[TCP].flags)[0])
            except Exception as Exct:
                print(Exct)
                print(str(ans[ICMP].type) +': '+ str(ans[ICMP].code))
        else:
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

    def __scan_udp(self):
        if self.__cert_result == False:
            print("Scan UDP on: %s:%s" %(self._targets, self.__ports))
        
        source_port=RandShort()
        ans = sr1(IP(dst=self._targets)/UDP(sport=source_port, dport=self.__ports),timeout=2, retry=2, verbose=False)
        
        if self.__cert_result == True:
            if ans.haslayer(UDP):
                print('Port open, not filtered [Got UDP packet]')
            elif ans[ICMP].code == 3:
                print('Port closed, not filtered')
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

    def __scan_ip_protocol(self): #https://www.eit.lth.se/ppplab/IPHeader.htm
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

    def __scan_tcp_custom(self):
        flag_value=self.__tcp_calc_flag()
        source_port=RandShort()
        ans=sr1(IP(dst=self._targets)/TCP(sport=source_port, dport=self.__ports, flags=flag_value),timeout=2, retry=2, verbose=False)

        try:
            ans.show()
        except (TypeError, AttributeError):
            print('Any packet received')

    def scanner(self):
        base=''
        self._targets=range_ip=self.IPcalc()
        if type(range_ip) == str:
            self.__portFor()
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
                            self.__portFor()
                    else:
                        for set in range(0, oct):
                                base+=range_ip[0][set]+'.'
                        for ip in range(int(range_ip[0][oct]), int(range_ip[1][oct])):
                            if base.count('.')==0:
                                for x in range(1, 255):
                                    for y in range(1, 255):
                                        for z in range(1, 255):
                                            self._targets=str(ip)+'.'+str(x)+'.'+str(y)+'.'+str(z)
                                            self.__portFor()
                            elif base.count('.')==1:
                                for x in range(1, 255):
                                    for y in range(1, 255):
                                        self._targets=base+str(ip)+'.'+str(x)+'.'+str(y)
                                        self.__portFor()
                            else:
                                for x in range(1, 255):
                                    self._targets=base+str(ip)+'.'+str(x)
                                    self.__portFor()

