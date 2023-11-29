import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import  IP, ICMP, traceroute 
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sr1, sr
from .IPinterpreter import IPinterpreter
from datetime import datetime

class HostDiscovery(IPinterpreter):
    def __init__(self, targets, discovery_type, icmp_type=8, timeout=0.1, retry=0):
        super().__init__(targets)
        self.discovery_type=discovery_type
        self.icmp_type=icmp_type
        self.timeout=timeout
        self.retry=retry

    #ICMP ping
    #https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-0
    def icmp_ping(self):
        print("Ping on %s" %(self._targets))
        if self.timeout < 0.8:
            self.timeout = 0.8
        ans = sr1(IP(dst=self._targets)/ICMP(type=self.icmp_type), timeout=self.timeout, retry=self.retry, verbose=False)
        if ans is None:
            print('Unreachable or filtered, reply not arrived')

        elif ans[ICMP].type == 0:
            print('Echo Reply - Host is up')

        elif ans[ICMP].type == 14:
            print('Timestamp Reply - Host is up')
            print('Timestamp origin:   '+str((ans[ICMP].ts_ori // (1000*60*60))%24) + ':' + 
                                        str((ans[ICMP].ts_ori // (1000*60))%60)+':'+
                                        str((ans[ICMP].ts_ori // 1000)%60)+'.'+
                                        str((ans[ICMP].ts_ori)%1000))

            print('Timestamp returned: '+str((ans[ICMP].ts_tx // (1000*60*60))%24) + ':' 
                                        +str((ans[ICMP].ts_tx // (1000*60))%60)+':'
                                        +str((ans[ICMP].ts_tx // 1000)%60)+'.'
                                        +str((ans[ICMP].ts_tx)%1000))

        else:
            print('Host is up')
            ans.show()

    #Traceroute    
    def traceroute(self):
        ans, unans = traceroute(target=self._targets, verbose=False, timeout=self.timeout)
        if ans is None:
            print('Unreachable or filtered, reply not arrived')
        else:
            ans.show()

    #Arp ping
    def arp_ping(self):
        ans, unans = sr(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self._targets), verbose=False, timeout=self.timeout)
        if ans is None:
            print('Unreachable or filtered, reply not arrived')
        else:
            for sent, received in ans:
                print('IP:{}   MAC:{}'.fomat(received.psrc,received.hwsrc))

    #Dict to enumarate
    def host_for(self):
        discovery_type = { 'ARPing' : self.arp_ping, 'Trace' : self.traceroute, 'ICMPing' : self.icmp_ping}
        discovery_type.get(self.discovery_type)()

    #Discovery scanner interpreter
    def discovery_scanner(self):
        print('Scanning started...'+datetime.now().strftime("%H:%M:%S"))
        base='' #operation on octets in IP address to iterate range
        self._targets=range_ip=self.IPcalc() #change string range of IP address to first and last address

        if type(range_ip) == str:   #if IPcalc didn't change anything that means it is single address
            self.host_for()

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
                            self.host_for()

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
                                            self.host_for()

                            elif base.count('.')==1:
                                for x in range(1, 255):
                                    for y in range(1, 255):
                                        self._targets=base+str(ip)+'.'+str(x)+'.'+str(y)
                                        self.host_for()

                            else:
                                for x in range(1, 255):
                                    self._targets=base+str(ip)+'.'+str(x)
                                    self.host_for()

        print('Scanning ended...'+datetime.now().strftime("%H:%M:%S"))