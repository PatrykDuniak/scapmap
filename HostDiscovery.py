import logging
import socket
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import  IP, UDP, ICMP, traceroute 
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether, arping
from scapy.sendrecv import sr1
from IPinterpreter import IPinterpreter

class HostDiscovery(IPinterpreter):

    def __init__(self, targets, icmp_type=8):
        super().__init__(targets)
        self.__icmp_type=icmp_type

    #https://en.wikipedia.org/wiki/List_of_DNS_record_types
    def get_domain_info(self):
        try:
            IPinterpreter.IPcalc(self)
            domain_name = socket.gethostbyaddr(self._targets)
            ans = sr1(IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain_name[0])),timeout=2, retry=2, verbose=False)
            ans[DNS].show()
        except:
            ans = sr1(IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=self._targets)), timeout=2, retry=2, verbose=False)
            if ans is None:
                print('Error')
            else:
                ans[DNS].show()

    #https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-0
    def icmp_ping(self):
        print("Ping on %s" %(self._targets))
        ans = sr1(IP(dst=self._targets)/ICMP(type=self.__icmp_type), timeout=2, retry=2, verbose=False)
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
            
    def traceroute(self):
        ans, unans = traceroute(target=self._targets, verbose=False)
        if ans is None:
            print('Unreachable or filtered, reply not arrived')
        else:
            ans.show()
        

    def arp_ping(self):
        ans, unans = arping(net=self._targets, verbose=False)
        if ans is None:
            print('Unreachable or filtered, reply not arrived')
        else:
            ans.show()
        

