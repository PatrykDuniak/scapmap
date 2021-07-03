import logging
import socket
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.sendrecv import sr1
from scapy.volatile import RandShort
from IPinterpreter import IPinterpreter

class HostDiscovery(IPinterpreter):
    def __init__(self, targets):
        super().__init__(targets)

    #https://en.wikipedia.org/wiki/List_of_DNS_record_types
    def get_domain_info(self):
        try:
            IPinterpreter.IPcalc(self)
            domain_name = socket.gethostbyaddr(self._targets)
            answer = sr1(IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain_name[0])),timeout=2, retry=2, verbose=False)
            answer[DNS].show()
        except:
            answer = sr1(IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=self._targets)), timeout=2, retry=2, verbose=False)
            if answer is None:
                print('Brak odpowiedzi')
            else:
                answer[DNS].show()
            
        
    
 

targets='212.77.98.9'
test = HostDiscovery(targets)
test.get_domain_info()



#answer = sr1(IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname='wp.pl')),timeout=2, retry=2, verbose=True)
#answer = sr1(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSRR(rrname=b'8.8.8.8', type=12)),timeout=2, retry=2, verbose=True)

#print(answer[DNS].summary())
#answer.show()

