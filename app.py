from HostDiscovery import HostDiscovery
from PortScanner import PortScanner


test = PortScanner('192.168.1.254', '80', 'TCP', type_tcp='SYN', specific_result=True) 
test.scanner()
