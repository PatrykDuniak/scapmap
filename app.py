from HostDiscovery import HostDiscovery
from PortScanner import PortScanner


test = PortScanner('192.168.1.254', '1-2024', 'TCP') 
test.scanner()
