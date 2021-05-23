import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.sendrecv import sr1
from scapy.volatile import RandShort
from IPinterpreter import IPinterpreter

class HostDiscovery(IPinterpreter):
    def __init__(self):
        pass