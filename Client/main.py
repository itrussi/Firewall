import scapy.all as scapy
import socket
import sys
from dataclasses import dataclass

@dataclass
class port_info:
    port: int
    reason: str
    montor: bool = False
    block: bool = False

@dataclass
class ip_info:
    ip: str
    reason: str
    montor: bool = False
    block: bool = False

class port_scanner:

    def __init__(self, target):

        # target = socket.gethostbyname(sys.argv[1])
        
        for port in range(1,65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
             
            # returns an error indicator
            result = s.connect_ex((target,port))
            if result ==0:
                print("Port {} is open".format(port))
            s.close()