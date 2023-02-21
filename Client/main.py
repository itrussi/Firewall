import scapy.all as scapy
import socket
from dataclasses import dataclass

@dataclass
class port_info:
    port: int = None
    reason: str = None
    montor: bool = False
    block: bool = False

@dataclass
class ip_info:
    ip: str = None
    reason: str = None
    montor: bool = False
    block: bool = False

@dataclass
class url_info:
    url: str = None
    reason: str = None
    montor: bool = False
    block: bool = False

class scanner:

    def __init__(self):
        pass

    def ports(self, target):
        
        ports = []
        
        for port in range(1,65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
             
            # returns an error indicator
            result = s.connect_ex((target, port))
            if result == 0:
                port = port_info(port, None)
                ports.append(port)
            s.close()

        return ports

        
if __name__ == "__main__":
    test = scanner()
    result = test.ports("0.0.0.0")
    print(result)