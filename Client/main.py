import scapy.all as scapy
import socket
import struct
import textwrap
from dataclasses import dataclass
import logging
import threading
from url_scan import check

@dataclass
class port_info:
    port_number: int = None
    reason: str = None
    monitor: bool = False
    block: bool = False

@dataclass
class ip_info:
    ip: str = None
    reason: str = None
    monitor: bool = False
    block: bool = False

@dataclass
class url_info:
    url: str = None
    reason: str = None
    monitor: bool = False
    block: bool = False

class network_tools:

    def __init__(self):
        pass

    def scanner(self, target):
        
        self.ports = []
        
        for port in range(1,65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
             
            # returns an error indicator
            result = s.connect_ex((target, port))
            if result == 0:
                port = port_info(port, None)
                self.ports.append(port)
            s.close()

        return self.ports

    def monitor(self, target):
        try:
            url = socket.gethostbyaddr(target)
            safe = check(url[1])
        except:
            pass

        if safe == False:
            print("Flag")

        else:
            print("Safe")

class Packet_Sniffer:

    def __init__(self, localports):

        self.localports = localports
        
        conn = socket.socket(socket.socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

        while True:
            raw_data, addr = conn.recvfrom(65536)
            des_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)

        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = self.ipv4_packet(data)
            print("IPV4 Packet:")
            print(f"Version: {version},\n Header Length: {header_length},\n Source: {src},\n Target: {target}")

            if proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = self.tcp(data)
                for port in self.localports:
                    if (port.port_number == src_port or dest_port) and (port.monitor == True):
                        print("Montior func")
                    else:
                        continue

            elif proto == 17:
                src_port, dest_port, size, data = self.udp_segment(data)
                for port in self.localports:
                    if (port.port_number == src_port or dest_port) and (port.monitor == True):
                        print("Montior func")
                    else:
                        continue

            else:
                pass

    def ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]

    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    def ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_length:]

    def ipv4(self, addr):
        return '.'.join(map(str, addr))

    def tcp(self, data):
        (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
        
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags >> 32) >> 5
        flag_ack = (offset_reserved_flags >> 16) >> 5
        flag_psh = (offset_reserved_flags >> 8) >> 5
        flag_rst = (offset_reserved_flags >> 4) >> 5
        flag_syn = (offset_reserved_flags >> 2) >> 5
        flag_fin = (offset_reserved_flags >> 1) >> 5

        return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

    def udp_segment(self, data):
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[8:]

    def format_multi_line(self, prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1

        return '\n'.join(prefix + line for line in textwrap.wrap(string, size))

class Client:

    def __init__(self):
        self.Firewall = Firewall()

        self.handler()

    def handler(self):
        while True:
            command = input(">>> ")

            if command == "help":
                print("Available commands:\n Block Port <port>,\n Block IP <IP>,\n Block URL <URL>,\n Unblock Port <port>,\n Unblock IP <IP>,\n Unblock URL <URL>,\n Monitor Port <port>,\n Stop Monitoring Port <port>")

            if "Block Port" in command:
                print("Block Port")
                
            elif "Block IP" in command:
                print("Block IP")
                
            elif "Block URL" in command:
                print("Block URL")
                
            elif "Unblock Port" in command:
                print("Unblock Port")
                
            elif "Unblock IP" in command:
                print("Unblock IP")
                
            elif "Unblock URL" in command:
                print("Unblock URL")

            elif "Monitor Port" in command:
                print("Unblock Port")
                
            elif "Stop Monitoring Port" in command:
                print("Stop Monitoring Port")

class Firewall:

    def __init__(self):

        logging.basicConfig(
            filename='./Logs/main.log',
            level=logging.INFO,
            format=
            '%(asctime)s — %(name)s — %(levelname)s — %(funcName)s:%(lineno)d — %(message)s'
        )
        
        self.logger = logging.getLogger(__name__)

        self.network_tools = network_tools()
        self.localports = self.network_tools.scanner("0.0.0.0")
        self.monitoring = threading.Thread(target=Packet_Sniffer(), args=(self.localports,))
        self.monitoring.start()

    def ban_port(self, port):
        pass

    def ban_ip(self, ip):
        pass

    def ban_url(self, url):
        pass

    def unban_port(self, port):
        pass
    
    def unban_ip(self, ip):
        pass
    
    def unban_url(self, url):
        pass
                
if __name__ == "__main__":
    Client()