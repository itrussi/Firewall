import scapy.all as scapy
from netfilterqueue import NetfilterQueue
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

    def url(self, target):
        try:
            url = socket.gethostbyaddr(target)
            safe = check(url[2])
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

        HOST = "0.0.0.0"
        PORT = 8080
        
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((HOST, PORT))

        instruction_1 = self.client.recv(1024).decode('utf-8')
        if instruction_1 == "UNAME":
            username = input("Username:: ")
            self.client.send(username.encode('utf-8'))

            instruction_2 = self.client.recv(1024).decode('utf-8')
            if instruction_2 == "PSWD":
                password = input("Password:: ")
                self.client.send(password.encode('utf-8'))

                response = self.client.recv(1024).decode('utf-8')
                if response == "Connected to Server!":
                    self.handler()
                else:
                    raise Exception("Server Refused Connection")

            elif instruction_2 == "REFUSE":
                raise Exception("Server Refused Connection")
                
            else:
                raise Exception("Server Connection Issue")

        else:
            raise Exception("Server Connection Issue")
        
        self.handler()

    def handler(self):

        while True:
            msg = command = input(">>> ")

            if command == "help":
                print("Available commands:\n Block Port <port>,\n Block IP <IP>,\n Block URL <URL>,\n Unblock Port <port>,\n Unblock IP <IP>,\n Unblock URL <URL>,\n Monitor Port <port>,\n Stop Monitoring Port <port>")

            if "Block Port" in command:
                port = command[11:]
                self.Firewall.ban_port(port, self.client)
                
            elif "Block IP" in command:
                ip = command[9:]
                self.Firewall.ban_ip(ip, self.client)
                
            elif "Block URL" in command:
                url = command[10:]
                self.Firewall.ban_url(url, self.client)
                
            elif "Unblock Port" in command:
                port = command[11:]
                self.Firewall.unban_port(port, self.client)
                
            elif "Unblock IP" in command:
                ip = command[9:]
                self.Firewall.unban_ip(ip, self.client)
                
            elif "Unblock URL" in command:
                url = command[10:]
                self.Firewall.ban_url(url, self.client)

            elif "Monitor Port" in command:
                port = command[13:]
                self.Firewall.monitor_port(port, self.client)
                
            elif "Stop Monitoring Port" in command:
                port = command[21:]
                self.Firewall.unmonitor_port(port, self.client)

            else:
                self.client.send(msg.encode('utf-8'))

class Firewall:

    def __init__(self, pkt):

        logging.basicConfig(
            filename='./Logs/main.log',
            level=logging.INFO,
            format=
            '%(asctime)s — %(name)s — %(levelname)s — %(funcName)s:%(lineno)d — %(message)s'
        )
        
        self.logger = logging.getLogger(__name__)

        self.nfqueue = NetfilterQueue()

        self.network_tools = network_tools()
        self.localports = self.network_tools.scanner("0.0.0.0")
        self.monitoring = threading.Thread(target=Packet_Sniffer(), args=(self.localports,))
        self.monitoring.start()

        self.banned_ports = []
        self.banned_prefixs = []
        self.banned_ips = []
        self.banned_urls = []

        for port in self.localports:
            if port.banned == True:
                self.banned_ports.apped(port)

        start_firewall = threading.Thread(target=self.firewall_start(), args=())
        start_firewall.start()

    def start_firewall(self):
        self.nfqueue.bind(1, self.firewall())
        
        try:
            self.nfqueue.run()
        except KeyboardInterrupt:
        	pass
        
        self.nfqueue.unbind()

    def restart_firewall(self):
        self.nfqueue.unbind()
        self.start_firewall()

    def firewall(self, pkt):

        sca = IP(pkt.get_payload())
        
        if(sca.haslayer(TCP)):
            t = sca.getlayer(TCP)
            if(t.dport in self.banned_ports):
                print(t.dport, "is a destination port that is blocked by the firewall.")
                pkt.drop()

        if(sca.haslayer(UDP)):
            t = sca.getlayer(UDP)
            if(t.dport in self.banned_ports):
                print(t.dport, "is a destination port that is blocked by the firewall.")
                pkt.drop()

        if(sca.src in self.banned_ips):
            print(sca.src, "is a incoming IP address that is banned by the firewall.")
            pkt.drop()

        try:
            url = self.network_tools.url(sca.dst)
            result = check(url)

            for url in self.banned_urls:
                if url == result:
                    print(sca.dst, "is an url that is banned by the firewall.")
                    pkt.drop()

        except:
            pass
        
        if(sca.dst in self.banned_ips):
            print(sca.dst, "is a outband IP address that is banned by the firewall.")
            pkt.drop()

        if(sca.src in self.banned_ips):
            print(sca.src, "is an imbound IP address that is banned by the firewall.")
            pkt.drop()

        if(True in [sca.src.find(suff)==0 for suff in self.banned_prefixs]):
            print("Prefix of " + sca.src + " is banned by the firewall.")
            pkt.drop()
    
    def ban_port(self, client, port):
        if port in self.banned_ports:
            return "Port already banned"

        elif port not in self.banned_ports:

            client.send(f"Ban Port {port}".encode('utf-8'))
            recv_data = client.recv(1024).decode('utf-8')

            if recv_data == True:
                self.banned_ports.append(port)
                self.restart_firewall()

                return "Successfull"

            else:
                return "Unsuccessfull"

    def ban_ip(self, client, ip):
        if ip in self.banned_ips:
            return "IP already banned"

        elif ip not in self.banned_ips:

            client.send(f"Ban IP {ip}".encode('utf-8'))
            recv_data = client.recv(1024).decode('utf-8')

            if recv_data == True:
                self.banned_ips.append(ip)
                self.restart_firewall()

                return "Successfull"

            else:
                return "Unsuccessfull"

    def ban_url(self, client, url):
        if url in self.banned_urls:
            return "URL already banned"

        elif url not in self.banned_urls:
            
            client.send(f"Ban URL {url}".encode('utf-8'))
            recv_data = client.recv(1024).decode('utf-8')

            if recv_data == True:
                self.banned_urls.append(url)
                self.restart_firewall()

                return "Successfull"
                
            else:
                return "Unsuccessfull"

    def unban_port(self, client, port):
        if port not in self.banned_ports:
            return "Port already unblocked"

        elif port in self.banned_ports:
            client.send(f"Unban Port {port}".encode('utf-8'))
            recv_data = client.recv(1024).decode('utf-8')

            if recv_data == True:
                self.banned_ports.remove(port)
                self.restart_firewall()

                return "Successfull"

            else:
                return "Unsuccessfull"
    
    def unban_ip(self, client, ip):
        if ip not in self.banned_ips:
            return "IP already unblocked"

        elif ip in self.banned_ips:

            client.send(f"Unban IP {ip}".encode('utf-8'))
            recv_data = client.recv(1024).decode('utf-8')

            if recv_data == True:
                self.banned_ips.remove(ip)
                self.restart_firewall()

                return "Successfull"

            else:
                return "Unsuccessfull"
    
    def unban_url(self, client, url):
        if url not in self.banned_urls:
            return "URL already unblocked"

        elif url in self.banned_urls:
            client.send(f"Unban Url: {url}".encode('utf-8'))
            recv_data = client.recv(1024).decode('utf-8')

            if recv_data == True:
                self.banned_urls.remove(url)
                self.restart_firewall()

                return "Successfull"

            else:
                return "Unsuccessfull"
                
if __name__ == "__main__":
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, Firewall)
    
    try:
        nfqueue.run()
    except KeyboardInterrupt:
    	pass
    
    nfqueue.unbind()