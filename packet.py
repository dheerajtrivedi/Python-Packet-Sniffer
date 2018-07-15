from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from multiprocessing import Process
from networking.pcap import Pcap
from networking.http import HTTP

class Packet:
    def __init__(self, data):
        self.eth_src_mac = None
        self.eth_dest_mac = None
        self.eth_type = None
        self.ip_version = None
        self.dest_ip = None
        self.src_ip = None
        self.ip_header_length= None
        self.ttl = None
        self.ip_protocol = None
        self.tcp_dest_port = None
        self.tcp_src_port = None
        self.tcp_sequence = None
        self.tcp_ack = None
        self.tcp_flag_urg = None
        self.tcp_flag_ack = None
        self.tcp_flag_psh = None
        self.tcp_flag_rst = None
        self.tcp_flag_syn = None
        self.tcp_flag_fin = None
        self.info = '-'

        eth = Ethernet(data)
        self.dest = self.eth_dest_mac = eth.dest_mac
        self.src = self.eth_src_mac = eth.src_mac
        self.proto = 'Ethernet II'
        self.eth_type = eth.proto
        self.length = eth.length
        self.info = '-'
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            self.dest = ipv4.target
            self.src = ipv4.src
            self.proto = 'IPv4'

            self.eth_type = 'IPv4'
            self.ip_version = ipv4.version
            self.dest_ip = ipv4.target
            self.src_ip = ipv4.src
            self.ip_header_length= ipv4.header_length
            self.ttl = ipv4.ttl

            if ipv4.proto == 1:
                self.proto = 'ICMP'
                self.ip_protocol = 'ICMP'
                icmp = ICMP(ipv4.data)
            elif ipv4.proto == 6:
                self.proto = 'TCP'
                self.ip_protocol = 'TCP'
                tcp = TCP(ipv4.data)
                self.tcp_dest_port = tcp.src_port
                self.tcp_src_port = tcp.dest_port
                self.tcp_sequence = tcp.sequence
                self.tcp_ack = tcp.acknowledgment
                self.tcp_flag_urg = tcp.flag_urg
                self.tcp_flag_ack = tcp.flag_ack
                self.tcp_flag_psh = tcp.flag_psh
                self.tcp_flag_rst = tcp.flag_rst
                self.tcp_flag_syn = tcp.flag_syn
                self.tcp_flag_fin = tcp.flag_fin
            elif ipv4.proto == 14:
                self.proto = 'UDP'
                udp = UDP(ipv4.data)
    def getIt(self):
        return (self.dest,self.src,self.proto,self.length,self.info)
