import socket
import time
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from multiprocessing import Process
from networking.pcap import Pcap
from networking.http import HTTP

from tkinter import *
from tkinter import ttk


class gui(Frame):
    def __init__(self,root):
        self.treeview = ttk.Treeview(root, columns = (2,3,4,5,6,7))
        self.treeview.heading('#0', text = "SNO.")
        self.treeview.heading(2, text = "Time",anchor = W)
        self.treeview.heading(3, text = "DEST")
        self.treeview.heading(4, text = "SRC")
        self.treeview.heading(5, text = "PROTOCOL")
        self.treeview.heading(6, text = "LENGTH")
        self.treeview.heading(7, text = "INFO")
        self.treeview.pack()

    def sniff(self):
        pcap = Pcap('capture.pcap')
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        ts1 = time.time()
        t = 0
        Packets = []
        ts1 = time.time()
        psize = 0
        while(True):
            psize += 1
            raw_data, addr = conn.recvfrom(65535)
            ts2 = time.time()
            t = ts2-ts1
            pcap.write(raw_data)
            eth = Ethernet(raw_data)
            self.dest = eth.dest_mac
            self.src = eth.src_mac
            self.proto = eth.proto
            self.length = eth.length
            self.info = '-'
            if eth.proto == 8:
                ipv4 = IPv4(eth.data)
                self.dest = ipv4.target
                self.src = ipv4.src
                self.proto = 'IPv4'
                if ipv4.proto == 1:
                    self.proto = 'ICMP'
                elif ipv4.proto == 6:
                    self.proto = 'TCP'
                elif ipv4.proto == 14:
                    self.proto = 'UDP p'


            Packets.append((t,self.dest,self.src,self.proto,self.length,self.info))
            self.treeview.insert('','end', text = psize, values = Packets[-1])
            self.treeview.update()

root = Tk()
hey = gui(root)
hey.sniff()
root.mainloop()
