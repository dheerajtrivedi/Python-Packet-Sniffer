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
        self.psize = 0
        self.tstart = time.time()
        root.protocol("WM_DELETE_WINDOW", root.destroy)
        #------------ MENUBAR ----------
        self.menu = Menu(root)
        root.config(menu=self.menu)
        self.sub_menu = Menu(self.menu)
        self.menu.add_cascade(label = 'File', menu = self.sub_menu)
        self.sub_menu.add_command(label = 'Start', command = self.start)
        self.sub_menu.add_command(label = 'Stop', command = self.stop)
        self.sub_menu.add_command(label = 'Quit', command = root.destroy)

        #------------ TOOLBAR ----------
        self.toolbar = Frame(root)
        self.startbutton = Button(self.toolbar, command = self.start)
        self.stopbutton = Button(self.toolbar, command = self.stop)
        run_img = PhotoImage(file='img/run.png')
        self.startbutton.config(image=run_img,compound= LEFT)
        self.startbutton.image = run_img

        stop_img = PhotoImage(file='img/stop.png')
        self.stopbutton.config(image=stop_img,compound= LEFT)
        self.stopbutton.image = stop_img

        self.startbutton.pack(side = LEFT, padx = 2)
        self.stopbutton.pack(side = LEFT, padx = 2)
        self.toolbar.pack(side ='top', fill=X)

        #------------ TREEVIEW ------------
        self.treeview = ttk.Treeview(root, height = 10, columns = (2,3,4,5,6,7))
        self.treeview.heading('#0', text = "SNO.")
        self.treeview.heading(2, text = "Time",anchor = W)
        self.treeview.heading(3, text = "DEST")
        self.treeview.heading(4, text = "SRC")
        self.treeview.heading(5, text = "PROTOCOL")
        self.treeview.heading(6, text = "LENGTH")
        self.treeview.heading(7, text = "INFO")

        self.scrollbar = Scrollbar(root)
        self.scrollbar.pack( side = RIGHT, fill=Y )
        self.treeview.pack()
        #------------ STATUSBAR -------------
        self.statusbar = Label(root,text = "Welcome...", bd = 1, relief = SUNKEN,anchor = W)
        self.statusbar.pack(side = BOTTOM, fill = X)

    def start(self):
        self.stop = 0
        self.statusbar.config(text = 'Capturing Packets...')
        self.sniff()

    def stop(self):
        self.stop = 1
        self.statusbar.config(text = 'Stopped.'+ str(self.psize) +' packets captured.')

    def sniff(self):
        pcap = Pcap('capture.pcap')
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        t = 0
        Packets = []
        while(self.stop == 0):
            print(self.psize)
            self.psize += 1
            raw_data, addr = conn.recvfrom(65535)
            ts2 = time.time()
            t = ts2-self.tstart
            pcap.write(raw_data)
            eth = Ethernet(raw_data)
            self.dest = eth.dest_mac
            self.src = eth.src_mac
            self.proto = 'Ethernet II'
            self.length = eth.length
            self.info = '-'
            if eth.proto == 8:
                ipv4 = IPv4(eth.data)
                self.dest = ipv4.target
                self.src = ipv4.src
                self.proto = 'IPv4'
                if ipv4.proto == 1:
                    self.proto = 'ICMP'
                    icmp = ICMP(ipv4.data)
                elif ipv4.proto == 6:
                    self.proto = 'TCP'
                    tcp = TCP(ipv4.data)
                elif ipv4.proto == 14:
                    self.proto = 'UDP'
                    udp = UDP(ipv4.data)


            Packets.append((t,self.dest,self.src,self.proto,self.length,self.info))
            self.treeview.insert('','end',self.psize, text = self.psize, values = Packets[-1])
            self.treeview.update()
root = Tk()
root.title('Packet Sniffer 0.2.2')
hey = gui(root)
root.mainloop()
