import socket
import time
from networking.pcap import Pcap
from packet import Packet

from tkinter import *
from tkinter import ttk
import tkinter.messagebox

filter_query_list = ['protocol','ip','dest_ip','src_ip','eth_type','ip_version','ip_protocol','port','dest_port','src_port','dest_mac','src_mac']
class gui(Frame):
    def __init__(self,root):
        self.psize = 0
        self.is_filter = False
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

        #------------ FILTER --------------
        self.filter_frame = Frame(root)
        self.filter_entry = Entry(self.filter_frame)
        self.filter_button = Button(self.filter_frame, text = 'FILTER', command = self.filter)
        self.help_button = Button(self.filter_frame, text = 'Help', command = self.help)
        self.filter_entry.pack(side = LEFT, padx = 2)
        self.filter_button.pack(side = LEFT, padx = 2)
        self.help_button.pack(side = RIGHT, padx = 2)
        self.filter_frame.pack(side = 'top', fill = X)

        #------------ TREEVIEW ------------
        self.treeview = ttk.Treeview(root, height = 10, columns = (2,3,4,5,6,7))
        self.treeview.heading('#0', text = "SNO.")
        self.treeview.heading(2, text = "Time",anchor = W)
        self.treeview.heading(3, text = "DEST")
        self.treeview.heading(4, text = "SRC")
        self.treeview.heading(5, text = "PROTOCOL")
        self.treeview.heading(6, text = "LENGTH")
        self.treeview.heading(7, text = "INFO")

        self.ysb = ttk.Scrollbar(root, orient=VERTICAL, command=self.treeview.yview)
        self.xsb = ttk.Scrollbar(root, orient=HORIZONTAL, command=self.treeview.xview)
        self.ysb.pack(anchor=E, fill=Y, side=RIGHT)
        self.xsb.pack(anchor=S, fill=X, side=BOTTOM)
        self.treeview.pack(expand=True, fill=BOTH)


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
    def filter(self):
        fil_str = self.filter_entry.get().replace(" ","")
        tmp_filter_list = fil_str.split(',')
        self.filter_list = {}
        self.is_filter = True
        for fil in tmp_filter_list:
            fil_q = fil.split('=')
            if fil_q[0] not in filter_query_list:
                self.is_filter = False
                tkinter.messagebox.showinfo('Input Error', 'Sorry! ' + fil_q[0] +' is not valid input. Please try again.')
                print(fil_q[0] + 'is invalid query. Please read help.')
                break
            self.filter_list[fil_q[0]] = fil_q[1]
        print(self.filter_list)
    def help(self):
        help_window = Toplevel(root)
        help_window.title('Help')
        var = '********************************************\n\
        To write filter query, add comma seperated \n \
        request in this format: \n \
        filter_type=options \n\n \
        For example: protocol=TCP,desr_ip=10.0.0.5\n\n \
        filter_type can be: protocol, ip, dest_ip, src_ip, \n \
        ip_protocol, eth_type.'
        help_label = Label(help_window, text=var,justify = LEFT)
        help_label.pack()
    def sniff(self):
        pcap = Pcap('capture.pcap')
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        t = 0
        while(self.stop == 0):
            print(self.psize)
            raw_data, addr = conn.recvfrom(65535)
            ts2 = time.time()
            t = ts2-self.tstart
            pcap.write(raw_data)
            pack = Packet(raw_data)
            if(self.is_filter):
                to_print = True
                for fil in self.filter_list:
                    qu = self.filter_list[fil]
                    print('Checking '+ qu+' in ' + str(pack.ip_protocol))
                    if fil == 'protocol':
                        if qu != pack.eth_type and qu != pack.ip_protocol:
                            to_print = False
                            break
                    elif fil == 'ip':
                        if qu != pack.dest_ip and qu != pack.src_ip:
                            to_print = False
                            break
                    elif fil == 'dest_ip':
                        if qu != pack.dest_ip:
                            to_print = False
                            break
                    elif fil == 'src_ip':
                        if qu != pack.src_ip:
                            to_print = False
                            break
                    elif fil == 'ip_protocol':
                        if qu != pack.ip_protocol:
                            to_print = False
                            break
                    elif fil == 'eth_type':
                        if qu != pack.eth_type:
                            to_print = False
                            break

                if to_print == True:
                    self.psize += 1
                    add = (t,) + pack.getIt()
                    Packets.append(add)
                    self.treeview.insert('','end',self.psize, text = self.psize, values = add)
            else:
                self.psize += 1
                add = (t,) + pack.getIt()
                Packets.append(add)
                self.treeview.insert('','end',self.psize, text = self.psize, values = add)
            self.treeview.update()

Packets = []
root = Tk()
root.title('Packet Sniffer 0.2.4')
hey = gui(root)
root.mainloop()
