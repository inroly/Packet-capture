# coding=utf-8
import datetime
import threading
import tkinter
from tkinter import *
from tkinter import font, filedialog
from tkinter.constants import *
from tkinter.messagebox import askyesno
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview

#from scapy.layers.inet import *
#from scapy.layers.l2 import *
from scapy.all import *

# 用来终止抓包线程的线程事件
stop_sending = threading.Event()
# 用来给抓到扥数据包编号
packet_id = 1
# 用来存放抓到的数据包
packet_list =[]
# 暂停抓包的标志位
pause_flag = False
# 保存文件标志位
save_flag = False
# 停止抓包标志位
stop_flag=False

# 状态栏类
class StatusBar(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.label = Label(self, bd=1, relief=SUNKEN, anchor=W)
        self.label.pack(fill=X)
    def set(self, fmt, *args):
        self.label.config(text=fmt % args)
        self.label.update_idletasks()
    def clear(self):
        self.label.config(text="")
        self.label.update_idletasks()


# 时间戳转为格式化的时间字符串
def timestamp2time(timestamp):
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    return mytime
"""
数据包列表单击事件响应函数，在数据包列表单击某数据包时，在协议解析区解析此数据包，并在hexdump区显示此数据包的十六进制内容
:param event: TreeView单击事件
:return: None
"""
def on_click_packet_list_tree(event):
    # event.widget获取Treeview对象，调用selection获取选择对象名称,返回结果为字符型元祖
    selected_item = event.widget.selection()
    # 清空packet_dissect_tree上现有的内容------------------------
    packet_dissect_tree.delete(*packet_dissect_tree.get_children())
    # 设置协议解析区的宽度
    packet_dissect_tree.column('Dissect', width=packet_list_frame.winfo_width())
    # 转换为整型
    packet_id = int(selected_item[0])-1
    # 取出要分析的数据包
    packet = packet_list[packet_id]
    #packet.show()
    lines = (packet.show(dump=True)).split('\n')  # dump=True返回字符串，不打出，\n换行符
    last_tree_entry = None
    for line in lines:
        if line.startswith('#'):
            line = line.strip('# ')  # 删除#
            last_tree_entry = packet_dissect_tree.insert('', 'end', text=line)  # 第一个参数为空表示根节点
        else:
            packet_dissect_tree.insert(last_tree_entry, 'end', text=line)
        col_width = font.Font().measure(line)
        # 根据新插入数据项的长度动态调整协议解析区的宽度
        if packet_dissect_tree.column('Dissect', width=None) < col_width:
            packet_dissect_tree.column('Dissect', width=col_width)

    if IP in packet:
        ip = packet[IP]
        ip_chksum = ip.chksum
        # ip.show()#抓到的IP报文
        ip.chksum = None
        # ip.show()
        ip_check = IP(raw(ip)).chksum
        ip.chksum = ip_chksum
        print(ip_chksum, "计算出的IP首部校验和：", ip_check)
        if TCP in packet:
            tcp = packet[TCP]
            tcp_chksum = tcp.chksum
            tcp.chksum = None
            tcp_check = TCP(raw(tcp)).chksum
            tcp.chksum = tcp_chksum
            print(tcp_chksum, "计算出的TCP检验和：", tcp_check)
            information = "IP与TCP的校验和检查通过\r\nIP的校验和为：{chksum_ip}\r\nTCP的检验和为：" \
                          "{chksum_tcp}".format(chksum_ip=ip_chksum, chksum_tcp=tcp_chksum)
            print(information)
            if ip_check == ip_chksum and tcp_check == tcp_chksum:
                tkinter.messagebox.showinfo("校验和的检查", information)
            else:
                tkinter.messagebox.showerror("校验和错误警告", "IP或TCP的校验和出错")
        elif UDP in packet:
            udp = packet[UDP]
            udp_chksum = udp.chksum
            udp.chksum = None
            # 重新计算数据包的校验和
            udp_check = UDP(raw(udp)).chksum
            udp.chksum = udp_chksum
            print(udp_chksum, "计算出的UDP检验和：", udp_check)
            information = "IP与UDP的校验和检查通过\r\nIP的校验和为：" \
                          "{chksum_ip}\r\nUDP的检验和为：{chksum_udp}".format(chksum_ip=ip_chksum, chksum_udp=udp_chksum)
            print(information)
            # 弹出提示窗口
            if ip_check == ip_chksum and udp_check == udp_chksum:
                tkinter.messagebox.showinfo("校验和的检查", information)
            else:
                tkinter.messagebox.showerror("校验和错误警告", "IP或UDP的校验和出错")

    # 在hexdump区显示此数据包的十六进制内容，不用修改
    hexdump_scrolledtext['state'] = 'normal'
    hexdump_scrolledtext.delete(1.0, END)
    hexdump_scrolledtext.insert(END, hexdump(packet, dump=True))
    hexdump_scrolledtext['state'] = 'disabled'

# 抓抓取数据包并保存
def capture_packet():
    # 设置过滤条件
    filters = fitler_entry.get()
    print("抓包条件："+filters)
    # 设置停止抓包的条件stop_filter
    stop_sending.clear()
    global packet_list
    # 清空列表
    packet_list.clear()
    # 抓取数据包并将抓到的包存在列表中
    sniff(prn=(lambda x: process_packet(x)), filter=filters, stop_filter=(lambda x: stop_sending.is_set()))

# 处理抓到的数据包
def process_packet(packet):
    if pause_flag == False:
        global packet_list
        # 将抓到的包存在列表中
        packet_list.append(packet)
        # 抓包的时间
        packet_time= timestamp2time(packet.time)
        src = packet[Ether].src
        dst = packet[Ether].dst
        type = packet[Ether].type
        types = {0x0800:'IPv4',0x0806:'ARP',0x86dd:'IPv6',0x88cc:'LLDP',0x891D:'TTE'}
        if type in types:
           proto = types[type]
        else:
             proto = 'LOOP'  # 协议
        # IP
        if proto == 'IPv4':
            # 建立协议查询字典
            protos = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP', 89:'OSPF'}
            src = packet[IP].src
            dst = packet[IP].dst
            proto=packet[IP].proto
            if proto in protos:
                proto=protos[proto]
        # tcp
        if TCP in packet:
            protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if sport in protos_tcp:
                proto = protos_tcp[sport]
            elif dport in protos_tcp:
                proto = protos_tcp[dport]
        elif UDP in packet:
            if packet[UDP].sport == 53 or packet[UDP].dport == 53:
                proto = 'DNS'
        length = len(packet)  # 长度
        info = packet.summary()  # 信息
        global packet_id  # 数据包的编号
        packet_list_tree.insert("", 'end', packet_id, text=packet_id,
                            values=(packet_id, packet_time, src, dst, proto, length, info))
        packet_list_tree.update_idletasks()  # 更新列表，不需要修改
        packet_id = packet_id + 1


# 将抓到的数据包保存为pcap格式的文件
def save_captured_data_to_file():
    global save_flag
    save_flag = True
    # 默认打开位置initialdir='d:\\',默认命名initialfile='.pcap'
    filename=tkinter.filedialog.asksaveasfilename(title='保存文件', filetypes=[('所有文件', '.*'),
                                                                           ('数据包', '.pcap')], initialfile='.pcap')
    if filename.find('.pcap') == -1:
        # 默认文件格式为 pcap
        filename = filename+'.pcap'

    wrpcap(filename, packet_list)

# 开始按钮单击响应函数，如果是停止后再次开始捕获，要提示用户保存已经捕获的数据
def start_capture():
    """
    开新线程，进行抓包，sniff的prn 选项设置为包处理函数，仿照just_a_test()写，过滤器为filter选项
    :return:
    """
    # 暂停，停止，保存的标志位
    global pause_flag,stop_flag,save_flag
    # 已经停止，重新开始抓包但没进行保存操作
    if stop_flag is True and save_flag is False:
        resault = tkinter.messagebox.askyesnocancel("保存提醒", "是否保存抓到的数据包")
        if resault is False:
            print("直接开始不保存")
        elif resault is True:
            print("先保存数据包,在进行抓包")
            # 默认打开位置initialdir='d:\\',默认命名initialfile='.pcap'
            filename = tkinter.filedialog.asksaveasfilename(title='保存文件', filetypes=[('所有文件', '.*'),
                                                                                     ('数据包', '.pcap')], initialfile='.pcap')
            if filename.find('.pcap') == -1:
                # 默认文件格式为 pcap
                filename = filename + '.pcap'
            wrpcap(filename, packet_list)
        else:
            print("取消抓包操作")
            stop_flag = False
            return
    # 设置开始按钮为不可用，暂停按钮可操作
    start_button['state'] = DISABLED  # 不可操作
    save_button['state'] = DISABLED
    pause_button['state'] = NORMAL  # 可操作
    stop_button['state'] = NORMAL
    stop_flag = False
    if pause_flag is False:
        # 清空已经抓到的数据包列表--------------
        items = packet_list_tree.get_children()
        for item in items:
            packet_list_tree.delete(item)
        packet_list_tree.clipboard_clear()
        global packet_id
        packet_id = 1
        # 开启新线程进行抓包
        t = threading.Thread(target=capture_packet)
        t.setDaemon(True)
        t.start()
        save_flag = False
    else:
        pause_flag = False

# 暂停按钮单击响应函数
def pause_capture():
    """
    抓包处理函数停止运行，仍然在抓包
    :return:
    """
    # 设置开始按钮为可用，暂停按钮为不可用
    start_button['state'] = NORMAL  # 可操作
    pause_button['state'] = DISABLED  # 不可操作
    global pause_flag
    pause_flag = True

# 停止按钮单击响应函数
def stop_capture():
    """
    终止线程，停止抓包
    :return:
    """
    # 终止线程，停止抓包
    stop_sending.set()
    # 设置开始按钮为可用，暂停按钮为不可用,保存为可用
    start_button['state'] = NORMAL # 可操作
    pause_button['state'] = DISABLED  # 不可操作
    stop_button['state'] = DISABLED
    save_button['state'] = NORMAL
    global pause_flag, stop_flag
    pause_flag = False
    stop_flag = True
    # 不能用加号+，连接不同格式字符
    print("停止抓包,共抓到", packet_id, "个数据包")

# 退出按钮单击响应函数,退出程序前要提示用户保存已经捕获的数据
def quit_program():
    """
    保存数据的函数，wrpcap   : Write a list of packets to a pcap file
    :return:
    """
    #终止线程，停止抓包
    stop_sending.set()
    # 已经暂停，或停止，需要提示保存在退出
    if stop_flag is True or pause_flag is True:
        # 没进行保存操作
        if save_flag is False:

            resault = tkinter.messagebox.askyesnocancel("保存提醒", "是否保存抓到的数据包")
            if resault is False:
                print("直接退出不保存")
                tk.destroy()
            elif resault is True:
                print("先保存数据包，再退出")
                # 默认打开位置initialdir='d:\\',默认命名initialfile='.pcap'
                filename = tkinter.filedialog.asksaveasfilename(title='保存文件',
                                                                filetypes=[('所有文件', '.*'), ('数据包', '.pcap')],initialfile='.pcap')
                if filename.find('.pcap') == -1:
                    # 默认文件格式为 pcap
                    filename = filename + '.pcap'
                wrpcap(filename, packet_list)
                tk.destroy()
            else:
                print("取消退出")
        else:
            print("已经保存，直接退出")
            tk.destroy()
    else:
        print("直接关闭窗口")
        tk.destroy()
# ---------------------以下代码负责绘制GUI界面---------------------
tk = tkinter.Tk()
tk.title("协议分析器")
# tk.resizable(0, 0)
# 带水平分割条的主窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

# 顶部的按钮及过滤器区
toolbar = Frame(tk)
start_button = Button(toolbar, width=8, text="开始", command=start_capture)
pause_button = Button(toolbar, width=8, text="暂停", command=pause_capture)
stop_button = Button(toolbar, width=8, text="停止", command=stop_capture)
save_button = Button(toolbar, width=8, text="保存数据", command=save_captured_data_to_file)
quit_button = Button(toolbar, width=8, text="退出", command=quit_program)
start_button['state'] = 'normal'
pause_button['state'] = 'disabled'
stop_button['state'] = 'disabled'
save_button['state'] = 'disabled'
quit_button['state'] = 'normal'
#filter_label = Label(toolbar, width=10, text="BPF过滤器：")
fitler_entry = Entry(toolbar)
start_button.pack(side=LEFT, padx=5)
pause_button.pack(side=LEFT, after=start_button, padx=10, pady=10)
stop_button.pack(side=LEFT, after=pause_button, padx=10, pady=10)
save_button.pack(side=LEFT, after=stop_button, padx=10, pady=10)
quit_button.pack(side=LEFT, after=save_button, padx=10, pady=10)
#filter_label.pack(side=LEFT, after=quit_button, padx=0, pady=10)
#fitler_entry.pack(side=LEFT, after=filter_label, padx=20, pady=10, fill=X, expand=YES)
toolbar.pack(side=TOP, fill=X)

# 数据包列表区
packet_list_frame = Frame()
packet_list_sub_frame = Frame(packet_list_frame)
packet_list_tree = Treeview(packet_list_sub_frame, selectmode='browse')
packet_list_tree.bind('<<TreeviewSelect>>', on_click_packet_list_tree)
# 数据包列表垂直滚动条
packet_list_vscrollbar = Scrollbar(packet_list_sub_frame, orient="vertical", command=packet_list_tree.yview)
packet_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
packet_list_tree.configure(yscrollcommand=packet_list_vscrollbar.set)
packet_list_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
# 数据包列表水平滚动条
packet_list_hscrollbar = Scrollbar(packet_list_frame, orient="horizontal", command=packet_list_tree.xview)
packet_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
packet_list_tree.configure(xscrollcommand=packet_list_hscrollbar.set)
# 数据包列表区列标题
packet_list_tree["columns"] = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
packet_list_column_width = [100, 180, 160, 160, 100, 100, 800]
packet_list_tree['show'] = 'headings'
for column_name, column_width in zip(packet_list_tree["columns"], packet_list_column_width):
    packet_list_tree.column(column_name, width=column_width, anchor='w')
    packet_list_tree.heading(column_name, text=column_name)
packet_list_tree.pack(side=LEFT, fill=X, expand=YES)
packet_list_frame.pack(side=TOP, fill=X, padx=5, pady=5, expand=YES, anchor='n')
# 将数据包列表区加入到主窗体
main_panedwindow.add(packet_list_frame)

# 协议解析区
packet_dissect_frame = Frame()
packet_dissect_sub_frame = Frame(packet_dissect_frame)
packet_dissect_tree = Treeview(packet_dissect_sub_frame, selectmode='browse')
packet_dissect_tree["columns"] = ("Dissect",)
packet_dissect_tree.column('Dissect', anchor='w')
packet_dissect_tree.heading('#0', text='Packet Dissection', anchor='w')
packet_dissect_tree.pack(side=LEFT, fill=BOTH, expand=YES)
# 协议解析区垂直滚动条
packet_dissect_vscrollbar = Scrollbar(packet_dissect_sub_frame, orient="vertical", command=packet_dissect_tree.yview)
packet_dissect_vscrollbar.pack(side=RIGHT, fill=Y)
packet_dissect_tree.configure(yscrollcommand=packet_dissect_vscrollbar.set)
packet_dissect_sub_frame.pack(side=TOP, fill=X, expand=YES)
# 协议解析区水平滚动条
packet_dissect_hscrollbar = Scrollbar(packet_dissect_frame, orient="horizontal", command=packet_dissect_tree.xview)
packet_dissect_hscrollbar.pack(side=BOTTOM, fill=X)
packet_dissect_tree.configure(xscrollcommand=packet_dissect_hscrollbar.set)
packet_dissect_frame.pack(side=LEFT, fill=X, padx=5, pady=5, expand=YES)
# 将协议解析区加入到主窗体
main_panedwindow.add(packet_dissect_frame)

# hexdump区
hexdump_scrolledtext = ScrolledText(height=10)
hexdump_scrolledtext['state'] = 'disabled'
# 将hexdump区区加入到主窗体
main_panedwindow.add(hexdump_scrolledtext)

main_panedwindow.pack(fill=BOTH, expand=1)

# 状态栏
status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)
#just_a_test()  # 展示一个数据包，不是抓来的
tk.mainloop()
