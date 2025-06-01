from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QLabel, QWidget,
    QHBoxLayout, QListWidget, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtCore import Qt, pyqtSlot, pyqtSignal, QThread
from collections import defaultdict
import time
import sys
import os
import pydivert
import logging
import locale
import socket
import threading
from urllib.parse import urlparse

# ---------------------------------------------------
#  Lokale set etme ve socket timeout
locale.setlocale(locale.LC_ALL, "en_US.UTF-8")
socket.setdefaulttimeout(2)
# ---------------------------------------------------

logging.basicConfig(
    filename="firewall_logs.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_to_file(message, level="info"):
    if level == "info":
        logging.info(message)
    elif level == "warning":
        logging.warning(message)
    elif level == "error":
        logging.error(message)


class Firewall(QThread):
    log_signal = pyqtSignal(str, str, str)
    rules_signal = pyqtSignal(str)

    PROTOCOL_MAP = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        8: "EGP",
        9: "IGP",
        17: "UDP",
        41: "IPv6",
        50: "ESP (Encapsulation Security Payload)",
        51: "AH (Authentication Header)",
        58: "ICMPv6",
        89: "OSPF (Open Shortest Path First)",
        112: "VRRP (Virtual Router Redundancy Protocol)",
        132: "SCTP (Stream Control Transmission Protocol)",
        137: "MPLS-in-IP",
        143: "EtherIP",
        255: "Experimental (Reserved)"
    }

    def __init__(self, rules, website_filter):
        super().__init__()
        self.rules = rules
        self.website_filter = website_filter
        self.running = True
        self.traffic_tracker = defaultdict(list)
        self.whitelist = ["127.0.0.1", "::1"]
        self.blacklist = set()

    def resolve_url_to_ip(self, url):
        try:
            socket.setdefaulttimeout(2)
            return socket.gethostbyname(url)
        except (socket.gaierror, socket.timeout):
            return None

    def get_protocol_name(self, protocol):
        if isinstance(protocol, tuple):
            protocol = protocol[0]
        return self.PROTOCOL_MAP.get(protocol, f"Unknown ({protocol})")

    def run(self):
        try:
            # “tcp or udp” filtresi, tüm TCP/UDP paketlerini yakalar
            with pydivert.WinDivert("tcp or udp") as w:
                for packet in w:
                    if not self.running:
                        break

                    src_ip = packet.src_addr
                    dst_ip = packet.dst_addr
                    protocol = self.get_protocol_name(packet.protocol)
                    curren_time = time.time()

                    # 1) Paketi önce GUI’ye ve log dosyasına bildir
                    self.log_signal.emit(src_ip, dst_ip, protocol)
                    log_to_file(f"Packet Seen: {src_ip}:{packet.src_port} -> {dst_ip}:{packet.dst_port}")

                    # 2) Whitelist kontrolü
                    if src_ip in self.whitelist:
                        w.send(packet)
                        continue

                    # 3) Blacklist kontrolü
                    if src_ip in self.blacklist:
                        self.rules_signal.emit(f"IP in Black List! Dropping {src_ip}")
                        continue

                    # 4) Website filter kontrolü
                    if dst_ip in self.website_filter:
                        self.rules_signal.emit(f"Blocked by Website Filter: {dst_ip}")
                        log_to_file(f"Blocked Website Packet: {dst_ip}", level="warning")
                        continue

                    # 5) DDoS koruması
                    self.traffic_tracker[src_ip].append(curren_time)
                    short_window = [ts for ts in self.traffic_tracker[src_ip] if curren_time - ts <= 1]
                    long_window  = [ts for ts in self.traffic_tracker[src_ip] if curren_time - ts <= 10]
                    if len(short_window) > 10000 or len(long_window) > 50000:
                        self.rules_signal.emit(
                            f"DDoS detected! Blacklisting {src_ip} (1s={len(short_window)},10s={len(long_window)})"
                        )
                        self.blacklist.add(src_ip)
                        log_to_file(f"DDoS Detected and Blocked: {src_ip}", level="warning")
                        threading.Thread(target=self.remove_from_blacklist, args=(src_ip,)).start()
                        continue

                    # 6) “Rules” listesine göre paket kontrolü
                    blocked = False
                    for rule in self.rules:
                        rule_lower = rule.lower()

                        # Protokol bazlı (“tcp” veya “udp”)
                        if rule_lower == "tcp" and protocol.lower() == "tcp":
                            self.rules_signal.emit("TCP Packet Blocked by Rule!")
                            log_to_file(
                                f"Blocked TCP by Rule: {src_ip}:{packet.src_port} -> {dst_ip}:{packet.dst_port}",
                                level="warning"
                            )
                            blocked = True
                            break

                        if rule_lower == "udp" and protocol.lower() == "udp":
                            self.rules_signal.emit("UDP Packet Blocked by Rule!")
                            log_to_file(
                                f"Blocked UDP by Rule: {src_ip}:{packet.src_port} -> {dst_ip}:{packet.dst_port}",
                                level="warning"
                            )
                            blocked = True
                            break

                        # Port bazlı kural (örneğin “:80”)
                        if rule.startswith(":"):
                            try:
                                port_num = int(rule.replace(":", ""))
                                if packet.src_port == port_num or packet.dst_port == port_num:
                                    self.rules_signal.emit(f"Packet Blocked by Port Rule {rule}")
                                    log_to_file(
                                        f"Blocked by Port Rule {rule}: {src_ip}:{packet.src_port} -> {dst_ip}:{packet.dst_port}",
                                        level="warning"
                                    )
                                    blocked = True
                                    break
                            except ValueError:
                                pass

                        # IP:Port bazlı kural (“192.168.1.1:80” gibi)
                        if ":" in rule and rule == f"{packet.src_addr}:{packet.src_port}":
                            self.rules_signal.emit(f"Packet Blocked by IP:Port Rule {rule}")
                            log_to_file(f"Blocked by IP:Port {rule}", level="warning")
                            blocked = True
                            break
                        if ":" in rule and rule == f"{packet.dst_addr}:{packet.dst_port}":
                            self.rules_signal.emit(f"Packet Blocked by IP:Port Rule {rule}")
                            log_to_file(f"Blocked by IP:Port {rule}", level="warning")
                            blocked = True
                            break

                    if blocked:
                        continue

                    # 7) Hiçbir engelleme yoksa paketi ilet
                    w.send(packet)

        except Exception as e:
            error_message = f"Firewall Error: {str(e)}"
            self.rules_signal.emit(error_message)
            log_to_file(error_message, level="error")

    def remove_from_blacklist(self, ip, timeout=60):
        time.sleep(timeout)
        if ip in self.blacklist:
            self.blacklist.remove(ip)
            self.rules_signal.emit(f"Removed from Black List: {ip}")
            log_to_file(f"Removed from Black List: {ip}", level="info")

    def stop(self):
        self.running = False


class FirewallGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        # ---------------------------------------------------
        # Burada QMainWindow için de ikonu mutlak yolla veriyoruz
        # ---------------------------------------------------
        self.setWindowTitle("Firewall")
        self.setWindowIcon(QIcon(r"C:\Users\User\Desktop\resim\1.ico"))

        screen = QApplication.primaryScreen()
        screen_size = screen.size()
        self.resize(screen_size.width() // 2, screen_size.height() // 2)

        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        layout = QVBoxLayout()

        # Start / Stop Butonları
        self.start_button = QPushButton("Start Firewall")
        self.start_button.clicked.connect(self.start_firewall)
        self.stop_button = QPushButton("Stop Firewall")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_firewall)

        # Kural Listesi (Rules)
        rule_layout = QHBoxLayout()
        self.rule_label = QLabel("Rules:")
        self.rule_list = QListWidget()
        self.rule_input = QLineEdit()
        self.rule_input.setPlaceholderText("Enter Port or IP Rule: (e.g. 192.168.1.1:80 or tcp or 80)...")
        self.add_rule_button = QPushButton("Add Rule")
        self.add_rule_button.clicked.connect(self.add_rule)
        rule_layout.addWidget(self.rule_input)
        rule_layout.addWidget(self.add_rule_button)
        self.delete_rule_button = QPushButton("Delete Selected Rule")
        self.delete_rule_button.clicked.connect(self.delete_rule)

        # Ağ Trafiği Tablosu (Network Traffic)
        self.network_label = QLabel("Network Traffic:")
        self.log_area = QTableWidget()
        self.log_area.setColumnCount(3)
        self.log_area.setHorizontalHeaderLabels(["Source", "Destination", "Protocol"])
        self.log_area.setEditTriggers(QTableWidget.NoEditTriggers)
        header = self.log_area.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)

        # Uygulanan Kurallar (Applied Rules)
        self.rules_label = QLabel("Applied Rules:")
        self.rules_area = QTextEdit()
        self.rules_area.setReadOnly(True)

        # Engellenen Siteler (Blocked Websites)
        self.web_label = QLabel("Blocked Websites:")
        self.web_list = QListWidget()

        website_layout = QHBoxLayout()
        self.website_input = QLineEdit()
        self.website_input.setPlaceholderText("Enter Website URL to Block: (e.g. www.example.com)...")
        self.add_website_button = QPushButton("Add Website")
        self.add_website_button.clicked.connect(self.add_website)
        website_layout.addWidget(self.website_input)
        website_layout.addWidget(self.add_website_button)

        # Layout Elemanlarını Ekle
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.rule_label)
        layout.addWidget(self.rule_list)
        layout.addLayout(rule_layout)
        layout.addWidget(self.delete_rule_button)
        layout.addWidget(self.network_label)
        layout.addWidget(self.log_area)
        layout.addWidget(self.rules_label)
        layout.addWidget(self.rules_area)
        layout.addWidget(self.web_label)
        layout.addWidget(self.web_list)
        layout.addLayout(website_layout)
        self.main_widget.setLayout(layout)

        # Başlangıç Durumları
        self.firewall_worker = None
        self.rules = []
        self.website_filter = set()

    @pyqtSlot(str, str, str)
    def add_to_traffic_table(self, src, dst, protocol):
        row_position = self.log_area.rowCount()
        self.log_area.insertRow(row_position)
        self.log_area.setItem(row_position, 0, QTableWidgetItem(src))
        self.log_area.setItem(row_position, 1, QTableWidgetItem(dst))
        self.log_area.setItem(row_position, 2, QTableWidgetItem(protocol))

    def add_rule(self):
        raw_rule = self.rule_input.text().strip()
        if not raw_rule:
            QMessageBox.warning(self, "Warning", "Enter a valid rule!")
            return

        if raw_rule.isdigit():
            rule = f":{raw_rule}"
        else:
            rule = raw_rule.lower()

        if rule not in self.rules:
            self.rules.append(rule)
            self.rule_list.addItem(rule)
            self.rules_area.append(f"Rule Added: {rule}")
            self.rule_input.clear()
        else:
            QMessageBox.warning(self, "Warning", "Rule already exists!")

    def delete_rule(self):
        selected_item = self.rule_list.currentItem()
        if selected_item:
            rule = selected_item.text()
            if rule in self.rules:
                self.rules.remove(rule)
            self.rule_list.takeItem(self.rule_list.row(selected_item))
            self.rules_area.append(f"Rule Deleted: {rule}")
        else:
            QMessageBox.warning(self, "Warning", "Select a Rule to Delete!")

    def start_firewall(self):
        if not self.firewall_worker:
            self.firewall_worker = Firewall(self.rules, self.website_filter)
            self.firewall_worker.log_signal.connect(self.add_to_traffic_table)
            self.firewall_worker.rules_signal.connect(self.rules_area.append)
            self.firewall_worker.start()
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)

    def add_website(self):
        raw_input = self.website_input.text().strip()
        if not raw_input:
            QMessageBox.warning(self, "Warning", "Enter a Valid URL!")
            return

        try:
            parsed = urlparse(raw_input if "://" in raw_input else "http://" + raw_input)
            domain = parsed.netloc
            if not domain:
                raise ValueError("No domain found")
        except Exception:
            QMessageBox.critical(self, "Error", "Invalid URL format!")
            return

        ip = None
        if self.firewall_worker:
            ip = self.firewall_worker.resolve_url_to_ip(domain)
        else:
            try:
                socket.setdefaulttimeout(2)
                ip = socket.gethostbyname(domain)
            except:
                ip = None

        if ip:
            self.website_filter.add(ip)
            self.web_list.addItem(f"{domain} ({ip})")
            self.website_input.clear()
            self.rules_area.append(f"Added to Website Filter: {domain} ({ip})")
        else:
            QMessageBox.critical(self, "Error", "Unable to resolve domain to IP!")

    def stop_firewall(self):
        if self.firewall_worker:
            self.firewall_worker.stop()
            self.firewall_worker.wait()
            self.firewall_worker = None
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.rules_area.append("Firewall Stopped!")


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # ---------------------------------------------------
    # ICO dosyanızın tam yolunu buraya yazın:
    icon_path = r"C:\Users\User\Desktop\resim\1.ico"
    app.setWindowIcon(QIcon(icon_path))
    # ---------------------------------------------------

    # 1) GLOBAL CSS (font-size'ları büyüttük)
    app.setStyleSheet("""
    QWidget {
         background-color: #121212;
         color: #E0E0E0;
         font-size: 14px;           /* Öncekiler 12px idi, 14px yaptık */
         font-family: "JetBrains Mono", monospace;
    }
    QPushButton {
         background-color: rgba(1, 50, 32, 0.6);
         border: none;
         padding: 12px;             /* Önce 8px’di, 12px yaptık */
         border-radius: 8px;        /* Önce 6px’di, 8px yaptık */
         font-size: 14px;           /* Önce 12px’di, 14px yaptık */
         font-weight: bold;
         color: #E0E0E0;
         transition: 0.2s;
    }
    QPushButton:hover {
         background-color: rgba(1, 80, 50, 0.7);
    }
    QPushButton:pressed {
         background-color: rgba(1, 30, 20, 0.8);
    }
    QLineEdit, QTextEdit, QListWidget, QTableWidget {
         background-color: rgba(40, 40, 40, 0.7);
         border: 1px solid #555;
         color: #E0E0E0;
         selection-background-color: rgba(1, 50, 32, 0.5);
         border-radius: 6px;        /* Önce 4px’di, 6px yaptık */
         padding: 6px;              /* Önce 3px’di, 6px yaptık */
         font-size: 14px;           /* Önce 11px’di, 14px yaptık */
    }
    QLabel {
         font-size: 15px;           /* Önce 13px’di, 15px yaptık */
         font-weight: bold;
         color: rgba(1, 120, 70, 0.8);
    }
    QHeaderView::section {
         background-color: #1E1E1E;
         padding: 6px;              /* Önce 4px’di, 6px yaptık */
         border: 1px solid #333;
         font-weight: bold;
         color: #D0D0D0;
         font-size: 13px;           /* Önce 11px’di, 13px yaptık */
    }
    QTableWidget {
        gridline-color: #333;
    }
    QTableWidget::item {
        padding-top: 8px;
        padding-bottom: 8px;        /* Satır yüksekliğini biraz artırmak için */
    }
    """)

    # 2) Ana pencereyi oluştur ve başlangıç boyutunu tamsayı int(...) ile ver
    gui = FirewallGUI()

    screen = QApplication.primaryScreen()
    screen_size = screen.size()
    # int(...) ile cast ederek float → int dönüştürüyoruz
    new_width = int(screen_size.width() * 0.6)
    new_height = int(screen_size.height() * 0.6)
    gui.resize(new_width, new_height)

    # 3) Pencere düzeyinde (title bar & taskbar) ikonu ata
    gui.setWindowIcon(QIcon(icon_path))

    # 4) Göster ve başlat
    gui.show()
    sys.exit(app.exec_())



