from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import AsyncSniffer
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QPushButton,
                             QTextEdit, QComboBox, QTableWidget, QTableWidgetItem,
                             QHeaderView, QSplitter, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont


class SnifferThread(QThread):
    packet_received = pyqtSignal(object)

    def __init__(self, interface, filter_text, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.filter_text = filter_text
        self.running = False
        self.sniffer = None

    def run(self):
        self.running = True
        try:
            self.sniffer = AsyncSniffer(
                iface=self.interface if self.interface != "All" else None,
                prn=self.process_packet,
                filter=self.filter_text if self.filter_text else None,
                store=False
            )
            self.sniffer.start()

            # Keep thread Alive while sniffing
            while self.running and (self.sniffer and self.sniffer.running):
                self.msleep(100)

        except Exception as e:
            print(f"Sniffing error: {e}")
        finally:
            if self.sniffer:
                self.sniffer.stop()

    def process_packet(self, packet):
        if self.running:
            self.packet_received.emit(packet)

    def stop(self):
        self.running = False
        if self.sniffer:
            self.sniffer.stop()


class PacketSnifferGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Akhil's Packet Sniffer")
        self.setGeometry(100, 100, 1000, 700)

        # Initialize variables
        self.sniffer_thread = None
        self.packet_count = 0
        self.interfaces = self.get_network_interfaces()

        self.init_ui()

    def get_network_interfaces(self):
        """Get available network interfaces"""
        try:
            interfaces = get_if_list()
            # Filter out loopback and invalid interfaces
            valid_interfaces = [iface for iface in interfaces if not iface.startswith(('lo', 'docker', 'veth', 'br-'))]
            return ['All'] + valid_interfaces if valid_interfaces else ["No interfaces found"]
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return ["No interfaces found"]

    def init_ui(self):
        """Initialize the user interface"""
        main_widget = QWidget()
        main_layout = QVBoxLayout()

        # Control panel
        control_panel = QWidget()
        control_layout = QHBoxLayout()

        # Interface selection
        interface_label = QLabel("Interface:")
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.interfaces)

        # Filter input
        filter_label = QLabel("Filter:")
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("e.g., tcp, udp, port 80, etc.")

        # Start/Stop buttons
        self.start_button = QPushButton("Start Sniffing")
        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button = QPushButton("Stop Sniffing")
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)

        # Add widgets to control layout
        control_layout.addWidget(interface_label)
        control_layout.addWidget(self.interface_combo)
        control_layout.addWidget(filter_label)
        control_layout.addWidget(self.filter_input)
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        control_panel.setLayout(control_layout)

        # Packet display area
        splitter = QSplitter(Qt.Vertical)

        # Packet list table
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels(["No.", "Time", "Source", "Destination", "Protocol", "Length"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.packet_table.doubleClicked.connect(self.show_packet_details)

        # Packet details area
        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        self.packet_details.setFont(QFont("Courier New", 10))

        splitter.addWidget(self.packet_table)
        splitter.addWidget(self.packet_details)
        splitter.setSizes([400, 200])

        # Add widgets to main layout
        main_layout.addWidget(control_panel)
        main_layout.addWidget(splitter)

        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")

        # Show ethical warning
        self.show_ethical_warning()

    def show_ethical_warning(self):
        """Show ethical use warning message"""
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Ethical Use Warning")
        msg.setText("ETHICAL USE NOTICE")
        msg.setInformativeText(
            "This packet sniffer is for educational purposes only.\n\n"
            "Only use it on networks you own or have explicit permission to monitor.\n"
            "Unauthorized packet sniffing may violate privacy laws and network policies."
        )
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def start_sniffing(self):
        """Start the packet sniffing process"""
        interface = self.interface_combo.currentText()
        filter_text = self.filter_input.text()

        if interface == "No interfaces found":
            QMessageBox.warning(self, "Error", "No valid network interfaces available!")
            return

        # Clear previous data
        self.packet_table.setRowCount(0)
        self.packet_details.clear()
        self.packet_count = 0

        # Start sniffer thread
        self.sniffer_thread = SnifferThread(interface, filter_text)
        self.sniffer_thread.packet_received.connect(self.add_packet_to_table)
        self.sniffer_thread.start()

        # Update UI
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_bar.showMessage(
            f"Sniffing on {interface}" + (f" with filter: {filter_text}" if filter_text else ""))

    def stop_sniffing(self):
        """Stop the packet sniffing process"""
        if self.sniffer_thread:
            self.status_bar.showMessage("Stopping sniffer...")
            QApplication.processEvents()  # Force UI update

            self.sniffer_thread.stop()
            self.sniffer_thread.quit()
            self.sniffer_thread.wait(500)  # Wait up to 500ms

        # Update UI
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_bar.showMessage("Stopped sniffing")

    def add_packet_to_table(self, packet):
        """Add a new packet to the packet table"""
        try:
            self.packet_count += 1
            row_position = self.packet_table.rowCount()
            self.packet_table.insertRow(row_position)

            # Get basic packet info
            time_str = datetime.fromtimestamp(packet.time).strftime('%H:%M:%S.%f')[:-3]
            src = self.get_packet_source(packet)
            dst = self.get_packet_destination(packet)
            protocol = self.get_packet_protocol(packet)
            length = str(len(packet))

            # Add items to table
            self.packet_table.setItem(row_position, 0, QTableWidgetItem(str(self.packet_count)))
            self.packet_table.setItem(row_position, 1, QTableWidgetItem(time_str))
            self.packet_table.setItem(row_position, 2, QTableWidgetItem(src))
            self.packet_table.setItem(row_position, 3, QTableWidgetItem(dst))
            self.packet_table.setItem(row_position, 4, QTableWidgetItem(protocol))
            self.packet_table.setItem(row_position, 5, QTableWidgetItem(length))

            # Store the full packet object in hidden data
            self.packet_table.item(row_position, 0).setData(Qt.UserRole, packet)

            # Auto-scroll to the new row
            self.packet_table.scrollToBottom()

        except Exception as e:
            print(f"Error processing packet: {e}")

    def get_packet_source(self, packet):
        """Get source IP/port from packet"""
        if IP in packet:
            if TCP in packet:
                return f"{packet[IP].src}:{packet[TCP].sport}"
            elif UDP in packet:
                return f"{packet[IP].src}:{packet[UDP].sport}"
            return packet[IP].src
        elif ARP in packet:
            return packet[ARP].psrc
        elif Ether in packet:
            return packet[Ether].src
        return "N/A"

    def get_packet_destination(self, packet):
        """Get destination IP/port from packet"""
        if IP in packet:
            if TCP in packet:
                return f"{packet[IP].dst}:{packet[TCP].dport}"
            elif UDP in packet:
                return f"{packet[IP].dst}:{packet[UDP].dport}"
            return packet[IP].dst
        elif ARP in packet:
            return packet[ARP].pdst
        elif Ether in packet:
            return packet[Ether].dst
        return "N/A"

    def get_packet_protocol(self, packet):
        """Get the highest layer protocol"""
        if TCP in packet:
            return "TCP"
        elif UDP in packet:
            return "UDP"
        elif ICMP in packet:
            return "ICMP"
        elif ARP in packet:
            return "ARP"
        elif IP in packet:
            return "IP"
        elif Ether in packet:
            return "Ethernet"
        return "Unknown"

    def show_packet_details(self, index):
        """Show detailed information about the selected packet"""
        row = index.row()
        packet_item = self.packet_table.item(row, 0)
        packet = packet_item.data(Qt.UserRole)

        details = self.analyze_packet(packet)
        self.packet_details.setPlainText(details)

    def analyze_packet(self, packet):
        """Analyze and return detailed information about the packet"""
        details = []

        # Add basic information
        details.append(f"=== Packet Summary ===")
        details.append(f"Time: {datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
        details.append(f"Length: {len(packet)} bytes")

        # Add protocol layers
        details.append("\n=== Protocol Layers ===")
        for layer in packet.layers():
            details.append(f"- {layer.__name__}")

        # Add detailed information for each layer
        if Ether in packet:
            details.append("\n=== Ethernet Header ===")
            details.append(f"Source MAC: {packet[Ether].src}")
            details.append(f"Destination MAC: {packet[Ether].dst}")
            details.append(f"Type: 0x{packet[Ether].type:04x}")

        if IP in packet:
            details.append("\n=== IP Header ===")
            details.append(f"Version: {packet[IP].version}")
            details.append(f"Header Length: {packet[IP].ihl * 4} bytes")
            details.append(f"TOS: 0x{packet[IP].tos:02x}")
            details.append(f"Total Length: {packet[IP].len}")
            details.append(f"Identification: 0x{packet[IP].id:04x}")
            details.append(f"Flags: {packet[IP].flags}")
            details.append(f"Fragment Offset: {packet[IP].frag}")
            details.append(f"TTL: {packet[IP].ttl}")
            details.append(f"Protocol: {packet[IP].proto} ({self.get_proto_name(packet[IP].proto)})")
            details.append(f"Header Checksum: 0x{packet[IP].chksum:04x}")
            details.append(f"Source IP: {packet[IP].src}")
            details.append(f"Destination IP: {packet[IP].dst}")

        if TCP in packet:
            details.append("\n=== TCP Header ===")
            details.append(f"Source Port: {packet[TCP].sport}")
            details.append(f"Destination Port: {packet[TCP].dport}")
            details.append(f"Sequence Number: {packet[TCP].seq}")
            details.append(f"Acknowledgment Number: {packet[TCP].ack}")
            details.append(f"Data Offset: {packet[TCP].dataofs} bytes")
            details.append(f"Flags: {packet[TCP].flags}")
            details.append(f"Window Size: {packet[TCP].window}")
            details.append(f"Checksum: 0x{packet[TCP].chksum:04x}")
            details.append(f"Urgent Pointer: {packet[TCP].urgptr}")

        if UDP in packet:
            details.append("\n=== UDP Header ===")
            details.append(f"Source Port: {packet[UDP].sport}")
            details.append(f"Destination Port: {packet[UDP].dport}")
            details.append(f"Length: {packet[UDP].len}")
            details.append(f"Checksum: 0x{packet[UDP].chksum:04x}")

        if ICMP in packet:
            details.append("\n=== ICMP Header ===")
            details.append(f"Type: {packet[ICMP].type}")
            details.append(f"Code: {packet[ICMP].code}")
            details.append(f"Checksum: 0x{packet[ICMP].chksum:04x}")

        if ARP in packet:
            details.append("\n=== ARP Header ===")
            details.append(f"Hardware Type: {packet[ARP].hwtype}")
            details.append(f"Protocol Type: 0x{packet[ARP].ptype:04x}")
            details.append(f"Hardware Size: {packet[ARP].hwlen}")
            details.append(f"Protocol Size: {packet[ARP].plen}")
            details.append(f"Operation: {packet[ARP].op}")
            details.append(f"Sender MAC: {packet[ARP].hwsrc}")
            details.append(f"Sender IP: {packet[ARP].psrc}")
            details.append(f"Target MAC: {packet[ARP].hwdst}")
            details.append(f"Target IP: {packet[ARP].pdst}")

        # Add payload (if any)
        if packet.payload:
            details.append("\n=== Payload ===")
            try:
                payload = bytes(packet.payload)
                # Try to decode as UTF-8
                try:
                    text = payload.decode('utf-8', errors='replace')
                    details.append(text)
                except:
                    # If not UTF-8, show hex dump
                    details.append(self.hex_dump(payload))
            except:
                details.append("(Payload not displayable)")

        return "\n".join(details)

    def get_proto_name(self, proto_num):
        """Get protocol name from number"""
        protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            58: "ICMPv6"
        }
        return protocols.get(proto_num, f"Unknown ({proto_num})")

    def hex_dump(self, data, bytes_per_line=16):
        """Create a hex dump of binary data"""
        dump = []
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            dump.append(f"{i:04x}:  {hex_str.ljust(bytes_per_line * 3)}  {ascii_str}")
        return "\n".join(dump)

    def closeEvent(self, event):
        """Handle window close event"""
        if hasattr(self, 'sniffer_thread') and self.sniffer_thread and self.sniffer_thread.isRunning():
            self.stop_sniffing()
            if self.sniffer_thread.isRunning():  # If still running after stop attempt
                self.sniffer_thread.terminate()  # Force stop if needed
        event.accept()


if __name__ == "__main__":
    # Check if running as root (required for packet sniffing on Linux)
    if os.name == 'posix' and os.geteuid() != 0:
        print("This program requires root privileges to sniff packets.")
        sys.exit(1)

    app = QApplication(sys.argv)
    sniffer = PacketSnifferGUI()
    sniffer.show()
    sys.exit(app.exec_())
