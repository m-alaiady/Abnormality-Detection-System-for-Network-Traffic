import pcap
from rich.console import Console
from rich.table import Table
from rich.text import Text
import time
import socket
from struct import unpack
import os
import sys
import dpkt
from sklearn.ensemble import IsolationForest
from colorama import init

init(autoreset=True)

class PacketSniffer:
    def __init__(self, interface="en0"):
        self.interface = interface
        self.pcap_object = pcap.pcap(name=interface)
        self.packet_id = 0
        self.console = Console()
        self.table = Table(title="[~] Intercepting Packets")
        self.table.add_column("ID", style="cyan")
        self.table.add_column("Src IP")
        self.table.add_column("Dest IP")
        self.table.add_column("Proto")
        self.table.add_column("Src Port")
        self.table.add_column("Dest Port")
        self.table.add_column("Size", style="cyan")
        self.table.add_column("Suspicious", style="red")

        self.console.print(self.table)

        self.protocol_map = {
            dpkt.ip.IP_PROTO_IP: "IP",
            dpkt.ip.IP_PROTO_ICMP: "ICMP",
            dpkt.ip.IP_PROTO_IGMP: "IGMP",
            dpkt.ip.IP_PROTO_TCP: "TCP",
            dpkt.ip.IP_PROTO_UDP: "UDP",
            dpkt.ip.IP_PROTO_GRE: "GRE",
            dpkt.ip.IP_PROTO_ESP: "ESP",
            dpkt.ip.IP_PROTO_AH: "AH",
            dpkt.ip.IP_PROTO_OSPF: "OSPF",
            dpkt.ip.IP_PROTO_SCTP: "SCTP",
            dpkt.ip.IP_PROTO_ICMP6: "ICMPv6",
            dpkt.ip.IP_PROTO_IP6: "IPv6",
            dpkt.ip.IP_PROTO_ROUTING: "Routing",
            dpkt.ip.IP_PROTO_FRAGMENT: "Fragment",
            dpkt.ip.IP_PROTO_RSVP: "RSVP",
            dpkt.ip.IP_PROTO_IPCOMP: "IPComp",
            dpkt.ip.IP_PROTO_PIM: "PIM",
            dpkt.ip.IP_PROTO_VRRP: "VRRP",
            dpkt.ip.IP_PROTO_L2TP: "L2TP",
        }

        self.model = IsolationForest(contamination=0.05)

    def fit_model(self, initial_packet_sizes):
        self.model.fit(initial_packet_sizes)

    def start_sniffing(self):
        packet_sizes = []

        for timestamp, packet in self.pcap_object:
            self.packet_id += 1
            packet_size = len(packet)
            packet_sizes.append([packet_size])

            eth_length = 14
            eth_header = packet[:eth_length]
            ip_header = packet[eth_length:20 + eth_length]
            iph = unpack('!BBHHHBBH4s4s', ip_header)

            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])

            eth = dpkt.ethernet.Ethernet(packet)
            protocol = "Unknown"
            src_port = "Unknown"
            dst_port = "Unknown"

            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                protocol = ip.p

            protocol_name = self.protocol_map.get(protocol, "Unknown")

            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data

                if isinstance(ip.data, dpkt.tcp.TCP) or isinstance(ip.data, dpkt.udp.UDP):
                    transport_layer = ip.data
                    src_port = transport_layer.sport
                    dst_port = transport_layer.dport

            is_suspicious = self.model.predict([[packet_size]])[0]

            data = [
                {
                    "ID": str(self.packet_id),
                    "Src_IP": str(src_ip),
                    "Dst_IP": str(dst_ip),
                    "Proto": str(protocol_name),
                    "Src_port": str(src_port),
                    "Dst_port": str(dst_port),
                    "Size": str(packet_size),
                    "Suspicious": Text("Yes", style="red") if is_suspicious == -1 else Text("No", style="green")
                },
            ]

            for item in data:
                self.table.add_row(item["ID"], item["Src_IP"], item["Dst_IP"], item["Proto"], item["Src_port"],
                                item["Dst_port"], item["Size"], item["Suspicious"])

            self.console.print(self.table)

            time.sleep(0.1)

            if self.packet_id % 100 == 0:
                self.model.fit(packet_sizes[-100:])


if __name__ == "__main__":
    interface = "en0"
    
    if os.geteuid() != 0:
        print(Fore.RED + "[!] This script must be run with sudo.")
        sys.exit(1)

    try:
        packet_sniffer = PacketSniffer(interface=interface)
        initial_packet_sizes = [[1000], [1500], [500]]
        packet_sniffer.fit_model(initial_packet_sizes)
        packet_sniffer.start_sniffing()
    except KeyboardInterrupt:
        print("[!] Program interrupted.")
