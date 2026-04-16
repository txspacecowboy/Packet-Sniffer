#!/usr/bin/env python3
"""
Network Packet Sniffer with Professional GUI using Scapy
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from collections import defaultdict
import queue
from datetime import datetime
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, DNS, wrpcap


class SnifferApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Packet Sniffer")
        self.geometry("1000x700")
        self.minsize(900, 650)

        self.packet_count = 0
        self.total_bytes = 0
        self.protocol_count = defaultdict(int)
        self.packets = []
        self.packet_queue = queue.Queue()
        self.sniffer = None
        self.sniffing = False

        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        self.style.configure("TButton", font=("Segoe UI", 10))
        self.style.configure("TLabel", font=("Segoe UI", 10))

        self.create_widgets()
        self.after(100, self.process_queue)

    def create_widgets(self):
        toolbar = ttk.Frame(self, padding=(10, 10, 10, 5))
        toolbar.pack(fill=tk.X)

        ttk.Label(toolbar, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        ttk.Entry(toolbar, textvariable=self.filter_var, width=32).pack(side=tk.LEFT, padx=6)

        ttk.Button(toolbar, text="TCP", command=lambda: self.set_filter("tcp")).pack(side=tk.LEFT, padx=6)
        ttk.Button(toolbar, text="UDP", command=lambda: self.set_filter("udp")).pack(side=tk.LEFT, padx=6)
        ttk.Button(toolbar, text="All", command=lambda: self.set_filter("")).pack(side=tk.LEFT, padx=6)

        ttk.Label(toolbar, text="Save file:").pack(side=tk.LEFT, padx=(20, 0))
        self.filename_var = tk.StringVar(value="capture.pcap")
        ttk.Entry(toolbar, textvariable=self.filename_var, width=24).pack(side=tk.LEFT, padx=6)

        self.start_btn = ttk.Button(toolbar, text="Start Sniffing", command=self.start_sniffing)
        self.start_btn.pack(side=tk.LEFT, padx=6)
        self.stop_btn = ttk.Button(toolbar, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=6)
        self.save_btn = ttk.Button(toolbar, text="Save Packets", command=self.save_packets, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT, padx=6)

        stats_frame = ttk.Frame(self, padding=(10, 0, 10, 10))
        stats_frame.pack(fill=tk.X)

        self.total_label = ttk.Label(stats_frame, text="Total Packets: 0")
        self.total_label.pack(side=tk.LEFT, padx=8)
        self.bytes_label = ttk.Label(stats_frame, text="Total Bytes: 0")
        self.bytes_label.pack(side=tk.LEFT, padx=8)
        self.tcp_label = ttk.Label(stats_frame, text="TCP: 0")
        self.tcp_label.pack(side=tk.LEFT, padx=8)
        self.udp_label = ttk.Label(stats_frame, text="UDP: 0")
        self.udp_label.pack(side=tk.LEFT, padx=8)
        self.icmp_label = ttk.Label(stats_frame, text="ICMP: 0")
        self.icmp_label.pack(side=tk.LEFT, padx=8)

        main_pane = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        left_frame = ttk.Frame(main_pane)
        main_pane.add(left_frame, weight=3)

        columns = ("#", "Time", "Source", "Destination", "Proto", "Length", "Info")
        self.packet_tree = ttk.Treeview(left_frame, columns=columns, show="headings", selectmode="browse")
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, anchor=tk.W, stretch=True)
        self.packet_tree.column("#", width=60, anchor=tk.CENTER)
        self.packet_tree.column("Time", width=120)
        self.packet_tree.column("Source", width=170)
        self.packet_tree.column("Destination", width=170)
        self.packet_tree.column("Proto", width=70, anchor=tk.CENTER)
        self.packet_tree.column("Length", width=70, anchor=tk.CENTER)
        self.packet_tree.column("Info", width=270)

        self.packet_tree.tag_configure("TCP", background="#d5f5e3", foreground="#000000")
        self.packet_tree.tag_configure("UDP", background="#d6eaf8", foreground="#000000")
        self.packet_tree.tag_configure("ICMP", background="#fdebd0", foreground="#000000")
        self.packet_tree.tag_configure("Other", background="#f6ddcc", foreground="#000000")

        packet_scroll = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscroll=packet_scroll.set)
        packet_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_tree.pack(fill=tk.BOTH, expand=True)

        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_selected)

        right_frame = ttk.Frame(main_pane)
        main_pane.add(right_frame, weight=2)

        tab_control = ttk.Notebook(right_frame)
        tab_control.pack(fill=tk.BOTH, expand=True)

        self.details_tab = ttk.Frame(tab_control)
        self.raw_tab = ttk.Frame(tab_control)

        tab_control.add(self.details_tab, text="Packet Details")
        tab_control.add(self.raw_tab, text="Raw Summary")

        details_frame = ttk.Frame(self.details_tab, padding=10)
        details_frame.pack(fill=tk.BOTH, expand=True)
        self.details_text = tk.Text(details_frame, wrap=tk.WORD, state=tk.DISABLED, height=16)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        raw_frame = ttk.Frame(self.raw_tab, padding=10)
        raw_frame.pack(fill=tk.BOTH, expand=True)
        self.raw_text = scrolledtext.ScrolledText(raw_frame, wrap=tk.WORD, height=16)
        self.raw_text.pack(fill=tk.BOTH, expand=True)

        self.status_label = ttk.Label(self, text="Ready", anchor=tk.W, padding=(10, 5))
        self.status_label.pack(fill=tk.X)

    def packet_callback(self, packet):
        self.packet_count += 1
        self.total_bytes += len(packet)
        self.packets.append(packet)

        timestamp = datetime.fromtimestamp(packet.time).strftime("%H:%M:%S")
        summary = packet.summary()
        row_info = "Unknown"
        src = dst = proto = ""
        length = len(packet)
        row_tag = "Other"

        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto_value = packet[IP].proto

            if proto_value == 6 and TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                row_info = f"TCP {src_port}->{dst_port}"
                proto = "TCP"
                row_tag = "TCP"
                self.protocol_count["TCP"] += 1
            elif proto_value == 17 and UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                row_info = f"UDP {src_port}->{dst_port}"
                proto = "UDP"
                row_tag = "UDP"
                self.protocol_count["UDP"] += 1
            elif proto_value == 1 and ICMP in packet:
                row_info = "ICMP"
                proto = "ICMP"
                row_tag = "ICMP"
                self.protocol_count["ICMP"] += 1
            else:
                row_info = f"Proto {proto_value}"
                proto = str(proto_value)
                row_tag = "Other"
                self.protocol_count["Other"] += 1
        else:
            row_info = "Non-IP"
            row_tag = "Other"
            self.protocol_count["Other"] += 1

        self.packet_queue.put({
            "type": "row",
            "values": (self.packet_count, timestamp, src, dst, proto, length, row_info),
            "tag": row_tag,
            "details": self.format_packet_details(packet, summary),
            "summary": summary,
        })

    def format_packet_details(self, packet, summary):
        lines = [
            f"Packet #{self.packet_count}",
            f"Timestamp: {datetime.fromtimestamp(packet.time):%Y-%m-%d %H:%M:%S}",
            f"Length: {len(packet)}",
            "",
        ]

        if IP in packet:
            lines.extend([
                f"Source: {packet[IP].src}",
                f"Destination: {packet[IP].dst}",
                f"Protocol: {packet[IP].proto}",
            ])
            if TCP in packet:
                lines.extend([
                    f"TCP Source Port: {packet[TCP].sport}",
                    f"TCP Dest Port: {packet[TCP].dport}",
                    f"Flags: {packet[TCP].flags}",
                ])
            if UDP in packet:
                lines.extend([
                    f"UDP Source Port: {packet[UDP].sport}",
                    f"UDP Dest Port: {packet[UDP].dport}",
                ])
            if ICMP in packet:
                lines.extend([
                    f"ICMP Type: {packet[ICMP].type}",
                    f"ICMP Code: {packet[ICMP].code}",
                ])
            if DNS in packet:
                if packet[DNS].qr == 0 and packet[DNS].qd:
                    lines.append(f"DNS Query: {packet[DNS].qd.qname.decode('utf-8', errors='ignore')}")
                elif packet[DNS].qr == 1 and packet[DNS].an:
                    lines.append(f"DNS Answer: {packet[DNS].an.rrname.decode('utf-8', errors='ignore')}")
        else:
            lines.append("Non-IP packet")

        lines.extend(["", "Summary:", summary])
        return "\n".join(lines)

    def start_sniffing(self):
        if self.sniffing:
            return
        self.sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.save_btn.config(state=tk.NORMAL)
        self.status_label.config(text="Sniffing...")

        filter_text = self.filter_var.get().strip() or None
        self.sniffer = AsyncSniffer(prn=self.packet_callback, filter=filter_text)
        self.sniffer.start()

    def stop_sniffing(self):
        if not self.sniffing:
            return
        self.sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Stopped")
        if self.sniffer:
            self.sniffer.stop()

    def save_packets(self):
        if self.packets:
            filename = self.filename_var.get().strip() or "capture.pcap"
            if not filename.lower().endswith(".pcap"):
                filename += ".pcap"
            wrpcap(filename, self.packets)
            messagebox.showinfo("Saved", f"Packets saved to {filename}")
            self.status_label.config(text=f"Saved {len(self.packets)} packets to {filename}")
        else:
            messagebox.showwarning("No Packets", "No packets to save.")

    def on_packet_selected(self, _event):
        selected = self.packet_tree.selection()
        if not selected:
            return
        item = self.packet_tree.item(selected[0])
        index = int(item["values"][0]) - 1
        packet = self.packets[index]
        details = self.format_packet_details(packet, packet.summary())
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete("1.0", tk.END)
        self.details_text.insert(tk.END, details)
        self.details_text.config(state=tk.DISABLED)
        self.raw_text.delete("1.0", tk.END)
        self.raw_text.insert(tk.END, packet.summary())

    def process_queue(self):
        try:
            while True:
                item = self.packet_queue.get_nowait()
                if item["type"] == "row":
                    self.packet_tree.insert("", tk.END, values=item["values"], tags=(item["tag"],))
                    self.details_text.config(state=tk.NORMAL)
                    self.details_text.delete("1.0", tk.END)
                    self.details_text.insert(tk.END, item["details"])
                    self.details_text.config(state=tk.DISABLED)
                    self.raw_text.delete("1.0", tk.END)
                    self.raw_text.insert(tk.END, item["summary"])
        except queue.Empty:
            pass

        self.total_label.config(text=f"Total Packets: {self.packet_count}")
        self.bytes_label.config(text=f"Total Bytes: {self.total_bytes}")
        self.tcp_label.config(text=f"TCP: {self.protocol_count['TCP']}")
        self.udp_label.config(text=f"UDP: {self.protocol_count['UDP']}")
        self.icmp_label.config(text=f"ICMP: {self.protocol_count['ICMP']}")

        self.after(100, self.process_queue)

    def set_filter(self, filter_text):
        self.filter_var.set(filter_text)


if __name__ == "__main__":
    app = SnifferApp()
    app.mainloop()