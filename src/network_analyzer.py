#!/usr/bin/env python3
"""
PyShark – Wireshark-inspired Network Protocol Analyzer
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import queue
import time
import datetime
import os
import csv
import json
from collections import defaultdict

try:
    from scapy.all import (
        AsyncSniffer, wrpcap, rdpcap, get_if_list,
        IP, IPv6, TCP, UDP, ICMP, DNS, ARP, Ether, Raw, conf,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── Constants ──────────────────────────────────────────────────────────────────

APP_TITLE = "PyShark – Network Protocol Analyzer"
APP_VERSION = "2.0.0"

PROTO_COLORS = {
    "TCP":    {"bg": "#e8f4fd", "fg": "#000000"},
    "UDP":    {"bg": "#e8f5e9", "fg": "#000000"},
    "ICMP":   {"bg": "#fff8e1", "fg": "#000000"},
    "ARP":    {"bg": "#fce4ec", "fg": "#000000"},
    "DNS":    {"bg": "#e1f5fe", "fg": "#000000"},
    "HTTP":   {"bg": "#e8f5e9", "fg": "#006400"},
    "HTTPS":  {"bg": "#e8eaf6", "fg": "#1a237e"},
    "TLS":    {"bg": "#e8eaf6", "fg": "#1a237e"},
    "DHCP":   {"bg": "#fff9c4", "fg": "#000000"},
    "NTP":    {"bg": "#f3e5f5", "fg": "#000000"},
    "IPv6":   {"bg": "#fbe9e7", "fg": "#000000"},
    "Other":  {"bg": "#ffffff", "fg": "#000000"},
}

PORT_TO_PROTO = {
    80: "HTTP", 8080: "HTTP", 8000: "HTTP", 8008: "HTTP",
    443: "HTTPS", 8443: "HTTPS",
    53: "DNS", 5353: "DNS",
    67: "DHCP", 68: "DHCP",
    123: "NTP",
}

ICMP_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
    5: "Redirect", 8: "Echo Request", 9: "Router Advertisement",
    10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem",
    13: "Timestamp Request", 14: "Timestamp Reply",
}

TCP_FLAGS = {
    0x001: "FIN", 0x002: "SYN", 0x004: "RST",
    0x008: "PSH", 0x010: "ACK", 0x020: "URG",
    0x040: "ECE", 0x080: "CWR",
}

KNOWN_TAGS = {k.lower() for k in PROTO_COLORS}


# ── Packet Analysis Logic ──────────────────────────────────────────────────────

class PacketAnalyzer:

    @staticmethod
    def get_protocol(pkt):
        if not SCAPY_AVAILABLE:
            return "Other"
        if pkt.haslayer(ARP):
            return "ARP"
        if pkt.haslayer(TCP):
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            for p in (dport, sport):
                if p in PORT_TO_PROTO:
                    return PORT_TO_PROTO[p]
            if pkt.haslayer(Raw):
                b = bytes(pkt[Raw])
                if b and b[0] in (0x14, 0x15, 0x16, 0x17):
                    return "TLS"
            return "TCP"
        if pkt.haslayer(UDP):
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            for p in (dport, sport):
                if p in PORT_TO_PROTO:
                    return PORT_TO_PROTO[p]
            return "UDP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        if pkt.haslayer(IPv6):
            return "IPv6"
        return "Other"

    @staticmethod
    def get_endpoints(pkt):
        src = dst = "N/A"
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        elif pkt.haslayer(ARP):
            src, dst = pkt[ARP].psrc, pkt[ARP].pdst
        elif pkt.haslayer(Ether):
            src, dst = pkt[Ether].src, pkt[Ether].dst
        return src, dst

    @staticmethod
    def decode_tcp_flags(flags):
        fi = int(flags)
        return ", ".join(n for bit, n in sorted(TCP_FLAGS.items()) if fi & bit) or "None"

    @staticmethod
    def get_info(pkt, protocol):
        try:
            if protocol == "ARP":
                a = pkt[ARP]
                if a.op == 1:
                    return f"Who has {a.pdst}? Tell {a.psrc}"
                return f"{a.psrc} is at {a.hwsrc}"

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                flags = PacketAnalyzer.decode_tcp_flags(tcp.flags)
                base = f"{tcp.sport} → {tcp.dport} [{flags}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"
                if protocol == "HTTP" and pkt.haslayer(Raw):
                    try:
                        first = bytes(pkt[Raw]).decode("utf-8", errors="ignore").split("\r\n")[0]
                        if first:
                            return first[:100]
                    except Exception:
                        pass
                if protocol in ("HTTPS", "TLS") and pkt.haslayer(Raw):
                    b = bytes(pkt[Raw])
                    if b:
                        label = {0x14: "Change Cipher Spec", 0x15: "Alert",
                                 0x16: "Handshake", 0x17: "Application Data"}.get(b[0], "")
                        if label:
                            return f"{tcp.sport} → {tcp.dport} TLS {label}"
                return base

            if pkt.haslayer(UDP):
                udp = pkt[UDP]
                if pkt.haslayer(DNS):
                    dns = pkt[DNS]
                    if dns.qr == 0 and dns.qd:
                        name = dns.qd.qname.decode(errors="ignore").rstrip(".")
                        return f"Standard query 0x{dns.id:04x} {name}"
                    if dns.qr == 1:
                        answers = []
                        an = dns.an
                        while an and hasattr(an, "rrname"):
                            if hasattr(an, "rdata"):
                                answers.append(str(an.rdata))
                            an = an.payload if hasattr(an, "payload") and hasattr(an.payload, "rrname") else None
                        return f"Standard query response 0x{dns.id:04x} {', '.join(answers[:3])}"
                return f"{udp.sport} → {udp.dport} Len={udp.len}"

            if pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                name = ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")
                return f"{name} id={getattr(icmp,'id',0)} seq={getattr(icmp,'seq',0)}"

            return pkt.summary()[:100]
        except Exception:
            return pkt.summary()[:100]

    @staticmethod
    def build_detail_nodes(pkt):
        nodes = []  # (indent_level, open_by_default, text)

        pkt_bytes = bytes(pkt)
        nodes.append((0, True,  f"Frame: {len(pkt_bytes)} bytes on wire, {len(pkt_bytes)} bytes captured"))
        nodes.append((1, False, f"Encapsulation type: Ethernet"))
        nodes.append((1, False, f"Frame length: {len(pkt_bytes)} bytes"))

        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            etype_map = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "802.1Q VLAN"}
            etype = etype_map.get(eth.type, f"0x{eth.type:04x}")
            nodes.append((0, True,  f"Ethernet II  Src: {eth.src}  Dst: {eth.dst}"))
            nodes.append((1, False, f"Destination: {eth.dst}"))
            nodes.append((1, False, f"Source: {eth.src}"))
            nodes.append((1, False, f"Type: {etype} (0x{eth.type:04x})"))

        if pkt.haslayer(ARP):
            a = pkt[ARP]
            op = {1: "request (1)", 2: "reply (2)"}.get(a.op, str(a.op))
            nodes.append((0, True,  f"Address Resolution Protocol ({op})"))
            nodes.append((1, False, f"Hardware type: Ethernet (1)"))
            nodes.append((1, False, f"Protocol type: IPv4 (0x{a.ptype:04x})"))
            nodes.append((1, False, f"Opcode: {op}"))
            nodes.append((1, False, f"Sender MAC: {a.hwsrc}"))
            nodes.append((1, False, f"Sender IP: {a.psrc}"))
            nodes.append((1, False, f"Target MAC: {a.hwdst}"))
            nodes.append((1, False, f"Target IP: {a.pdst}"))

        if pkt.haslayer(IP):
            ip = pkt[IP]
            proto_name = {1: "ICMP (1)", 6: "TCP (6)", 17: "UDP (17)"}.get(ip.proto, str(ip.proto))
            flags_parts = []
            if ip.flags & 0x2:
                flags_parts.append("Don't Fragment")
            if ip.flags & 0x1:
                flags_parts.append("More Fragments")
            nodes.append((0, True,  f"Internet Protocol Version 4  Src: {ip.src}  Dst: {ip.dst}"))
            nodes.append((1, False, f"Version: 4"))
            nodes.append((1, False, f"Header Length: {ip.ihl * 4} bytes ({ip.ihl})"))
            nodes.append((1, False, f"Differentiated Services: 0x{ip.tos:02x}"))
            nodes.append((1, False, f"Total Length: {ip.len}"))
            nodes.append((1, False, f"Identification: 0x{ip.id:04x} ({ip.id})"))
            nodes.append((1, False, f"Flags: 0x{int(ip.flags):02x}  {', '.join(flags_parts) or 'None'}"))
            nodes.append((1, False, f"Fragment Offset: {ip.frag}"))
            nodes.append((1, False, f"Time to Live: {ip.ttl}"))
            nodes.append((1, False, f"Protocol: {proto_name}"))
            nodes.append((1, False, f"Header Checksum: 0x{ip.chksum:04x}"))
            nodes.append((1, False, f"Source Address: {ip.src}"))
            nodes.append((1, False, f"Destination Address: {ip.dst}"))

        if pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            nodes.append((0, True,  f"Internet Protocol Version 6  Src: {ip6.src}  Dst: {ip6.dst}"))
            nodes.append((1, False, f"Version: 6"))
            nodes.append((1, False, f"Traffic Class: 0x{ip6.tc:02x}"))
            nodes.append((1, False, f"Flow Label: 0x{ip6.fl:05x}"))
            nodes.append((1, False, f"Payload Length: {ip6.plen}"))
            nodes.append((1, False, f"Next Header: {ip6.nh}"))
            nodes.append((1, False, f"Hop Limit: {ip6.hlim}"))
            nodes.append((1, False, f"Source: {ip6.src}"))
            nodes.append((1, False, f"Destination: {ip6.dst}"))

        if pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            type_name = ICMP_TYPES.get(icmp.type, f"Unknown ({icmp.type})")
            nodes.append((0, True,  f"Internet Control Message Protocol"))
            nodes.append((1, False, f"Type: {icmp.type} ({type_name})"))
            nodes.append((1, False, f"Code: {icmp.code}"))
            nodes.append((1, False, f"Checksum: 0x{icmp.chksum:04x}"))
            if hasattr(icmp, "id"):
                nodes.append((1, False, f"Identifier: {icmp.id} (0x{icmp.id:04x})"))
            if hasattr(icmp, "seq"):
                nodes.append((1, False, f"Sequence Number: {icmp.seq}"))

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags_str = PacketAnalyzer.decode_tcp_flags(tcp.flags)
            nodes.append((0, True,  f"Transmission Control Protocol  Src: {tcp.sport}  Dst: {tcp.dport}  Seq: {tcp.seq}"))
            nodes.append((1, False, f"Source Port: {tcp.sport}"))
            nodes.append((1, False, f"Destination Port: {tcp.dport}"))
            nodes.append((1, False, f"Sequence Number: {tcp.seq}"))
            nodes.append((1, False, f"Acknowledgment Number: {tcp.ack}"))
            nodes.append((1, False, f"Header Length: {tcp.dataofs * 4} bytes ({tcp.dataofs})"))
            nodes.append((1, True,  f"Flags: 0x{int(tcp.flags):03x} ({flags_str})"))
            for bit, name in sorted(TCP_FLAGS.items()):
                if int(tcp.flags) & bit:
                    nodes.append((2, False, f"  .... .... .... .{name}: Set"))
            nodes.append((1, False, f"Window Size: {tcp.window}"))
            nodes.append((1, False, f"Checksum: 0x{tcp.chksum:04x}"))
            nodes.append((1, False, f"Urgent Pointer: {tcp.urgptr}"))

        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            nodes.append((0, True,  f"User Datagram Protocol  Src: {udp.sport}  Dst: {udp.dport}"))
            nodes.append((1, False, f"Source Port: {udp.sport}"))
            nodes.append((1, False, f"Destination Port: {udp.dport}"))
            nodes.append((1, False, f"Length: {udp.len}"))
            nodes.append((1, False, f"Checksum: 0x{udp.chksum:04x}"))

        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            qr_str = "Response" if dns.qr else "Query"
            nodes.append((0, True,  f"Domain Name System ({qr_str})"))
            nodes.append((1, False, f"Transaction ID: 0x{dns.id:04x}"))
            nodes.append((1, False, f"Flags: {'Response' if dns.qr else 'Query'}"))
            nodes.append((1, False, f"Questions: {dns.qdcount}"))
            nodes.append((1, False, f"Answer RRs: {dns.ancount}"))
            nodes.append((1, False, f"Authority RRs: {dns.nscount}"))
            nodes.append((1, False, f"Additional RRs: {dns.arcount}"))
            if dns.qd:
                qtype_map = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 28: "AAAA", 16: "TXT"}
                qtype = qtype_map.get(dns.qd.qtype, str(dns.qd.qtype))
                name = dns.qd.qname.decode(errors="ignore").rstrip(".")
                nodes.append((1, True,  f"Queries"))
                nodes.append((2, False, f"{name}: type {qtype}"))
                nodes.append((3, False, f"Name: {name}"))
                nodes.append((3, False, f"Type: {qtype} ({dns.qd.qtype})"))
            an = dns.an
            if an and hasattr(an, "rrname"):
                nodes.append((1, True, f"Answers"))
                while an and hasattr(an, "rrname"):
                    try:
                        rname = an.rrname.decode(errors="ignore").rstrip(".")
                        rdata = str(an.rdata) if hasattr(an, "rdata") else "N/A"
                        nodes.append((2, False, f"{rname}: {rdata}"))
                    except Exception:
                        pass
                    an = an.payload if (hasattr(an, "payload") and hasattr(an.payload, "rrname")) else None

        if pkt.haslayer(Raw):
            raw_bytes = bytes(pkt[Raw])
            nodes.append((0, False, f"Data ({len(raw_bytes)} bytes)"))
            preview = " ".join(f"{b:02x}" for b in raw_bytes[:32])
            nodes.append((1, False, f"Data: {preview}{'...' if len(raw_bytes) > 32 else ''}"))

        return nodes

    @staticmethod
    def get_hex_dump(pkt):
        raw = bytes(pkt)
        lines = []
        for i in range(0, len(raw), 16):
            chunk = raw[i:i + 16]
            left  = " ".join(f"{b:02x}" for b in chunk[:8])
            right = " ".join(f"{b:02x}" for b in chunk[8:])
            hex_str = f"{left:<23}  {right:<23}"
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append((i, hex_str, ascii_str))
        return lines


# ── Statistics Window ──────────────────────────────────────────────────────────

class StatsWindow(tk.Toplevel):
    def __init__(self, parent, packets):
        super().__init__(parent)
        self.title("Protocol Hierarchy Statistics")
        self.geometry("640x380")
        self.configure(bg="#f5f5f5")
        self.resizable(True, True)

        ttk.Label(self, text="Protocol Hierarchy Statistics",
                  font=("Segoe UI", 11, "bold")).pack(pady=(12, 4))

        frame = ttk.Frame(self, padding=(8, 0, 8, 8))
        frame.pack(fill=tk.BOTH, expand=True)

        cols = ("Protocol", "Packets", "%", "Bytes", "Bytes/Pkt")
        tree = ttk.Treeview(frame, columns=cols, show="headings", height=14)
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=100, anchor="center")
        tree.column("Protocol", width=200, anchor="w")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
        for pkt in packets:
            proto = PacketAnalyzer.get_protocol(pkt)
            stats[proto]["packets"] += 1
            stats[proto]["bytes"] += len(bytes(pkt))

        total = max(len(packets), 1)
        for proto, d in sorted(stats.items(), key=lambda x: -x[1]["packets"]):
            pct = f"{d['packets'] / total * 100:.1f}%"
            bpp = f"{d['bytes'] // max(d['packets'], 1)}"
            tree.insert("", "end", values=(proto, d["packets"], pct, d["bytes"], bpp))

        ttk.Button(self, text="Close", command=self.destroy).pack(pady=6)


# ── About Dialog ───────────────────────────────────────────────────────────────

class AboutDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("About PyShark")
        self.geometry("360x210")
        self.resizable(False, False)
        self.configure(bg="#f5f5f5")

        ttk.Label(self, text="PyShark", font=("Segoe UI", 22, "bold")).pack(pady=(20, 2))
        ttk.Label(self, text=f"Version {APP_VERSION}", font=("Segoe UI", 9)).pack()
        ttk.Label(self, text="Network Protocol Analyzer", font=("Segoe UI", 9)).pack()
        ttk.Label(self, text="Powered by Scapy  •  Inspired by Wireshark",
                  font=("Segoe UI", 8), foreground="#666666").pack(pady=(6, 0))
        ttk.Separator(self, orient="horizontal").pack(fill=tk.X, padx=24, pady=10)
        ttk.Button(self, text="OK", command=self.destroy).pack()


# ── Main Application ───────────────────────────────────────────────────────────

class PySharkApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1320x820")
        self.minsize(960, 640)

        # State
        self.packets = []
        self.packet_queue = queue.Queue()
        self.sniffer = None
        self.sniffing = False
        self.capture_start = None
        self.packet_count = 0
        self.total_bytes = 0
        self._context_iid = None
        self._sort_reverse = {}

        # Vars
        self.iface_var = tk.StringVar()
        self.cap_filter_var = tk.StringVar()
        self.disp_filter_var = tk.StringVar()
        self.autoscroll_var = tk.BooleanVar(value=True)

        self.style = ttk.Style(self)
        self._apply_theme()
        self._build_menu()
        self._build_toolbar()
        self._build_filter_bar()
        self._build_main_area()
        self._build_statusbar()
        self._load_interfaces()

        self.after(100, self._process_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── Theme ────────────────────────────────────────────────────────────────

    def _apply_theme(self):
        self.configure(bg="#f0f0f0")
        self.style.theme_use("clam")
        self.style.configure("Treeview",
            background="#ffffff", foreground="#000000",
            rowheight=22, fieldbackground="#ffffff",
            font=("Consolas", 9))
        self.style.configure("Treeview.Heading",
            background="#d8d8d8", foreground="#000000",
            font=("Segoe UI", 9, "bold"), relief="flat")
        self.style.map("Treeview.Heading", background=[("active", "#b8b8b8")])
        self.style.map("Treeview",
            background=[("selected", "#0078d7")],
            foreground=[("selected", "#ffffff")])
        self.style.configure("TButton", font=("Segoe UI", 9), padding=(6, 3))
        self.style.configure("Status.TFrame", background="#e8e8e8")
        self.style.configure("Status.TLabel",
            background="#e8e8e8", font=("Segoe UI", 8))

    # ── Menu ─────────────────────────────────────────────────────────────────

    def _build_menu(self):
        bar = tk.Menu(self)
        self.configure(menu=bar)

        # File
        fm = tk.Menu(bar, tearoff=0)
        bar.add_cascade(label="File", menu=fm)
        fm.add_command(label="Open Capture File...    Ctrl+O", command=self._open_pcap)
        fm.add_command(label="Save Capture As...      Ctrl+S", command=self._save_pcap)
        fm.add_separator()
        fm.add_command(label="Export Packets as CSV...",  command=self._export_csv)
        fm.add_command(label="Export Packets as JSON...", command=self._export_json)
        fm.add_separator()
        fm.add_command(label="Exit", command=self._on_close)

        # Capture
        cm = tk.Menu(bar, tearoff=0)
        bar.add_cascade(label="Capture", menu=cm)
        cm.add_command(label="Start    Ctrl+E", command=self._start_capture)
        cm.add_command(label="Stop     Ctrl+E", command=self._stop_capture)
        cm.add_command(label="Restart",          command=self._restart_capture)
        cm.add_separator()
        cm.add_command(label="Interfaces...",    command=self._show_iface_dialog)

        # Analyze
        am = tk.Menu(bar, tearoff=0)
        bar.add_cascade(label="Analyze", menu=am)
        am.add_command(label="Protocol Hierarchy...", command=self._show_stats)
        am.add_separator()
        am.add_command(label="Apply Display Filter",  command=self._apply_display_filter)
        am.add_command(label="Clear Display Filter",  command=self._clear_display_filter)

        # View
        vm = tk.Menu(bar, tearoff=0)
        bar.add_cascade(label="View", menu=vm)
        vm.add_checkbutton(label="Auto-scroll", variable=self.autoscroll_var)
        vm.add_separator()
        vm.add_command(label="Zoom In   Ctrl++", command=lambda: self._zoom(1))
        vm.add_command(label="Zoom Out  Ctrl+-", command=lambda: self._zoom(-1))
        vm.add_command(label="Reset Zoom",       command=lambda: self._zoom(0))
        vm.add_separator()
        vm.add_command(label="Clear Packet List", command=self._clear_packets)

        # Help
        hm = tk.Menu(bar, tearoff=0)
        bar.add_cascade(label="Help", menu=hm)
        hm.add_command(label="About PyShark...", command=lambda: AboutDialog(self))

        self.bind("<Control-o>", lambda _: self._open_pcap())
        self.bind("<Control-s>", lambda _: self._save_pcap())
        self.bind("<Control-e>", lambda _: self._toggle_capture())
        self.bind("<Control-equal>", lambda _: self._zoom(1))
        self.bind("<Control-minus>",  lambda _: self._zoom(-1))

    # ── Toolbar ───────────────────────────────────────────────────────────────

    def _build_toolbar(self):
        ttk.Separator(self, orient="horizontal").pack(fill=tk.X)
        tb = ttk.Frame(self, padding=(4, 3))
        tb.pack(fill=tk.X)

        ttk.Label(tb, text="Interface:").pack(side=tk.LEFT, padx=(2, 2))
        self.iface_combo = ttk.Combobox(tb, textvariable=self.iface_var,
                                        width=24, state="readonly",
                                        font=("Segoe UI", 9))
        self.iface_combo.pack(side=tk.LEFT, padx=(0, 6))

        ttk.Separator(tb, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=4)

        self.btn_start = ttk.Button(tb, text="▶  Start",  command=self._start_capture)
        self.btn_stop  = ttk.Button(tb, text="■  Stop",   command=self._stop_capture, state="disabled")
        self.btn_restart = ttk.Button(tb, text="↺  Restart", command=self._restart_capture)
        for btn in (self.btn_start, self.btn_stop, self.btn_restart):
            btn.pack(side=tk.LEFT, padx=2)

        ttk.Separator(tb, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=4)

        ttk.Button(tb, text="Open",  command=self._open_pcap).pack(side=tk.LEFT, padx=2)
        ttk.Button(tb, text="Save",  command=self._save_pcap).pack(side=tk.LEFT, padx=2)

        ttk.Separator(tb, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=4)

        ttk.Button(tb, text="Stats", command=self._show_stats).pack(side=tk.LEFT, padx=2)
        ttk.Button(tb, text="Clear", command=self._clear_packets).pack(side=tk.LEFT, padx=2)

        self.capture_dot = ttk.Label(tb, text="  ●  Idle",
                                     foreground="#888888", font=("Segoe UI", 9, "bold"))
        self.capture_dot.pack(side=tk.RIGHT, padx=10)

    # ── Filter bar ────────────────────────────────────────────────────────────

    def _build_filter_bar(self):
        ttk.Separator(self, orient="horizontal").pack(fill=tk.X)
        fb = ttk.Frame(self, padding=(4, 3))
        fb.pack(fill=tk.X)

        ttk.Label(fb, text="Display Filter:").pack(side=tk.LEFT, padx=(2, 4))
        self.disp_entry = ttk.Entry(fb, textvariable=self.disp_filter_var,
                                    font=("Consolas", 9), width=46)
        self.disp_entry.pack(side=tk.LEFT, padx=(0, 4))
        self.disp_entry.bind("<Return>",     lambda _: self._apply_display_filter())
        self.disp_entry.bind("<Escape>",     lambda _: self._clear_display_filter())

        ttk.Button(fb, text="Apply", command=self._apply_display_filter).pack(side=tk.LEFT, padx=2)
        ttk.Button(fb, text="Clear", command=self._clear_display_filter).pack(side=tk.LEFT, padx=2)

        ttk.Separator(fb, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=8)

        ttk.Label(fb, text="Capture Filter (BPF):").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Entry(fb, textvariable=self.cap_filter_var,
                  font=("Consolas", 9), width=28).pack(side=tk.LEFT)

        # Quick filter buttons
        ttk.Separator(fb, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=8)
        ttk.Label(fb, text="Quick:").pack(side=tk.LEFT, padx=(0, 4))
        for label, expr in (("TCP", "tcp"), ("UDP", "udp"), ("ICMP", "icmp"),
                             ("DNS", "dns"), ("ARP", "arp"), ("HTTP", "http"), ("All", "")):
            ttk.Button(fb, text=label, width=5,
                       command=lambda e=expr: self._quick_filter(e)).pack(side=tk.LEFT, padx=1)

    # ── Three-pane main area ──────────────────────────────────────────────────

    def _build_main_area(self):
        ttk.Separator(self, orient="horizontal").pack(fill=tk.X)
        outer = ttk.PanedWindow(self, orient=tk.VERTICAL)
        outer.pack(fill=tk.BOTH, expand=True)

        self._build_packet_list(outer)

        bottom = ttk.PanedWindow(outer, orient=tk.HORIZONTAL)
        outer.add(bottom, weight=1)

        self._build_detail_pane(bottom)
        self._build_hex_pane(bottom)

    def _build_packet_list(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, weight=2)

        cols = ("no", "time", "src", "dst", "proto", "len", "info")
        self.pkt_tree = ttk.Treeview(frame, columns=cols,
                                     show="headings", selectmode="browse")

        hdrs = {"no": ("No.",         58,  "center"),
                "time": ("Time",      115, "center"),
                "src":  ("Source",    155, "w"),
                "dst":  ("Destination",155,"w"),
                "proto":("Protocol",  80,  "center"),
                "len":  ("Length",    64,  "center"),
                "info": ("Info",      520, "w")}

        for col, (text, width, anchor) in hdrs.items():
            self.pkt_tree.heading(col, text=text,
                command=lambda c=col: self._sort_column(c))
            self.pkt_tree.column(col, width=width, anchor=anchor,
                                 stretch=(col == "info"))

        for proto, colors in PROTO_COLORS.items():
            self.pkt_tree.tag_configure(proto.lower(),
                background=colors["bg"], foreground=colors["fg"])

        vsb = ttk.Scrollbar(frame, orient="vertical",   command=self.pkt_tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal",  command=self.pkt_tree.xview)
        self.pkt_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.pkt_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self.pkt_tree.bind("<<TreeviewSelect>>", self._on_packet_selected)
        self.pkt_tree.bind("<Button-3>",          self._show_ctx_menu)

        self._ctx_menu = tk.Menu(self, tearoff=0)
        self._ctx_menu.add_command(label="Copy Source IP",      command=self._ctx_copy_src)
        self._ctx_menu.add_command(label="Copy Destination IP", command=self._ctx_copy_dst)
        self._ctx_menu.add_command(label="Copy Info",           command=self._ctx_copy_info)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Filter by Protocol",  command=self._ctx_filter_proto)
        self._ctx_menu.add_command(label="Filter by Source IP", command=self._ctx_filter_src)
        self._ctx_menu.add_command(label="Filter by Dest IP",   command=self._ctx_filter_dst)

    def _build_detail_pane(self, parent):
        frame = ttk.LabelFrame(parent, text="Packet Details", padding=2)
        parent.add(frame, weight=1)

        self.detail_tree = ttk.Treeview(frame, show="tree", selectmode="browse")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.detail_tree.yview)
        self.detail_tree.configure(yscrollcommand=vsb.set)
        self.detail_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_hex_pane(self, parent):
        frame = ttk.LabelFrame(parent, text="Packet Bytes (Hex Dump)", padding=2)
        parent.add(frame, weight=1)

        self.hex_text = tk.Text(
            frame, font=("Consolas", 9),
            bg="#1e1e1e", fg="#d4d4d4",
            insertbackground="#ffffff",
            state="disabled", wrap="none", relief="flat")

        vsb = ttk.Scrollbar(frame, orient="vertical",   command=self.hex_text.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal",  command=self.hex_text.xview)
        self.hex_text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.hex_text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self.hex_text.tag_configure("offset",    foreground="#569cd6")
        self.hex_text.tag_configure("hex_bytes", foreground="#d4d4d4")
        self.hex_text.tag_configure("ascii",     foreground="#9cdcfe")
        self.hex_text.tag_configure("sep",       foreground="#555555")

    # ── Status bar ────────────────────────────────────────────────────────────

    def _build_statusbar(self):
        ttk.Separator(self, orient="horizontal").pack(fill=tk.X, side=tk.BOTTOM)
        sb = ttk.Frame(self, style="Status.TFrame", padding=(4, 2))
        sb.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_lbl    = ttk.Label(sb, text="Ready",     style="Status.TLabel", width=30)
        self.pkt_count_lbl = ttk.Label(sb, text="Pkts: 0",   style="Status.TLabel", width=10)
        self.bytes_lbl     = ttk.Label(sb, text="Bytes: 0",  style="Status.TLabel", width=16)
        self.dur_lbl       = ttk.Label(sb, text="Time: 0s",  style="Status.TLabel", width=12)
        self.filt_lbl      = ttk.Label(sb, text="",          style="Status.TLabel")
        self.proto_lbl     = ttk.Label(sb, text="",          style="Status.TLabel")
        self.iface_lbl     = ttk.Label(sb, text="Iface: —",  style="Status.TLabel", width=22)

        sep = lambda: ttk.Separator(sb, orient="vertical")
        for w in (self.status_lbl, sep(), self.pkt_count_lbl, sep(), self.bytes_lbl,
                  sep(), self.dur_lbl, sep(), self.filt_lbl):
            w.pack(side=tk.LEFT, padx=4, fill=tk.Y) if isinstance(w, ttk.Separator) else w.pack(side=tk.LEFT, padx=6)

        self.iface_lbl.pack(side=tk.RIGHT, padx=6)
        sep().pack(side=tk.RIGHT, fill=tk.Y)
        self.proto_lbl.pack(side=tk.RIGHT, padx=6)

    # ── Interfaces ────────────────────────────────────────────────────────────

    def _load_interfaces(self):
        if not SCAPY_AVAILABLE:
            self.iface_combo["values"] = ["(Scapy not installed)"]
            return
        try:
            ifaces = get_if_list()
            self.iface_combo["values"] = ifaces
            if ifaces:
                self.iface_var.set(ifaces[0])
        except Exception:
            self.iface_combo["values"] = ["(Error loading interfaces)"]

    def _show_iface_dialog(self):
        if not SCAPY_AVAILABLE:
            return
        try:
            ifaces = get_if_list()
        except Exception:
            return
        win = tk.Toplevel(self)
        win.title("Capture Interfaces")
        win.geometry("480x300")
        ttk.Label(win, text="Select a network interface to capture on:",
                  font=("Segoe UI", 10, "bold")).pack(pady=10)
        lb = tk.Listbox(win, font=("Consolas", 9), selectmode=tk.SINGLE)
        for iface in ifaces:
            lb.insert("end", iface)
        lb.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)
        def _select():
            sel = lb.curselection()
            if sel:
                self.iface_var.set(ifaces[sel[0]])
                self.iface_lbl.configure(text=f"Iface: {ifaces[sel[0]][:20]}")
                win.destroy()
        ttk.Button(win, text="Select", command=_select).pack(pady=6)

    # ── Capture ───────────────────────────────────────────────────────────────

    def _start_capture(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Missing Dependency",
                "Scapy is not installed.\nRun:  pip install scapy\n"
                "Also install Npcap from npcap.com (Windows).")
            return
        if self.sniffing:
            return
        iface = self.iface_var.get()
        if not iface or iface.startswith("("):
            messagebox.showwarning("No Interface", "Please select a valid network interface.")
            return
        bpf = self.cap_filter_var.get().strip() or None
        try:
            self.sniffing = True
            self.capture_start = time.time()
            self.sniffer = AsyncSniffer(iface=iface, filter=bpf,
                                        prn=self._packet_callback, store=False)
            self.sniffer.start()
            self.btn_start.configure(state="disabled")
            self.btn_stop.configure(state="normal")
            self.capture_dot.configure(text="  ●  Capturing", foreground="#00aa00")
            self.status_lbl.configure(text=f"Capturing on {iface[:28]}...")
            self.iface_lbl.configure(text=f"Iface: {iface[:20]}")
            self._tick_duration()
        except Exception as e:
            self.sniffing = False
            messagebox.showerror("Capture Error",
                f"Could not start capture:\n{e}\n\n"
                "Ensure Npcap is installed and you have Administrator privileges.")

    def _stop_capture(self):
        if not self.sniffing:
            return
        self.sniffing = False
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.capture_dot.configure(text="  ●  Stopped", foreground="#cc3300")
        self.status_lbl.configure(text=f"Stopped — {self.packet_count} packets captured")

    def _restart_capture(self):
        self._stop_capture()
        self._clear_packets()
        self.after(300, self._start_capture)

    def _toggle_capture(self):
        (self._stop_capture if self.sniffing else self._start_capture)()

    def _clear_packets(self):
        self.packets.clear()
        self.packet_count = 0
        self.total_bytes = 0
        for iid in self.pkt_tree.get_children():
            self.pkt_tree.delete(iid)
        self._clear_detail_views()
        self._update_counters()

    # ── Packet callback (sniffer thread) ──────────────────────────────────────

    def _packet_callback(self, pkt):
        try:
            idx = len(self.packets)
            self.packets.append(pkt)
            proto = PacketAnalyzer.get_protocol(pkt)
            src, dst = PacketAnalyzer.get_endpoints(pkt)
            info = PacketAnalyzer.get_info(pkt, proto)
            pkt_len = len(bytes(pkt))
            ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
            rel = ts - (self.capture_start or ts)
            self.packet_queue.put({
                "idx": idx, "proto": proto, "src": src, "dst": dst,
                "info": info, "len": pkt_len, "time": f"{rel:.6f}",
            })
        except Exception:
            pass

    # ── Queue processor (main thread) ─────────────────────────────────────────

    def _process_queue(self):
        try:
            processed = 0
            while processed < 60:
                d = self.packet_queue.get_nowait()
                self._insert_row(d)
                processed += 1
        except queue.Empty:
            pass
        finally:
            self.after(100, self._process_queue)

    def _insert_row(self, d):
        self.packet_count += 1
        self.total_bytes  += d["len"]

        proto = d["proto"]
        tag   = proto.lower() if proto.lower() in KNOWN_TAGS else "other"

        filt = self.disp_filter_var.get().strip()
        if filt and not self._matches_filter(d, filt):
            return

        iid = str(d["idx"])
        self.pkt_tree.insert("", "end", iid=iid,
            values=(self.packet_count, d["time"], d["src"], d["dst"],
                    proto, d["len"], d["info"]),
            tags=(tag,))
        if self.autoscroll_var.get():
            self.pkt_tree.see(iid)
        self._update_counters()

    # ── Display filter ────────────────────────────────────────────────────────

    def _matches_filter(self, d, filt):
        f = filt.lower().strip()
        proto_l = d["proto"].lower()

        if f in KNOWN_TAGS:
            return proto_l == f

        for prefix, field in (("ip.src==", "src"), ("ip.src ==", "src"),
                               ("ip.dst==", "dst"), ("ip.dst ==", "dst")):
            if f.startswith(prefix):
                return d[field] == filt.split("==", 1)[-1].strip()

        if f.startswith("ip.addr==") or f.startswith("ip.addr =="):
            addr = filt.split("==", 1)[-1].strip()
            return addr in (d["src"], d["dst"])

        needle = f.strip("\"'")
        return any(needle in str(v).lower()
                   for v in (d["src"], d["dst"], d["proto"], d["info"]))

    def _apply_display_filter(self):
        filt = self.disp_filter_var.get().strip()
        for iid in self.pkt_tree.get_children():
            self.pkt_tree.delete(iid)

        shown = 0
        for idx, pkt in enumerate(self.packets):
            proto = PacketAnalyzer.get_protocol(pkt)
            src, dst = PacketAnalyzer.get_endpoints(pkt)
            info = PacketAnalyzer.get_info(pkt, proto)
            pkt_len = len(bytes(pkt))
            ts = float(pkt.time) if hasattr(pkt, "time") else 0.0
            rel = ts - (self.capture_start or ts)
            d = {"idx": idx, "proto": proto, "src": src, "dst": dst,
                 "info": info, "len": pkt_len, "time": f"{rel:.6f}"}
            if filt and not self._matches_filter(d, filt):
                continue
            tag = proto.lower() if proto.lower() in KNOWN_TAGS else "other"
            self.pkt_tree.insert("", "end", iid=str(idx),
                values=(idx + 1, d["time"], src, dst, proto, pkt_len, info),
                tags=(tag,))
            shown += 1

        self.filt_lbl.configure(
            text=f"Filter: '{filt}'  ({shown}/{len(self.packets)} pkts)" if filt
            else f"")

    def _clear_display_filter(self):
        self.disp_filter_var.set("")
        self._apply_display_filter()

    def _quick_filter(self, expr):
        self.disp_filter_var.set(expr)
        self._apply_display_filter()

    # ── Packet selection & detail views ──────────────────────────────────────

    def _on_packet_selected(self, _event):
        sel = self.pkt_tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if idx >= len(self.packets):
            return
        pkt = self.packets[idx]
        self._populate_detail_tree(pkt)
        self._populate_hex_dump(pkt)

    def _populate_detail_tree(self, pkt):
        for iid in self.detail_tree.get_children():
            self.detail_tree.delete(iid)
        nodes = PacketAnalyzer.build_detail_nodes(pkt)
        parent_stack = {-1: ""}
        for level, open_flag, text in nodes:
            parent = parent_stack.get(level - 1, "")
            iid = self.detail_tree.insert(parent, "end", text=text, open=open_flag)
            parent_stack[level] = iid
            for l in [k for k in parent_stack if k > level]:
                del parent_stack[l]

    def _populate_hex_dump(self, pkt):
        self.hex_text.configure(state="normal")
        self.hex_text.delete("1.0", "end")
        for offset, hex_str, ascii_str in PacketAnalyzer.get_hex_dump(pkt):
            self.hex_text.insert("end", f"{offset:04x}  ", "offset")
            self.hex_text.insert("end", hex_str,           "hex_bytes")
            self.hex_text.insert("end", "  ",              "sep")
            self.hex_text.insert("end", ascii_str,         "ascii")
            self.hex_text.insert("end", "\n")
        self.hex_text.configure(state="disabled")

    def _clear_detail_views(self):
        for iid in self.detail_tree.get_children():
            self.detail_tree.delete(iid)
        self.hex_text.configure(state="normal")
        self.hex_text.delete("1.0", "end")
        self.hex_text.configure(state="disabled")

    # ── Context menu ──────────────────────────────────────────────────────────

    def _show_ctx_menu(self, event):
        iid = self.pkt_tree.identify_row(event.y)
        if iid:
            self.pkt_tree.selection_set(iid)
            self._context_iid = iid
            self._ctx_menu.tk_popup(event.x_root, event.y_root)

    def _ctx_vals(self):
        if self._context_iid:
            return self.pkt_tree.item(self._context_iid)["values"]
        return None

    def _ctx_copy_src(self):
        v = self._ctx_vals()
        if v:
            self.clipboard_clear(); self.clipboard_append(str(v[2]))

    def _ctx_copy_dst(self):
        v = self._ctx_vals()
        if v:
            self.clipboard_clear(); self.clipboard_append(str(v[3]))

    def _ctx_copy_info(self):
        v = self._ctx_vals()
        if v:
            self.clipboard_clear(); self.clipboard_append(str(v[6]))

    def _ctx_filter_proto(self):
        v = self._ctx_vals()
        if v:
            self.disp_filter_var.set(str(v[4]).lower())
            self._apply_display_filter()

    def _ctx_filter_src(self):
        v = self._ctx_vals()
        if v:
            self.disp_filter_var.set(f"ip.src=={v[2]}")
            self._apply_display_filter()

    def _ctx_filter_dst(self):
        v = self._ctx_vals()
        if v:
            self.disp_filter_var.set(f"ip.dst=={v[3]}")
            self._apply_display_filter()

    # ── Statistics ────────────────────────────────────────────────────────────

    def _show_stats(self):
        if not self.packets:
            messagebox.showinfo("No Data", "No packets captured yet.")
            return
        StatsWindow(self, self.packets)

    def _update_counters(self):
        counts = defaultdict(int)
        for pkt in self.packets:
            counts[PacketAnalyzer.get_protocol(pkt)] += 1
        self.pkt_count_lbl.configure(text=f"Pkts: {self.packet_count}")
        self.bytes_lbl.configure(text=f"Bytes: {self.total_bytes:,}")
        self.proto_lbl.configure(
            text=f"TCP:{counts['TCP']}  UDP:{counts['UDP']}  "
                 f"ICMP:{counts['ICMP']}  DNS:{counts['DNS']}  "
                 f"ARP:{counts['ARP']}  Other:{counts['Other']}")

    def _tick_duration(self):
        if self.sniffing and self.capture_start:
            e = int(time.time() - self.capture_start)
            self.dur_lbl.configure(text=f"Time: {e}s")
            self.after(1000, self._tick_duration)

    # ── Column sorting ────────────────────────────────────────────────────────

    def _sort_column(self, col):
        rev = self._sort_reverse.get(col, False)
        items = [(self.pkt_tree.set(k, col), k) for k in self.pkt_tree.get_children("")]
        try:
            items.sort(key=lambda t: float(t[0]), reverse=rev)
        except ValueError:
            items.sort(key=lambda t: t[0].lower(), reverse=rev)
        for i, (_, k) in enumerate(items):
            self.pkt_tree.move(k, "", i)
        self._sort_reverse[col] = not rev
        arrow = " ▲" if not rev else " ▼"
        hdrs = {"no": "No.", "time": "Time", "src": "Source", "dst": "Destination",
                "proto": "Protocol", "len": "Length", "info": "Info"}
        self.pkt_tree.heading(col, text=hdrs.get(col, col) + arrow)

    # ── Zoom ──────────────────────────────────────────────────────────────────

    def _zoom(self, direction):
        cur = int(self.style.lookup("Treeview", "font", default="Consolas 9").split()[-1])
        if direction == 0:
            sz = 9
        elif direction == 1:
            sz = min(cur + 1, 16)
        else:
            sz = max(cur - 1, 7)
        self.style.configure("Treeview", font=("Consolas", sz), rowheight=sz + 10)
        self.hex_text.configure(font=("Consolas", sz))
        self.detail_tree.configure(style="Treeview")

    # ── File I/O ──────────────────────────────────────────────────────────────

    def _open_pcap(self):
        path = filedialog.askopenfilename(
            title="Open Capture File",
            filetypes=[("PCAP/PCAPng", "*.pcap *.pcapng"), ("All files", "*.*")])
        if not path:
            return
        try:
            self._clear_packets()
            pkts = rdpcap(path)
            if pkts:
                self.capture_start = float(pkts[0].time)
            for pkt in pkts:
                proto = PacketAnalyzer.get_protocol(pkt)
                src, dst = PacketAnalyzer.get_endpoints(pkt)
                info = PacketAnalyzer.get_info(pkt, proto)
                pkt_len = len(bytes(pkt))
                rel = float(pkt.time) - (self.capture_start or 0)
                idx = len(self.packets)
                self.packets.append(pkt)
                self.packet_count += 1
                self.total_bytes  += pkt_len
                tag = proto.lower() if proto.lower() in KNOWN_TAGS else "other"
                self.pkt_tree.insert("", "end", iid=str(idx),
                    values=(idx + 1, f"{rel:.6f}", src, dst, proto, pkt_len, info),
                    tags=(tag,))
            self._update_counters()
            self.status_lbl.configure(
                text=f"Opened {os.path.basename(path)}  ({len(pkts)} pkts)")
        except Exception as e:
            messagebox.showerror("Open Error", f"Could not open file:\n{e}")

    def _save_pcap(self):
        if not self.packets:
            messagebox.showinfo("Nothing to Save", "No packets to save.")
            return
        path = filedialog.asksaveasfilename(
            title="Save Capture As",
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if not path:
            return
        try:
            wrpcap(path, self.packets)
            self.status_lbl.configure(
                text=f"Saved {len(self.packets)} pkts → {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def _export_csv(self):
        if not self.packets:
            messagebox.showinfo("Nothing to Export", "No packets to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export as CSV", defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["No.", "Time", "Source", "Destination",
                             "Protocol", "Length", "Info"])
                for iid in self.pkt_tree.get_children():
                    w.writerow(self.pkt_tree.item(iid)["values"])
            self.status_lbl.configure(text=f"Exported CSV → {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _export_json(self):
        if not self.packets:
            messagebox.showinfo("Nothing to Export", "No packets to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export as JSON", defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            rows = []
            for iid in self.pkt_tree.get_children():
                v = self.pkt_tree.item(iid)["values"]
                rows.append({"no": v[0], "time": v[1], "source": v[2],
                              "destination": v[3], "protocol": v[4],
                              "length": v[5], "info": v[6]})
            with open(path, "w", encoding="utf-8") as f:
                json.dump(rows, f, indent=2)
            self.status_lbl.configure(text=f"Exported JSON → {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def _on_close(self):
        self._stop_capture()
        self.destroy()


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    app = PySharkApp()
    app.mainloop()


if __name__ == "__main__":
    main()
