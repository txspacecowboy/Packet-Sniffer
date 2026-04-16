# Network Analyzer

A basic network packet sniffer built with Python and Scapy.

## Features

- Capture network packets
- Packet filtering using BPF
- Basic statistics (packet count, protocol distribution)
- Protocol analysis (TCP, UDP, ICMP details)
- Command-line interface with options

## Requirements

- Python 3.x
- Scapy library
- Npcap (for Windows raw packet access)

## Installation

1. Install Python 3.x from [python.org](https://www.python.org/downloads/) or Microsoft Store.
2. Install Npcap from [npcap.com](https://npcap.com/).
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the script with options:

```
python src/network_analyzer.py [options]
```

Options:
- `-i, --interface`: Specify network interface (e.g., `Ethernet`)
- `-f, --filter`: BPF filter (e.g., `tcp port 80`)
- `-c, --count`: Number of packets to capture (default: 10)

Examples:
- Capture 10 packets on default interface: `python src/network_analyzer.py`
- Filter HTTP traffic: `python src/network_analyzer.py -f "tcp port 80"`
- Capture on specific interface: `python src/network_analyzer.py -i "Wi-Fi"`

Note: May require administrator privileges.

## Future Enhancements

- Real-time statistics
- GUI interface
- Packet saving/export