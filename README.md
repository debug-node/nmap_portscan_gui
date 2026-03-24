# Network Port Scanner GUI

A lightweight, fast TCP port scanner with a graphical user interface built with Python and Tkinter.

## Features

- **Advanced GUI** – customizable scanner settings with intuitive controls
- **Multi-threaded scanning** – configurable concurrent threads (10-1000) for optimal speed
- **Adjustable timeout** – control connection timeout (0.1-5.0 seconds)
- **Service identification** – automatically identifies 13+ well-known services
- **Real-time progress** – live progress bar, scan speed, and ETA
- **Multiple export formats** – save results as TXT, JSON, or CSV
- **Auto-save feature** – results automatically saved to `results/` folder with timestamp
- **Stop functionality** – gracefully cancel scanning at any time
- **Cross-platform** – works on Windows, macOS, and Linux

## Requirements

- Python 3.7 or newer
- Tkinter (included by default; on Debian/Ubuntu install `python3-tk`)

No third-party packages required!

## Installation

```bash
git clone https://github.com/debug-node/nmap_portscan_gui.git
cd nmap_portscan_gui
python portscanergui.py
```

## Usage

1. **Enter Target** – IP address (e.g., `192.168.1.1`) or hostname (e.g., `scanme.nmap.org`)
2. **Set Port Range** – Start Port and End Port (default: 1-1024)
3. **Configure Settings** (optional):
   - **Timeout** – connection timeout in seconds (default: 0.5s)
   - **Max Workers** – maximum concurrent threads (default: 500)
   - **Export Format** – TXT, JSON, or CSV (default: TXT)
4. **Click "▶ Start Scan"** – scanning begins immediately
5. **Monitor Progress** – watch real-time results, speed, and ETA
6. **Click "⏹ Stop"** – gracefully stop the scan
7. **Click "💾 Save Results"** – export to `results/` folder

## Supported Services

| Port | Service    | Port | Service  |
|------|-----------|------|----------|
| 21   | FTP       | 443  | HTTPS    |
| 22   | SSH       | 3306 | MySQL    |
| 23   | Telnet    | 3389 | RDP      |
| 25   | SMTP      | 5900 | VNC      |
| 53   | DNS       | 8080 | HTTP-Alt |
| 80   | HTTP      |      |          |
| 110  | POP3      |      |          |
| 143  | IMAP      |      |          |

## Output Formats

### TXT (Plain Text)
```
=== Network Port Scan Results ===
Target: 192.168.1.1
Scan Time: 2026-03-24 14:30:45
Total Open Ports: 3
========================================

Port    22 - SSH
Port    80 - HTTP
Port   443 - HTTPS
```

### JSON
```json
{
  "target": "192.168.1.1",
  "scan_time": "2026-03-24 14:30:45",
  "total_ports": 3,
  "open_ports": [
    {"port": 22, "service": "SSH"},
    {"port": 80, "service": "HTTP"},
    {"port": 443, "service": "HTTPS"}
  ]
}
```

### CSV
```
Port,Service
22,SSH
80,HTTP
443,HTTPS
```

## Project Structure

```
nmap_portscan_gui/
├── portscanergui.py          # Main GUI application
├── README.md                 # This file
└── results/                  # Auto-generated folder for scan results
    ├── scan_20260324_143056.txt
    ├── scan_20260324_143102.json
    └── scan_20260324_143145.csv
```

## Performance Tips

- **Increase Max Workers** for faster scanning (but may trigger firewall rate limiting)
- **Decrease Timeout** for quicker results on responsive networks
- **Decrease Port Range** for faster scans (e.g., scan common ports: 1-1000)
- **Use localhost (127.0.0.1)** for testing without network latency

## Legal Notice

⚠️ **This tool should only be used on networks you own or have explicit permission to scan.** Unauthorized port scanning may be illegal in your jurisdiction.

## License

Open Source - Free to use and modify

## Author

Security enthusiast – Cyber Security Project
