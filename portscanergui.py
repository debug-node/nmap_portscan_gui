import socket
import threading
import time
import queue
import sys
import json
import csv
import os
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox

# ---------------------------
# Service Map (extend freely)
# ---------------------------
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
}

# ---------------------------
# Scanner Worker
# ---------------------------
class PortScanner:
    """
    Multi-threaded port scanner for TCP connections.
    
    Attributes:
        target (str): IP address or hostname to scan
        start_port (int): Starting port number
        end_port (int): Ending port number
        timeout (float): Socket timeout in seconds (default: 0.5)
        max_workers (int): Maximum concurrent threads (default: 500)
    """
    
    def __init__(self, target, start_port, end_port, timeout=0.5, max_workers=500):
        """Initialize the port scanner with target and configuration."""
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_workers = max_workers
        self._stop_event = threading.Event()

        self.total_ports = max(0, end_port - start_port + 1)
        self.scanned_count = 0
        self.open_ports = []            # list[(port, service)]
        self._lock = threading.Lock()
        self.result_queue = queue.Queue()
        self.start_time = None          # Track scan duration
        self.scan_speed = 0             # Ports per second

    def stop(self):
        """Signal the scanner to stop all scanning threads."""
        self._stop_event.set()

    def _scan_port(self, port):
        """
        Scan a single port for TCP connectivity.
        
        Args:
            port (int): Port number to scan
        """
        if self._stop_event.is_set():
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                with self._lock:
                    self.open_ports.append((port, service))
                self.result_queue.put(('open', port, service))
            s.close()
        except Exception:
            pass  # Silently ignore errors (connection refused, timeouts, etc.)
        finally:
            with self._lock:
                self.scanned_count += 1
                # Calculate scanning speed
                if self.start_time:
                    elapsed = time.time() - self.start_time
                    if elapsed > 0:
                        self.scan_speed = self.scanned_count / elapsed
            self.result_queue.put(('progress', self.scanned_count, self.total_ports))

    def resolve_target(self):
        """Resolve hostname to IP address."""
        return socket.gethostbyname(self.target)

    def run(self):
        """Execute the port scanning process with thread pool."""
        self.start_time = time.time()  # Track scan duration
        sem = threading.Semaphore(self.max_workers)
        threads = []

        for port in range(self.start_port, self.end_port + 1):
            if self._stop_event.is_set():
                break
            sem.acquire()
            t = threading.Thread(target=self._worker_wrapper, args=(sem, port), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.result_queue.put(('done', None, None))

    def _worker_wrapper(self, sem, port):
        """Worker thread wrapper for resource management."""
        try:
            self._scan_port(port)
        finally:
            sem.release()

# ---------------------------
# Tkinter GUI (with advanced settings)
# ---------------------------
class ScannerGUI(tk.Tk):
    """
    Advanced GUI for network port scanning.
    Features: Multi-threaded scanning, customizable settings, export options.
    """
    
    def __init__(self):
        super().__init__()
        self.title("Network Port Scanner - Advanced GUI")
        self.geometry("800x600")
        self.minsize(750, 550)

        self.scanner_thread = None
        self.scanner = None
        self.start_time = None
        self.poll_after_ms = 40
        
        # Settings with defaults
        self.var_timeout = tk.DoubleVar(value=0.5)
        self.var_workers = tk.IntVar(value=500)
        self.var_export_format = tk.StringVar(value="txt")

        self._build_ui()

    def _build_ui(self):
        """Build the complete user interface."""
        # === SETTINGS FRAME ===
        frm_settings = ttk.LabelFrame(self, text="Scanner Settings")
        frm_settings.pack(fill="x", padx=10, pady=10)

        # Row 1: Target, Start Port, End Port
        ttk.Label(frm_settings, text="Target (IP/Hostname):").grid(row=0, column=0, padx=8, pady=8, sticky="e")
        self.ent_target = ttk.Entry(frm_settings, width=30)
        self.ent_target.grid(row=0, column=1, padx=8, pady=8, sticky="w")

        ttk.Label(frm_settings, text="Start Port:").grid(row=0, column=2, padx=8, pady=8, sticky="e")
        self.ent_start = ttk.Entry(frm_settings, width=10)
        self.ent_start.insert(0, "1")
        self.ent_start.grid(row=0, column=3, padx=8, pady=8, sticky="w")

        ttk.Label(frm_settings, text="End Port:").grid(row=0, column=4, padx=8, pady=8, sticky="e")
        self.ent_end = ttk.Entry(frm_settings, width=10)
        self.ent_end.insert(0, "1024")
        self.ent_end.grid(row=0, column=5, padx=8, pady=8, sticky="w")

        # Row 2: Advanced Settings (Timeout, Max Workers)
        ttk.Label(frm_settings, text="Timeout (sec):").grid(row=1, column=0, padx=8, pady=8, sticky="e")
        spn_timeout = ttk.Spinbox(frm_settings, from_=0.1, to=5.0, textvariable=self.var_timeout, width=8)
        spn_timeout.grid(row=1, column=1, padx=8, pady=8, sticky="w")

        ttk.Label(frm_settings, text="Max Workers:").grid(row=1, column=2, padx=8, pady=8, sticky="e")
        spn_workers = ttk.Spinbox(frm_settings, from_=10, to=1000, textvariable=self.var_workers, width=8)
        spn_workers.grid(row=1, column=3, padx=8, pady=8, sticky="w")

        ttk.Label(frm_settings, text="Export as:").grid(row=1, column=4, padx=8, pady=8, sticky="e")
        combo_export = ttk.Combobox(frm_settings, textvariable=self.var_export_format, 
                                     values=["txt", "json", "csv"], width=8, state="readonly")
        combo_export.grid(row=1, column=5, padx=8, pady=8, sticky="w")

        # Row 3: Control Buttons
        self.btn_start = ttk.Button(frm_settings, text="▶ Start Scan", command=self.start_scan)
        self.btn_start.grid(row=2, column=3, padx=8, pady=8, sticky="ew")

        self.btn_stop = ttk.Button(frm_settings, text="⏹ Stop", command=self.stop_scan, state="disabled")
        self.btn_stop.grid(row=2, column=4, padx=8, pady=8, sticky="ew")

        for i in range(6):
            frm_settings.grid_columnconfigure(i, weight=1)

        # === STATUS FRAME ===
        frm_status = ttk.LabelFrame(self, text="Status")
        frm_status.pack(fill="x", padx=10, pady=(0, 10))

        self.var_status = tk.StringVar(value="Idle")
        self.lbl_status = ttk.Label(frm_status, textvariable=self.var_status, font=("Arial", 10, "bold"))
        self.lbl_status.pack(side="left", padx=10, pady=8)

        self.var_details = tk.StringVar(value="")
        self.lbl_details = ttk.Label(frm_status, textvariable=self.var_details, foreground="gray")
        self.lbl_details.pack(side="left", padx=20, pady=8)

        self.var_elapsed = tk.StringVar(value="Elapsed: 0.00s | Speed: 0 p/s | ETA: --:--")
        self.lbl_elapsed = ttk.Label(frm_status, textvariable=self.var_elapsed, font=("Arial", 9))
        self.lbl_elapsed.pack(side="right", padx=10, pady=8)

        self.progress = ttk.Progressbar(frm_status, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(0, 10))

        # === RESULTS FRAME ===
        frm_results = ttk.LabelFrame(self, text="Open Ports")
        frm_results.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.txt_results = tk.Text(frm_results, height=16, wrap="none", font=("Courier", 9))
        self.txt_results.pack(fill="both", expand=True, side="left", padx=(10, 0), pady=10)

        yscroll = ttk.Scrollbar(frm_results, orient="vertical", command=self.txt_results.yview)
        yscroll.pack(side="right", fill="y", pady=10)
        self.txt_results.configure(yscrollcommand=yscroll.set)

        xscroll = ttk.Scrollbar(self, orient="horizontal", command=self.txt_results.xview)
        xscroll.pack(fill="x", padx=10, pady=(0, 10))
        self.txt_results.configure(xscrollcommand=xscroll.set)

        # === BOTTOM BUTTONS ===
        frm_bottom = ttk.Frame(self)
        frm_bottom.pack(fill="x", padx=10, pady=(0, 12))

        self.btn_clear = ttk.Button(frm_bottom, text="Clear Results", command=self.clear_results)
        self.btn_clear.pack(side="left", padx=5)

        self.btn_save = ttk.Button(frm_bottom, text="💾 Save Results", command=self.save_results, state="disabled")
        self.btn_save.pack(side="right", padx=5)

    # -----------------------
    # Control Handlers
    # -----------------------
    def start_scan(self):
        """Validate inputs and start the port scanning process."""
        if self.scanner_thread and self.scanner_thread.is_alive():
            messagebox.showinfo("Scanner", "A scan is already running.")
            return

        target = self.ent_target.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a target IP or hostname.")
            return

        try:
            start_port = int(self.ent_start.get().strip())
            end_port = int(self.ent_end.get().strip())
        except ValueError:
            messagebox.showerror("Input Error", "Ports must be integers.")
            return

        if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port):
            messagebox.showerror("Input Error", "Port range must be within 0–65535 and start ≤ end.")
            return

        # Get settings from UI
        timeout = self.var_timeout.get()
        max_threads = self.var_workers.get()

        # Validate settings
        if timeout < 0.1 or timeout > 5.0:
            messagebox.showerror("Settings Error", "Timeout must be between 0.1 and 5.0 seconds.")
            return
        
        if max_threads < 10 or max_threads > 1000:
            messagebox.showerror("Settings Error", "Max workers must be between 10 and 1000.")
            return

        self.scanner = PortScanner(target, start_port, end_port, timeout=timeout, max_workers=max_threads)

        # Pre-resolve target to catch DNS issues early
        try:
            resolved_ip = self.scanner.resolve_target()
            self.append_text(f"Target: {target} ({resolved_ip})\n")
            self.append_text(f"Range: {start_port}-{end_port} | Timeout: {timeout}s | Workers: {max_threads}\n")
            self.append_text(f"Export Format: {self.var_export_format.get().upper()}\n")
            self.append_text("-" * 60 + "\n\n")
        except socket.gaierror:
            messagebox.showerror("Resolution Error", f"Failed to resolve target '{target}'.\nPlease check the hostname or IP address.")
            self.scanner = None
            return
        except Exception as e:
            messagebox.showerror("Error", f"Connection error: {e}")
            self.scanner = None
            return

        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.clear_progress()

        self.start_time = time.time()
        self.var_status.set("🔄 Scanning...")
        self.var_details.set("")
        self.update_elapsed()

        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()

        self.after(self.poll_after_ms, self.poll_results)

    def stop_scan(self):
        """Signal the scanner to stop gracefully."""
        if self.scanner:
            self.scanner.stop()
            self.var_status.set("⏸ Stopping...")

    def clear_results(self):
        """Clear all results and reset UI to idle state."""
        self.txt_results.delete("1.0", tk.END)
        self.clear_progress()
        self.var_status.set("✓ Idle")
        self.var_details.set("")
        self.var_elapsed.set("Elapsed: 0.00s | Speed: 0 p/s | ETA: --:--")
        self.btn_save.configure(state="disabled")

    def save_results(self):
        """Save scan results directly to results folder without dialog."""
        if not self.scanner or not self.scanner.open_ports:
            messagebox.showinfo("Save Results", "No open ports to save.")
            return

        export_format = self.var_export_format.get()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_dir = os.path.join(os.path.dirname(__file__), "results")
        
        # Create results directory if it doesn't exist
        os.makedirs(results_dir, exist_ok=True)
        
        filename = f"scan_{timestamp}.{export_format}"
        file_path = os.path.join(results_dir, filename)

        try:
            sorted_ports = sorted(self.scanner.open_ports, key=lambda x: x[0])
            
            if export_format == "txt":
                self._save_as_txt(file_path, sorted_ports)
            elif export_format == "json":
                self._save_as_json(file_path, sorted_ports)
            elif export_format == "csv":
                self._save_as_csv(file_path, sorted_ports)
            
            messagebox.showinfo("✅ Saved Successfully", f"Results saved to:\nresults/{filename}")
            self.append_text(f"\n💾 Saved to: results/{filename}\n")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save file.\n{e}")

    def _save_as_txt(self, file_path, ports):
        """Export results as plain text."""
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("=== Network Port Scan Results ===\n")
            f.write(f"Target: {self.scanner.target}\n")
            f.write(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Open Ports: {len(ports)}\n")
            f.write("=" * 40 + "\n\n")
            
            for port, service in ports:
                f.write(f"Port {port:5d} - {service}\n")

    def _save_as_json(self, file_path, ports):
        """Export results as JSON."""
        data = {
            "target": self.scanner.target,
            "scan_time": time.strftime('%Y-%m-%d %H:%M:%S'),
            "total_ports": len(ports),
            "open_ports": [{"port": port, "service": service} for port, service in ports]
        }
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _save_as_csv(self, file_path, ports):
        """Export results as CSV."""
        with open(file_path, "w", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Port", "Service"])
            for port, service in ports:
                writer.writerow([port, service])

    # -----------------------
    # UI Helpers
    # -----------------------
    def append_text(self, text):
        """Append text to results display and scroll to end."""
        self.txt_results.insert(tk.END, text)
        self.txt_results.see(tk.END)

    def clear_progress(self):
        """Reset progress bar."""
        self.progress.configure(value=0, maximum=1)

    def update_elapsed(self):
        """Update elapsed time, speed, and ETA display."""
        if self.start_time and self.var_status.get() in ("🔄 Scanning...", "⏸ Stopping..."):
            elapsed = time.time() - self.start_time
            
            # Calculate speed and ETA
            if self.scanner:
                speed = self.scanner.scan_speed if self.scanner.scanned_count > 0 else 0
                remaining = max(0, self.scanner.total_ports - self.scanner.scanned_count)
                
                if speed > 0:
                    eta_seconds = int(remaining / speed)
                    eta_str = f"{eta_seconds // 60}:{eta_seconds % 60:02d}"
                else:
                    eta_str = "--:--"
                
                self.var_elapsed.set(f"Elapsed: {elapsed:.2f}s | Speed: {speed:.1f} p/s | ETA: {eta_str}")
            else:
                self.var_elapsed.set(f"Elapsed: {elapsed:.2f}s | Speed: 0 p/s | ETA: --:--")
            
            self.after(200, self.update_elapsed)

    def poll_results(self):
        """Poll scanner queue for results and update UI."""
        if not self.scanner:
            return

        try:
            while True:
                msg_type, a, b = self.scanner.result_queue.get_nowait()
                if msg_type == 'open':
                    port, service = a, b
                    self.append_text(f"[✓] Port {port:5d} → {service}\n")
                elif msg_type == 'progress':
                    scanned, total = a, b
                    self.progress.configure(maximum=max(total, 1), value=scanned)
                    percent = int((scanned / max(total, 1)) * 100)
                    self.var_status.set(f"🔄 Scanning... {percent}% ({scanned}/{total})")
                    self.var_details.set(f"Found: {len(self.scanner.open_ports)} open port(s)")
                elif msg_type == 'done':
                    total_open = len(self.scanner.open_ports)
                    elapsed = time.time() - self.start_time if self.start_time else 0
                    self.append_text("\n" + "=" * 60 + "\n")
                    self.append_text(f"✅ Scan Complete!\n")
                    self.append_text(f"   Total Open Ports: {total_open}\n")
                    self.append_text(f"   Time Elapsed: {elapsed:.2f}s\n")
                    self.append_text("Click 'Save Results' to export\n")
                    self.var_status.set("✅ Completed")
                    self.var_details.set(f"Found {total_open} open port(s)")
                    self.btn_start.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
                    self.btn_save.configure(state="normal" if total_open else "disabled")
                    self.start_time = None
        except queue.Empty:
            pass

        if self.scanner_thread and self.scanner_thread.is_alive():
            self.after(self.poll_after_ms, self.poll_results)
        else:
            if self.var_status.get() in ("🔄 Scanning...", "⏸ Stopping..."):
                self.var_status.set("✅ Completed")
            self.btn_start.configure(state="normal")
            self.btn_stop.configure(state="disabled")

def main():
    """Launch the port scanner GUI application."""
    # Windows console nicety if launched from terminal
    if sys.platform.startswith("win"):
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-10), 7)
        except Exception:
            pass

    app = ScannerGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
