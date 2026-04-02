# coding: utf-8
import os
import sys
import time
import threading
import warnings
import joblib
import pandas as pd
import numpy as np
import ipaddress
from io import StringIO
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, Ether, ARP, conf, get_if_list, srp
from flow_state import FlowState

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.panel import Panel
from rich.columns import Columns
from rich.layout import Layout
from rich import box

# Suppress sklearn & scapy noise
warnings.filterwarnings("ignore")

# =============================
# LOAD MODEL
# =============================

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH  = os.path.join(BASE_DIR, "models", "network_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.pkl")

model  = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

# Silence sklearn forest verbosity
try:
    model.verbose = 0
    for est in getattr(model, "estimators_", []):
        est.verbose = 0
except Exception:
    pass

COLUMN_ORDER = list(scaler.feature_names_in_)

# =============================
# SETTINGS
# =============================

ATTACK_THRESHOLD = 0.90
FLOW_TIMEOUT     = 2        # seconds
DEVICE_ONLY_MODE = False    # False = full network
INTERFACE        = None     # None = auto-detect
REFRESH_RATE     = 1        # dashboard refresh (seconds)
ARP_RESCAN_SECS  = 60       # periodic ARP rescan interval
ARP_SCAN_SUBNET  = None     # None = auto from interface

# ── IP Filter Settings ───────────────────────────────────────
# True  = show karo  |  False = hide karo
SHOW_PRIVATE = True    # LAN IPs  (192.168.x.x, 10.x.x.x etc)
SHOW_PUBLIC  = True    # WAN IPs  (internet ke IPs)
# ─────────────────────────────────────────────────────────────

# =============================
# SHARED STATE
# =============================

flows          = {}
mac_table      = {}   # ip -> mac

# Per detected-IP traffic stats
ip_stats       = {}   # { ip: { mac, status, prob, port, proto, direction, last_seen, attacks, total } }

# ARP-discovered devices (full network map)
discovered     = {}   # { ip: { mac, first_seen, last_seen, status } }

console = Console()

# =============================
# UTILITIES
# =============================

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def should_ignore(src_ip, dst_ip):
    if dst_ip.startswith("224.") or dst_ip.startswith("239."):
        return True
    if dst_ip.endswith(".255") or dst_ip == "255.255.255.255":
        return True
    if DEVICE_ONLY_MODE and is_private(src_ip) and is_private(dst_ip):
        return True
    return False


def get_key(pkt):
    if IP not in pkt:
        return None
    ip    = pkt[IP]
    proto = ip.proto
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        sport, dport = 0, 0
    return (ip.src, ip.dst, sport, dport, proto)


def format_proto(proto):
    return {6: "TCP", 17: "UDP"}.get(proto, f"P{proto}")


def predict_silent(df):
    """Model prediction — joblib parallel verbose output completely suppress karo."""
    # Python-level redirect
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout = sys.stderr = StringIO()
    # OS file-descriptor level redirect (joblib writes here directly)
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    old_stderr_fd = os.dup(2)
    os.dup2(devnull_fd, 2)
    os.close(devnull_fd)
    try:
        scaled = scaler.transform(df)
        prob   = model.predict_proba(scaled)[0]
        return prob[1]
    finally:
        os.dup2(old_stderr_fd, 2)
        os.close(old_stderr_fd)
        sys.stdout, sys.stderr = old_out, old_err


def register_discovered(ip, mac, status="ONLINE"):
    now = datetime.now().strftime("%H:%M:%S")
    if ip not in discovered:
        discovered[ip] = {
            "mac"        : mac or "??:??:??:??:??:??",
            "first_seen" : now,
            "last_seen"  : now,
            "status"     : status,
        }
    else:
        discovered[ip]["last_seen"] = now
        discovered[ip]["status"]    = status
        if mac and mac != "??:??:??:??:??:??":
            discovered[ip]["mac"] = mac


# =============================
# ARP SCANNER
# =============================

def get_local_subnet(iface):
    try:
        from scapy.all import get_if_addr
        local_ip = get_if_addr(iface)
        if not local_ip or local_ip == "0.0.0.0":
            return None
        subnet = local_ip.rsplit(".", 1)[0] + ".0/24"
        return subnet, local_ip
    except Exception:
        return None


def arp_scan(subnet, iface):
    """ARP broadcast — live hosts discover karo. Silent (no print, updates state)."""
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = StringIO()
        try:
            answered, _ = srp(pkt, iface=iface, timeout=3, verbose=False)
        finally:
            sys.stdout, sys.stderr = old_out, old_err

        for _, rx in answered:
            register_discovered(rx.psrc, rx.hwsrc, "ONLINE")

    except Exception:
        pass


def periodic_arp_scan(subnet, iface, interval):
    while True:
        time.sleep(interval)
        arp_scan(subnet, iface)


# =============================
# DASHBOARD TABLES
# =============================

def build_unified_table():
    """
    Ek hi table mein:
      - Saare ARP-discovered devices (poora network)
      - Jo actually communicate kare unhe model prediction bhi
    """
    attack_count = sum(1 for v in ip_stats.values() if v["prob"] > ATTACK_THRESHOLD)

    t = Table(
        title=f"Network Devices  ({len(discovered)} discovered  |  {len(ip_stats)} active  |  {attack_count} attacks)",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
        title_style="bold white on dark_blue",
        expand=True,
    )

    t.add_column("#",         style="dim",       width=3,  justify="right")
    t.add_column("IP Address",                   width=16)
    t.add_column("MAC",       style="cyan",      width=19)
    t.add_column("Status",                       width=12, justify="center")
    t.add_column("Atk %",                        width=8,  justify="center")
    t.add_column("Port",                         width=7,  justify="center")
    t.add_column("Proto",                        width=6,  justify="center")
    t.add_column("Direction",                    width=10, justify="center")
    t.add_column("Attacks",  style="red bold",   width=7,  justify="center")
    t.add_column("Flows",    style="dim",        width=6,  justify="center")
    t.add_column("Last Seen",style="dim",        width=10, justify="center")

    # ARP-discovered IPs ko base banao, traffic wale overlay karo
    all_ips = set(discovered.keys()) | set(ip_stats.keys())

    # Sort: attacks first, then by IP
    def sort_key(ip):
        is_atk = ip_stats.get(ip, {}).get("prob", 0) > ATTACK_THRESHOLD
        has_traffic = ip in ip_stats
        try:
            parts = tuple(int(x) for x in ip.split("."))
        except Exception:
            parts = (999, 999, 999, 999)
        return (not is_atk, not has_traffic, parts)

    for idx, ip in enumerate(sorted(all_ips, key=sort_key), 1):
        stats    = ip_stats.get(ip, {})
        disc     = discovered.get(ip, {})
        mac      = stats.get("mac") or disc.get("mac", "??:??:??:??:??:??")
        last     = stats.get("last_seen") or disc.get("last_seen", "-")
        has_flow = bool(stats)
        is_atk   = stats.get("prob", 0) > ATTACK_THRESHOLD if has_flow else False

        if is_atk:
            status_txt = Text("ATTACK",     style="bold red on dark_red")
            prob_txt   = Text(f"{stats['prob']*100:.1f}%", style="bold red")
            ip_txt     = Text(ip,           style="bold red")
            row_style  = "on dark_red"
        elif has_flow:
            status_txt = Text("ACTIVE",     style="bold yellow")
            prob_txt   = Text(f"{stats['prob']*100:.1f}%", style="green")
            ip_txt     = Text(ip,           style="bold yellow")
            row_style  = ""
        else:
            status_txt = Text("DISCOVERED", style="dim white")
            prob_txt   = Text("-",          style="dim")
            ip_txt     = Text(ip,           style="white")
            row_style  = ""

        t.add_row(
            str(idx),
            ip_txt,
            mac,
            status_txt,
            prob_txt,
            str(stats.get("port",  "-")),
            stats.get("proto",     "-"),
            stats.get("direction", "-"),
            str(stats.get("attacks", "-")) if has_flow else "-",
            str(stats.get("total",   "-")) if has_flow else "-",
            last,
            style=row_style,
        )

    t.caption = (
        f"[yellow]ACTIVE[/] = traffic detected  |  "
        f"[dim]DISCOVERED[/] = ARP scan only  |  "
        f"[red]ATTACK[/] = threat detected  |  "
        f"Updated: {datetime.now().strftime('%H:%M:%S')}"
    )
    return t


def build_stats_panel():
    """Top summary panel."""
    total    = len(discovered)
    active   = len(ip_stats)
    attacks  = sum(1 for v in ip_stats.values() if v["prob"] > ATTACK_THRESHOLD)
    iface    = INTERFACE if INTERFACE else str(conf.iface)
    mode     = "Device-Only" if DEVICE_ONLY_MODE else "Full Network"
    now      = datetime.now().strftime("%H:%M:%S")

    text = (
        f"[bold cyan]Interface:[/] {iface}   "
        f"[bold cyan]Mode:[/] {mode}   "
        f"[bold cyan]Devices on LAN:[/] [bold white]{total}[/]   "
        f"[bold cyan]Active (traffic):[/] [bold yellow]{active}[/]   "
        f"[bold cyan]Attacks:[/] [bold red]{attacks}[/]   "
        f"[bold cyan]Time:[/] {now}"
    )
    return Panel(text, title="[bold white]Network IDS Dashboard[/]",
                 border_style="blue", padding=(0, 1))


def build_full_dashboard():
    """Combine all panels into one renderable."""
    from rich.console import Group
    return Group(
        build_stats_panel(),
        build_unified_table(),
    )


# =============================
# PACKET PROCESSOR
# =============================

def handle_arp_pkt(pkt):
    arp = pkt[ARP]
    if arp.psrc and arp.psrc != "0.0.0.0":
        register_discovered(arp.psrc, arp.hwsrc)
        mac_table[arp.psrc] = arp.hwsrc
    if arp.pdst and arp.pdst != "0.0.0.0" and arp.op == 2:
        register_discovered(arp.pdst, arp.hwdst)


def process_packet(pkt):
    # Passive ARP learning
    if ARP in pkt:
        handle_arp_pkt(pkt)
        return

    key = get_key(pkt)
    if key is None:
        return

    src_ip, dst_ip, sport, dport, proto = key

    if should_ignore(src_ip, dst_ip):
        return

    # MAC table
    if Ether in pkt:
        mac_table[src_ip] = pkt[Ether].src
        mac_table[dst_ip] = pkt[Ether].dst
        register_discovered(src_ip, pkt[Ether].src)
        register_discovered(dst_ip, pkt[Ether].dst)

    # Flow tracking
    if key not in flows:
        flows[key] = FlowState(key, pkt)
    else:
        flows[key].update(pkt)

    if flows[key].flow_duration() <= FLOW_TIMEOUT:
        return

    features = flows[key].build_basic_features()
    aligned  = {col: float(features.get(col, 0)) for col in COLUMN_ORDER}
    df       = pd.DataFrame([aligned])

    try:
        attack_prob = predict_silent(df)

        src_type   = "LAN" if is_private(src_ip) else "WAN"
        dst_type   = "LAN" if is_private(dst_ip) else "WAN"
        direction  = f"{src_type}->{dst_type}"
        proto_name = format_proto(proto)
        now_str    = datetime.now().strftime("%H:%M:%S")

        if src_ip not in ip_stats:
            ip_stats[src_ip] = {"attacks": 0, "total": 0}

        ip_stats[src_ip].update({
            "mac"       : mac_table.get(src_ip, "??:??:??:??:??:??"),
            "prob"      : attack_prob,
            "port"      : dport,
            "proto"     : proto_name,
            "direction" : direction,
            "last_seen" : now_str,
            "total"     : ip_stats[src_ip]["total"] + 1,
        })
        if attack_prob > ATTACK_THRESHOLD:
            ip_stats[src_ip]["attacks"] += 1

    except Exception:
        pass

    del flows[key]


# =============================
# STALE CLEANUP
# =============================

def cleanup_stale_flows():
    now   = time.time()
    stale = [k for k, v in flows.items() if (now - v.last_seen) > 30]
    for k in stale:
        del flows[k]


# =============================
# MAIN
# =============================

if __name__ == "__main__":

    # Interface selection
    iface = INTERFACE if INTERFACE else str(conf.iface)

    # Print available interfaces
    console.rule("[bold blue]Network IDS Dashboard[/]")
    console.print("\n[cyan]Available Interfaces:[/]")
    for i, ifc in enumerate(get_if_list()):
        marker = "  [yellow]<-- selected[/]" if str(ifc) == str(iface) else ""
        console.print(f"  [{i:>2}]  {ifc}{marker}")

    console.print(f"\n  [cyan]Interface :[/] {iface}")
    console.print(f"  [cyan]Mode      :[/] {'Device-Only' if DEVICE_ONLY_MODE else 'Full Ethernet Network'}")
    console.print(f"  [cyan]Threshold :[/] {ATTACK_THRESHOLD}")
    console.print(f"  [cyan]Promiscuous:[/] ON")

    # Subnet detection
    subnet_info = get_local_subnet(iface)
    if ARP_SCAN_SUBNET:
        subnet, local_ip = ARP_SCAN_SUBNET, "N/A"
    elif subnet_info:
        subnet, local_ip = subnet_info
    else:
        subnet, local_ip = None, "unknown"

    console.print(f"  [cyan]Local IP  :[/] {local_ip}")
    if subnet:
        console.print(f"  [cyan]ARP Subnet:[/] {subnet}")
    console.print()

    # Initial ARP scan
    if subnet:
        with console.status("[bold green]Running ARP scan...[/]"):
            arp_scan(subnet, iface)
        console.print(f"[green]  ARP scan complete — {len(discovered)} devices found.[/]\n")

        # Periodic background rescan
        scan_t = threading.Thread(
            target=periodic_arp_scan,
            args=(subnet, iface, ARP_RESCAN_SECS),
            daemon=True
        )
        scan_t.start()

    # Packet sniffing thread
    def sniff_thread():
        try:
            sniff(
                iface=iface,
                prn=process_packet,
                store=False,
                filter="",       # ARP + IP dono
                promisc=True     # surrounding network detect karo
            )
        except PermissionError:
            console.print("[red]ERROR: Run as Administrator (Windows) or sudo (Linux)[/]")
        except Exception as e:
            console.print(f"[red]Sniff error: {e}[/]")

    sniff_t = threading.Thread(target=sniff_thread, daemon=True)
    sniff_t.start()

    # Live dashboard
    try:
        with Live(
            build_full_dashboard(),
            console=console,
            refresh_per_second=1 / REFRESH_RATE,
            screen=True
        ) as live:
            while True:
                time.sleep(REFRESH_RATE)
                cleanup_stale_flows()
                live.update(build_full_dashboard())

    except KeyboardInterrupt:
        console.rule("[yellow]Dashboard stopped[/]")
        total   = len(ip_stats)
        attacks = sum(1 for v in ip_stats.values() if v["prob"] > ATTACK_THRESHOLD)
        console.print(f"  Total IPs seen   : {total}")
        console.print(f"  Total attacks    : {attacks}")
        console.print(f"  Devices on LAN   : {len(discovered)}")
