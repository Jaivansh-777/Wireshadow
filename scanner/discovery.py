"""Host discovery: auto-detect local subnet + nmap ping sweep."""
from __future__ import annotations

import ipaddress
import socket

import nmap


def get_local_ip() -> str:
    """Best-effort local IP via UDP connect trick (no traffic sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def detect_subnet(prefix: int = 24) -> str:
    """Return e.g. '192.168.1.0/24' derived from the local IP."""
    ip = get_local_ip()
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(net)
    except ValueError:
        return f"{ip}/32"


def discover_live_hosts(subnet: str, timeout: int = 5) -> list[dict]:
    """Run `nmap -sn` ping sweep. Returns [{ip, hostname, status}]."""
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=subnet, arguments=f"-sn --host-timeout {timeout}s")
    except nmap.PortScannerError as e:
        raise RuntimeError(f"nmap ping sweep failed: {e}. Is nmap installed?") from e

    hosts: list[dict] = []
    for ip in scanner.all_hosts():
        info = scanner[ip]
        hostnames = info.get("hostnames", [])
        hostname = hostnames[0].get("name", "") if hostnames else ""
        hosts.append({"ip": ip, "hostname": hostname, "status": info.get("status", {}).get("state", "up")})
    return hosts


def arp_discover_scapy(subnet: str, timeout: int = 3) -> list[dict]:
    """Fallback ARP discovery using scapy (LAN only, needs root)."""
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError as e:
        raise RuntimeError("scapy not installed") from e
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    ans, _ = srp(pkt, timeout=timeout, verbose=0)
    return [{"ip": r.psrc, "hostname": "", "status": "up", "mac": r.hwsrc} for _, r in ans]
