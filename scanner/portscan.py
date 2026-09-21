"""TCP SYN / TCP Connect / UDP port scanning via python-nmap."""
from __future__ import annotations

import os

import nmap


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False  # Windows


def _parse_host(scanner: nmap.PortScanner, ip: str) -> dict:
    """Normalise one nmap host record to {ip, hostname, ports, os}."""
    if ip not in scanner.all_hosts():
        return {"ip": ip, "hostname": "", "ports": [], "os": []}
    rec = scanner[ip]
    hostnames = rec.get("hostnames", [])
    hostname = hostnames[0].get("name", "") if hostnames else ""
    ports: list[dict] = []
    for proto in ("tcp", "udp"):
        for port, pinfo in rec.get(proto, {}).items():
            ports.append(
                {
                    "port": port,
                    "protocol": proto,
                    "state": pinfo.get("state", ""),
                    "service": pinfo.get("name", ""),
                    "product": pinfo.get("product", ""),
                    "version": pinfo.get("version", ""),
                    "extrainfo": pinfo.get("extrainfo", ""),
                    "cpe": pinfo.get("cpe", ""),
                }
            )
    os_matches = [{"name": m.get("name", ""), "accuracy": m.get("accuracy", "")} for m in rec.get("osmatch", [])]
    return {"ip": ip, "hostname": hostname, "ports": sorted(ports, key=lambda p: p["port"]), "os": os_matches}


def tcp_syn_scan(host: str, port_range: str = "1-1000", with_versions: bool = True, timeout: int = 5) -> dict:
    """TCP SYN scan (-sS). Falls back to connect scan without root."""
    scanner = nmap.PortScanner()
    svc = "-sV" if with_versions else "-sS"
    args = f"-sS {svc} -p {port_range} --open --host-timeout {timeout*10}s -T4"
    if not _is_root():
        args = args.replace("-sS", "-sT")  # unprivileged fallback
    scanner.scan(hosts=host, arguments=args)
    return _parse_host(scanner, host)


def tcp_connect_scan(host: str, port_range: str = "1-1000", with_versions: bool = True, timeout: int = 5) -> dict:
    """TCP Connect scan (-sT): no root required, more logged on target."""
    scanner = nmap.PortScanner()
    svc = "-sV" if with_versions else ""
    scanner.scan(hosts=host, arguments=f"-sT {svc} -p {port_range} --open --host-timeout {timeout*10}s -T4")
    return _parse_host(scanner, host)


def udp_scan_top_ports(host: str, ports: list[int] | None = None, timeout: int = 5) -> dict:
    """UDP scan (-sU) over a top-ports list. Slow by nature; keep list small."""
    scanner = nmap.PortScanner()
    top = ports or [53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 500, 514, 520, 1434, 1900, 4500, 5060, 5353, 11211]
    port_str = ",".join(map(str, top))
    args = f"-sU -p {port_str} --open --host-timeout {timeout*10}s -T4"
    if not _is_root():
        # UDP scan needs raw sockets; without root return empty with note
        return {"ip": host, "hostname": "", "ports": [], "os": [], "note": "UDP scan skipped: requires root"}
    scanner.scan(hosts=host, arguments=args)
    return _parse_host(scanner, host)


def full_scan(host: str, port_range: str = "1-1000", udp_ports: list[int] | None = None, timeout: int = 5) -> dict:
    """Combined SYN (+versions) + UDP top ports, merged into one host record."""
    if _is_root():
        tcp = tcp_syn_scan(host, port_range, with_versions=True, timeout=timeout)
    else:
        tcp = tcp_connect_scan(host, port_range, with_versions=True, timeout=timeout)
        tcp["note"] = "Ran TCP Connect scan (no root for SYN)."
    try:
        udp = udp_scan_top_ports(host, udp_ports, timeout=timeout)
    except Exception as e:  # never let UDP kill the whole scan
        udp = {"ports": [], "note": f"UDP scan error: {e}"}
    merged_ports = tcp.get("ports", []) + [p for p in udp.get("ports", []) if p not in tcp.get("ports", [])]
    tcp["ports"] = sorted(merged_ports, key=lambda p: (p["protocol"], p["port"]))
    if udp.get("note"):
        tcp["udp_note"] = udp["note"]
    # OS detection pass (best effort, needs root)
    if _is_root():
        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=host, arguments="-O --osscan-guess")
            if host in scanner.all_hosts():
                tcp["os"] = [
                    {"name": m.get("name", ""), "accuracy": m.get("accuracy", "")}
                    for m in scanner[host].get("osmatch", [])
                ]
        except Exception:
            pass
    return tcp
