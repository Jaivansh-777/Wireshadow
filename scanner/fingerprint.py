"""Service banner grabbing + OS fingerprint enrichment."""
from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

_DEFAULT_PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    25: b"EHLO scanner\r\n",
    21: b"",
    22: b"",
    23: b"",
    3306: b"",
}


def grab_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    """Open TCP, read (and optionally probe) the service banner."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            probe = _DEFAULT_PROBES.get(port, b"")
            if probe:
                try:
                    s.sendall(probe)
                except OSError:
                    pass
            try:
                data = s.recv(2048)
            except socket.timeout:
                return ""
            text = data.decode("utf-8", errors="replace")
            # strip telnet IAC sequences + non-printables so tables stay clean
            text = re.sub(r"\xff[\xfb-\xfe][\x00-\xff]?", "", text)
            text = "".join(c for c in text if c.isprintable() or c in "\n\t")
            return " ".join(text.split())[:300]
    except Exception:
        return ""


def enrich_with_banners(host_result: dict, timeout: float = 3.0, max_workers: int = 20) -> dict:
    """Banner-grab every open TCP port concurrently; adds 'banner' per port."""
    ports = [p for p in host_result.get("ports", []) if p.get("protocol") == "tcp" and p.get("state") == "open"]
    if not ports:
        return host_result
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as ex:
        futs = {ex.submit(grab_banner, host_result["ip"], p["port"], timeout): p for p in ports}
        for fut in as_completed(futs):
            futs[fut]["banner"] = fut.result()
    return host_result


def guess_os_from_ttl_banner(host_result: dict) -> str:
    """Cheap heuristic when nmap -O is unavailable (banner/TTL hints)."""
    if host_result.get("os"):
        return host_result["os"][0].get("name", "")
    blobs = " ".join(p.get("banner", "") + p.get("product", "") for p in host_result.get("ports", [])).lower()
    if "microsoft" in blobs or "iis" in blobs or "windows" in blobs:
        return "Windows (heuristic from banners)"
    if "openssh" in blobs or "linux" in blobs or "ubuntu" in blobs or "debian" in blobs:
        return "Linux (heuristic from banners)"
    return "Unknown"
