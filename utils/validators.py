"""Input validation + legal-safety helpers."""
from __future__ import annotations

import ipaddress
import socket


def is_valid_ip_or_subnet(value: str) -> bool:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    # allow plain hostname
    try:
        socket.gethostbyname(value)
        return True
    except socket.gaierror:
        return False


def is_public_ip(ip: str) -> bool:
    """True if the address is globally routable (warn-worthy)."""
    try:
        addr = ipaddress.ip_address(socket.gethostbyname(ip.split("/")[0]))
        return addr.is_global
    except Exception:
        return False


def is_private_target(target: str) -> bool:
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            return net.is_private
        addr = ipaddress.ip_address(socket.gethostbyname(target))
        return addr.is_private or addr.is_loopback
    except Exception:
        return False


def expand_target(target: str) -> str:
    """Normalise target for nmap (hostnames pass through)."""
    return target.strip()


def validate_port_range(port_range: str) -> bool:
    try:
        parts = port_range.replace(" ", "").split(",")
        for p in parts:
            if "-" in p:
                a, b = p.split("-", 1)
                if not (0 < int(a) <= int(b) <= 65535):
                    return False
            else:
                if not (0 < int(p) <= 65535):
                    return False
        return True
    except Exception:
        return False
