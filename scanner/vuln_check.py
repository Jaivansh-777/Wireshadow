"""Offline CVE matching against detected service versions.

Uses a small curated signature table (no network needed). For production
use, sync with NVD/CPE feeds; this covers notorious cases + risky services.
"""
from __future__ import annotations

import re

# (service_regex, version_regex, cve, severity, description)
SIGNATURES: list[tuple[str, str, str, str, str]] = [
    (r"vsftpd", r"2\.3\.4", "CVE-2011-2523", "Critical", "vsftpd 2.3.4 backdoor — remote shell via smiley-face login."),
    (r"proftpd", r"1\.3\.3", "CVE-2010-4221", "High", "ProFTPD Telnet IAC buffer overflow, pre-auth RCE."),
    (r"openssh", r"[1-7]\.[0-3]", "CVE-2016-0777 / CVE-2018-15473", "Medium", "Old OpenSSH: roaming bug / user enumeration."),
    (r"openssh", r"8\.[0-7]", "CVE-2023-38408", "High", "OpenSSH < 9.3 ssh-agent PKCS#11 RCE chain."),
    (r"samba|smb|netbios", r"3\.[0-5]\.", "CVE-2017-7494", "Critical", "Samba < 4.6.4 writable-share RCE (EternalRed)."),
    (r"msrpc|smb", r"", "CVE-2017-0144", "Critical", "SMBv1 exposed — EternalBlue family (WannaCry). Verify & disable SMBv1."),
    (r"telnet", r"", "NO-CVE-PLAINTEXT", "High", "Telnet transmits credentials in cleartext. Replace with SSH."),
    (r"ftp", r"", "NO-CVE-PLAINTEXT", "Medium", "FTP transmits credentials in cleartext. Prefer SFTP/FTPS."),
    (r"vnc", r"", "WEAK-AUTH", "High", "VNC often weakly authenticated; brute-forceable. Restrict + tunnel via SSH/VPN."),
    (r"rdp|ms-wbt", r"", "BLUEKEEP-FAMILY", "High", "RDP exposed — BlueKeep-class risk (CVE-2019-0708). Patch + NLA + VPN."),
    (r"mysql", r"5\.[0-5]\.", "CVE-2016-6662", "High", "MySQL 5.x EOL branch with privilege-escalation flaws. Upgrade to 8.x."),
    (r"apache|httpd", r"2\.4\.(1|2|3|4)?[0-9]\b", "CVE-2021-44790", "High", "Apache httpd 2.4.x < 2.4.52 mod_lua buffer overflow."),
    (r"apache|httpd", r"2\.2\.", "CVE-2017-7679", "High", "Apache 2.2 EOL — multiple unpatched flaws. Migrate to 2.4 latest."),
    (r"nginx", r"1\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\.", "CVE-2017-7529", "Medium", "nginx < 1.13.3 range-filter integer overflow."),
    (r"ssl|https|tls", r"", "CHECK-TLS", "Medium", "Verify TLS version/cipher suite (disable SSLv3/TLS1.0/1.1, weak ciphers)."),
]


def match_cves(service: str, product: str, version: str, port: int = 0) -> list[dict]:
    """Return list of {cve, severity, description} matches for one service."""
    hay = f"{service} {product} {version}".lower()
    hits: list[dict] = []
    for svc_re, ver_re, cve, sev, desc in SIGNATURES:
        if re.search(svc_re, hay):
            if not ver_re or re.search(ver_re, version or "", re.IGNORECASE) or re.search(ver_re, hay):
                # generic risk entries (telnet/ftp/rdp/vnc) match regardless of version
                if ver_re == "" or re.search(ver_re, hay) or ver_re in ("",):
                    hits.append({"cve": cve, "severity": sev, "description": desc, "port": port})
            elif ver_re == "":
                hits.append({"cve": cve, "severity": sev, "description": desc, "port": port})
    # de-dup by CVE
    seen, out = set(), []
    for h in hits:
        if h["cve"] not in seen:
            seen.add(h["cve"])
            out.append(h)
    return out


def check_host(host_result: dict) -> list[dict]:
    """Match CVEs for every detected port on a host. Adds findings list."""
    findings: list[dict] = []
    for p in host_result.get("ports", []):
        if p.get("state") != "open":
            continue
        for hit in match_cves(p.get("service", ""), p.get("product", ""), p.get("version", ""), p.get("port", 0)):
            findings.append({**hit, "service": f"{p.get('product','')} {p.get('version','')}".strip() or p.get("service", "")})
    # port-445/139 without version info still deserves SMBv1 warning
    open_ports = {p.get("port") for p in host_result.get("ports", []) if p.get("state") == "open"}
    if {139, 445} & open_ports and not any(f["cve"] == "CVE-2017-0144" for f in findings):
        findings.append({"cve": "CVE-2017-0144", "severity": "Critical",
                         "description": "SMB ports open — confirm SMBv1 disabled (EternalBlue family).",
                         "port": 445, "service": "smb"})
    return findings
