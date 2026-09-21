#!/usr/bin/env python3
"""AI Network Scanner — entry point.

Flow: authorization check → subnet input → discovery → portscan
      (+ banners, CVE match) → AI analysis → PDF report → SQLite history.
"""
from __future__ import annotations

import argparse
import getpass
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from db.history import get_scan, list_scans, save_scan
from utils.config import load_config
from utils.logger import get_console, setup_logger
from utils.validators import is_public_ip, is_valid_ip_or_subnet, validate_port_range

AUTHORIZATION_TEXT = """
[bold red]LEGAL AUTHORIZATION REQUIRED[/bold red]

This tool performs ACTIVE network scanning (ping sweeps, SYN/connect
scans, banner grabs). In most jurisdictions this is ONLY lawful against
systems you own or have explicit written permission to test.

By typing [bold]I AUTHORIZE[/bold] you confirm:
  1. You own the target network(s) or hold written authorization.
  2. You accept full legal responsibility for this scan.
  3. You consent to this scan being logged (audit log + SQLite history).
"""


def require_authorization(console: Console, cfg: dict, logger, assume_yes: bool = False) -> bool:
    if not cfg["legal"].get("require_authorization", True):
        return True
    console.print(Panel(AUTHORIZATION_TEXT, title="Authorization", border_style="red"))
    if assume_yes:
        logger.warning("Authorization bypassed via --yes flag by user %s", getpass.getuser())
        return True
    answer = Prompt.ask("Type [bold]I AUTHORIZE[/bold] to continue (anything else aborts)", default="abort")
    if answer.strip() != "I AUTHORIZE":
        console.print("[red]Aborted: authorization not granted.[/red]")
        logger.warning("Scan aborted: authorization declined by %s", getpass.getuser())
        return False
    logger.warning("Authorization granted by user=%s", getpass.getuser())
    return True


RISK_STYLE = {"Low": "green", "Medium": "yellow", "High": "dark_orange", "Critical": "bold red"}
SEV_STYLE = {"Critical": "bold red", "High": "red", "Medium": "yellow", "Low": "green"}


def risk_text(score: int, level: str) -> Text:
    bar_len = max(1, min(10, score * 10 // 100))
    bar = "█" * bar_len + "░" * (10 - bar_len)
    return Text.assemble((f"{score:3d} ", "bold"), (f"{level:8s} ", RISK_STYLE.get(level, ""), ), (bar, RISK_STYLE.get(level, "")))


def show_hosts(console: Console, hosts: list[dict]) -> None:
    table = Table(title="Live Hosts", show_lines=False)
    table.add_column("IP", style="cyan")
    table.add_column("Hostname")
    table.add_column("Status", style="green")
    for h in hosts:
        table.add_row(h["ip"], h.get("hostname", "") or "—", h.get("status", "up"))
    console.print(table)


def show_host_detail(console: Console, host: dict, analysis_host: dict | None) -> None:
    score = (analysis_host or {}).get("risk_score", 0)
    level = (analysis_host or {}).get("risk_level", "Low")
    header = Text.assemble(("◉ ", RISK_STYLE.get(level, "")), (f"{host['ip']}", "bold cyan"),
                           ("  risk ", "dim"), risk_text(score, level))
    if host.get("hostname"):
        header.append(f"  ({host['hostname']})", style="dim")

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Proto", style="dim")
    table.add_column("Service", style="bold")
    table.add_column("Version")
    table.add_column("Banner", style="dim", max_width=42)
    for p in host.get("ports", []):
        if p.get("state") != "open":
            continue
        table.add_row(str(p["port"]), p.get("protocol", ""), p.get("service", "") or "unknown",
                      f"{p.get('product','')} {p.get('version','')}".strip() or "—",
                      (p.get("banner", "") or "—")[:80])

    vuln_lines: list[Text] = []
    for f in host.get("cve_findings", []):
        vuln_lines.append(Text.assemble(
            (f"[{f.get('severity','?')}] ", SEV_STYLE.get(f.get("severity", ""), "")),
            (f"{f.get('cve','')} ", "bold"),
            (f":{f.get('port','')} — {f.get('description','')}", "")))
    vulns = Group(*vuln_lines) if vuln_lines else Text("No known CVE matches.", style="dim green")

    rec_items = (analysis_host or {}).get("recommendations", [])
    recs = Group(*[Text(f"▸ {r}", style="") for r in rec_items]) if rec_items else Text("—", style="dim")
    misc_items = (analysis_host or {}).get("misconfigurations", [])
    misc = Group(*[Text(f"⚠ {m}", style="yellow") for m in misc_items]) if misc_items else Text("—", style="dim")

    console.print(Panel(Group(header, Text(""), table),
                        title=f"host {host['ip']}", border_style=RISK_STYLE.get(level, "")))
    console.print(Panel(vulns, title="[bold]vulnerabilities[/bold]", border_style="red"))
    if misc_items or rec_items:
        console.print(Panel(Group(Text("Misconfigurations:", style="bold yellow"), misc, Text(""),
                                    Text("Recommendations:", style="bold green"), recs),
                            title="[bold]findings & fixes[/bold]", border_style="blue"))


def cmd_scan(args, cfg: dict, console: Console, logger) -> int:
    # Heavy deps (nmap/scapy/reportlab/requests) imported lazily so that
    # `history` and --help work on a bare interpreter. Friendly error if
    # the user forgot the venv install.
    try:
        from rich.progress import track

        from ai.analyzer import analyze_scan
        from reports.generator import generate_pdf
        from scanner.discovery import detect_subnet, discover_live_hosts
        from scanner.fingerprint import enrich_with_banners
        from scanner.portscan import full_scan
        from scanner.vuln_check import check_host
    except ImportError as e:
        console.print(f"[red]Missing dependency ({e}). Install it first:[/red]")
        console.print("[bold]python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt[/bold]")
        return 1

    if not require_authorization(console, cfg, logger, assume_yes=args.yes):
        return 2

    # --- target selection ---
    target = args.target
    if not target:
        auto = detect_subnet()
        console.print(f"[dim]Auto-detected local subnet:[/dim] [bold]{auto}[/bold]")
        target = Prompt.ask("Subnet / host to scan", default=auto if cfg["scan"]["default_range"] == "auto" else cfg["scan"]["default_range"])
    if target == "auto":
        target = detect_subnet()
    if not is_valid_ip_or_subnet(target):
        console.print(f"[red]Invalid target: {target}[/red]")
        return 2
    if is_public_ip(target):
        console.print(Panel(f"[bold yellow]WARNING:[/bold yellow] {target} appears to be a PUBLIC address. "
                            "Scanning it without written permission may be illegal.", border_style="yellow"))
        if not Confirm.ask("Continue anyway?", default=False):
            console.print("[red]Aborted.[/red]")
            return 2
        logger.warning("User proceeded against PUBLIC target %s", target)

    port_range = args.ports or cfg["scan"]["port_range"]
    if not validate_port_range(port_range):
        console.print(f"[red]Invalid port range: {port_range}[/red]")
        return 2
    udp_ports: list[int] = cfg["scan"].get("udp_top_ports", [53, 161, 500, 1900, 5353])
    timeout = cfg["scan"].get("timeout", 5)
    logger.warning("SCAN START user=%s target=%s ports=%s", getpass.getuser(), target, port_range)

    # --- discovery ---
    if "/" in target:  # subnet → ping sweep first
        with console.status(f"[bold green]Discovering live hosts in {target}…[/bold green]"):
            try:
                live = discover_live_hosts(target, timeout=timeout)
            except RuntimeError as e:
                console.print(f"[red]{e}[/red]")
                return 1
        if not live:
            console.print("[yellow]No live hosts found.[/yellow]")
            return 0
        show_hosts(console, live)
        hosts_to_scan = [h["ip"] for h in live]
        if not args.all and len(hosts_to_scan) > 1 and not Confirm.ask(f"Deep-scan all {len(hosts_to_scan)} hosts?", default=True):
            hosts_to_scan = [Prompt.ask("Which host/IP?", default=hosts_to_scan[0])]
    else:
        hosts_to_scan = [target]

    # --- deep scan (threaded) ---
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(10, len(hosts_to_scan))) as ex:
        futs = {ex.submit(full_scan, ip, port_range, udp_ports, timeout): ip for ip in hosts_to_scan}
        for fut in track(as_completed(futs), total=len(futs), description="Port scanning…"):
            ip = futs[fut]
            try:
                rec = fut.result()
                rec = enrich_with_banners(rec, timeout=timeout)
                rec["cve_findings"] = check_host(rec)
                results.append(rec)
                logger.warning("SCAN HOST user=%s ip=%s open=%d", getpass.getuser(), ip,
                               sum(1 for p in rec.get("ports", []) if p.get("state") == "open"))
            except Exception as e:
                console.print(f"[red]Scan of {ip} failed: {e}[/red]")
                logger.error("Scan of %s failed: %s", ip, e)
    results.sort(key=lambda h: h.get("ip", ""))

    # --- AI analysis ---
    with console.status("[bold green]Running AI analysis…[/bold green]"):
        analysis = analyze_scan(results, cfg["ai"])
    verdict = Group(
        Text(analysis.get("network_summary", "No summary available."), style=""),
        Text(""),
        Text("Top priorities:", style="bold"),
        Group(*[Text(f"  {i+1}. {p}", style="yellow") for i, p in enumerate(analysis.get("top_priorities", []) or ["None listed."])]),
    )
    console.print(Panel(verdict, title=f"[bold]✦ AI verdict[/bold] [dim]({analysis.get('provider','')})[/dim]",
                        border_style="accent", padding=(1, 2)))
    by_ip = {h.get("ip"): h for h in analysis.get("hosts", [])}
    for rec in results:
        show_host_detail(console, rec, by_ip.get(rec.get("ip", "")))

    # --- persist + report ---
    payload = {"target": target, "port_range": port_range, "hosts": results, "analysis": analysis}
    scan_id = save_scan(cfg["legal"]["db_path"], target, payload)
    out_dir = Path(cfg["report"]["output_dir"])
    pdf = out_dir / f"scan_{target.replace('/', '_')}_{datetime.now():%Y%m%d_%H%M%S}.pdf"
    generate_pdf(pdf, target, results, analysis)
    console.print(f"[bold green]PDF report:[/bold green] {pdf}   [dim](scan_id={scan_id})[/dim]")
    logger.warning("SCAN DONE user=%s target=%s scan_id=%s report=%s", getpass.getuser(), target, scan_id, pdf)
    return 0


def cmd_history(args, cfg: dict, console: Console) -> int:
    rows = list_scans(cfg["legal"]["db_path"], limit=args.limit)
    if not rows:
        console.print("[yellow]No scans in history yet.[/yellow]")
        return 0
    table = Table(title="Scan History")
    table.add_column("scan_id", style="cyan")
    table.add_column("target")
    table.add_column("created_at")
    for r in rows:
        table.add_row(r["scan_id"], r["target"], r["created_at"])
    console.print(table)
    if args.show:
        data = get_scan(cfg["legal"]["db_path"], args.show)
        if not data:
            console.print(f"[red]Unknown scan_id: {args.show}[/red]")
            return 2
        console.print_json(data=data)
    return 0


def main(argv: list[str] | None = None) -> int:
    cfg = load_config()
    logger = setup_logger(cfg["legal"].get("log_file", "scan_audit.log"))
    console = get_console()

    ap = argparse.ArgumentParser(prog="wireshadow", description="WIRESHADOW — AI-powered network scanner (authorized use only).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_scan = sub.add_parser("scan", help="Discover + port-scan a subnet/host")
    p_scan.add_argument("-t", "--target", default=None, help="e.g. 192.168.1.0/24, 192.168.1.10, or 'auto'")
    p_scan.add_argument("-p", "--ports", default=None, help="e.g. 1-1000 (default from config.yaml)")
    p_scan.add_argument("--all", action="store_true", help="Deep-scan all live hosts without asking")
    p_scan.add_argument("-y", "--yes", action="store_true", help="Skip interactive auth prompt (still logged)")
    p_hist = sub.add_parser("history", help="Show past scans")
    p_hist.add_argument("--limit", type=int, default=20)
    p_hist.add_argument("--show", default=None, help="Print stored JSON for a scan_id")
    args = ap.parse_args(argv)

    console.print(Panel(Group(
        Text("W I R E S H A D O W", style="accent", justify="center"),
        Text("move unseen · see everything", style="ghost", justify="center"),
    ), border_style="accent", padding=(1, 4)))
    console.print(Panel("[ghost]Authorized use only. Every scan is logged to scan_audit.log + SQLite history.[/ghost]",
                        border_style="ghost"))
    if args.cmd == "scan":
        return cmd_scan(args, cfg, console, logger)
    return cmd_history(args, cfg, console)


if __name__ == "__main__":
    raise SystemExit(main())
