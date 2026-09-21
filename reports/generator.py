"""PDF report generation with reportlab."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

RISK_COLORS = {"Low": colors.HexColor("#2e7d32"), "Medium": colors.HexColor("#f9a825"),
               "High": colors.HexColor("#ef6c00"), "Critical": colors.HexColor("#c62828")}


def _risk_level(score: int) -> str:
    return "Low" if score < 25 else "Medium" if score < 50 else "High" if score < 75 else "Critical"


def generate_pdf(output_path: str | Path, target: str, hosts: list[dict], analysis: dict) -> Path:
    """Build executive summary + per-host technical details + recommendations."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    story = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    story.append(Paragraph("WIRESHADOW — Security Report", styles["Title"]))
    story.append(Paragraph(f"Target: <b>{target}</b> &nbsp;|&nbsp; Generated: {now} &nbsp;|&nbsp; "
                           f"Provider: {analysis.get('provider', 'n/a')}", styles["Normal"]))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(analysis.get("network_summary", "No summary available."), styles["Normal"]))
    story.append(Spacer(1, 0.3 * cm))

    # Risk table
    by_ip = {h.get("ip"): h for h in analysis.get("hosts", [])}
    rows = [["Host", "Open ports", "Risk score", "Risk level"]]
    for h in hosts:
        a = by_ip.get(h.get("ip", ""), {})
        score = a.get("risk_score", 0)
        rows.append([h.get("ip", ""), str(sum(1 for p in h.get("ports", []) if p.get("state") == "open")),
                     str(score), a.get("risk_level", _risk_level(score))])
    t = Table(rows, colWidths=[5 * cm, 3 * cm, 3 * cm, 4 * cm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#212121")),
                           ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                           ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")])]))
    story.append(t)
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("Top Priorities", styles["Heading2"]))
    for pri in analysis.get("top_priorities", []) or ["None listed."]:
        story.append(Paragraph(f"• {pri}", styles["Normal"]))

    # Per-host details
    for h in hosts:
        ip = h.get("ip", "")
        a = by_ip.get(ip, {})
        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph(f"Host: {ip} {('(' + h['hostname'] + ')') if h.get('hostname') else ''} — "
                               f"Risk {a.get('risk_score', 0)} ({a.get('risk_level', 'n/a')})", styles["Heading2"]))
        if h.get("os"):
            story.append(Paragraph("OS guesses: " + "; ".join(
                f"{o.get('name')} ({o.get('accuracy')}%)" for o in h["os"][:3]), styles["Normal"]))
        prows = [["Port", "Proto", "State", "Service", "Version", "CVE hits"]]
        for p in h.get("ports", []):
            if p.get("state") != "open":
                continue
            ver = f"{p.get('product','')} {p.get('version','')}".strip()
            cves = ", ".join(v.get("cve", "") for v in (a.get("vulnerabilities", []) or []) if v.get("port") == p.get("port"))
            prows.append([str(p.get("port")), p.get("protocol", ""), p.get("state", ""),
                          p.get("service", ""), ver[:40], cves[:40]])
        if len(prows) == 1:
            prows.append(["—", "—", "no open ports shown", "—", "—", "—"])
        pt = Table(prows, colWidths=[2 * cm, 2 * cm, 2 * cm, 3 * cm, 4 * cm, 3.5 * cm])
        pt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474f")),
                                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                                ("FONTSIZE", (0, 0), (-1, -1), 8)]))
        story.append(pt)
        for section, key in (("Vulnerabilities", "vulnerabilities"), ("Misconfigurations", "misconfigurations"),
                             ("Recommendations", "recommendations")):
            items = a.get(key, [])
            story.append(Paragraph(section, styles["Heading3"]))
            if not items:
                story.append(Paragraph("None.", styles["Normal"]))
            for it in items:
                story.append(Paragraph(f"• {it if isinstance(it, str) else it.get('cve','') + ' — ' + it.get('description','')}",
                                       styles["Normal"]))
    story.append(Spacer(1, 0.6 * cm))
    story.append(Paragraph("Disclaimer: scan only systems you own or are explicitly authorised to test. "
                           "AI output is advisory — verify findings manually.", styles["Italic"]))
    SimpleDocTemplate(str(output_path), pagesize=A4,
                      title=f"Network Scan Report — {target}").build(story)
    return output_path
