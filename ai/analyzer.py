"""AI analysis via OpenRouter (free models) with heuristic fallback."""
from __future__ import annotations

import json

import requests

from .prompts import SYSTEM_PROMPT, build_analysis_prompt

SEV_WEIGHT = {"Critical": 25, "High": 15, "Medium": 7, "Low": 2}


def _extract_json(content: str) -> dict:
    """Pull the first balanced {...} block that parses and has a 'hosts' key.

    Reasoning-style free models often wrap JSON in thinking text or fences,
    so a plain index/rindex slice is too brittle.
    """
    best: dict | None = None
    i = 0
    while True:
        start = content.find("{", i)
        if start == -1:
            break
        depth = 0
        for j in range(start, len(content)):
            if content[j] == "{":
                depth += 1
            elif content[j] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(content[start: j + 1])
                    except json.JSONDecodeError:
                        break
                    if isinstance(obj, dict) and "hosts" in obj:
                        return obj
                    if best is None and isinstance(obj, dict):
                        best = obj
                    break
        i = start + 1
    if best is not None:
        return best
    raise RuntimeError(f"No JSON object in model reply; snippet: {content[:300]!r}")


def _post_openrouter(payload_hosts: list[dict], ai_cfg: dict, model: str) -> dict:
    """Single attempt against one model id. Raises RuntimeError with body on HTTP error."""
    resp = requests.post(
        ai_cfg.get("base_url", "https://openrouter.ai/api/v1/chat/completions"),
        headers={"Authorization": f"Bearer {ai_cfg['api_key']}", "Content-Type": "application/json",
                 "HTTP-Referer": "https://github.com/ai-network-scanner", "X-Title": "WIRESHADOW Scanner"},
        json={"model": model,
              "max_tokens": ai_cfg.get("max_tokens", 2000), "temperature": 0.2,
              "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                           {"role": "user", "content": build_analysis_prompt(json.dumps(payload_hosts)[:12000])}]},
        timeout=ai_cfg.get("timeout", 60),
    )
    try:
        resp.raise_for_status()
    except requests.HTTPError as e:
        # OpenRouter puts the real reason (e.g. bad model id) in the body
        raise RuntimeError(f"{e} | model={model} | body={resp.text[:300]}") from e
    content = resp.json()["choices"][0]["message"]["content"].strip()
    # strip accidental markdown fences
    if content.startswith("```"):
        content = content.strip("`").split("\n", 1)[-1].rsplit("```", 1)[0]
    data = _extract_json(content)
    data.setdefault("provider", model)
    return data


def heuristic_analysis(hosts: list[dict]) -> dict:
    """Deterministic offline fallback when no API key / request fails."""
    out_hosts = []
    for h in hosts:
        score = 0
        vulns = list(h.get("cve_findings", []))
        for v in vulns:
            score += SEV_WEIGHT.get(v.get("severity", "Low"), 2)
        n_open = sum(1 for p in h.get("ports", []) if p.get("state") == "open")
        score += min(n_open * 2, 20)
        misc, recs = [], []
        svcs = " ".join(p.get("service", "") for p in h.get("ports", [])).lower()
        if "telnet" in svcs:
            misc.append("Telnet (cleartext admin) exposed")
            recs.append("Disable Telnet; use SSH with key auth only")
        if "ftp" in svcs and "sftp" not in svcs and "ssh" not in svcs:
            misc.append("Plain FTP exposed without SSH/SFTP alternative")
            recs.append("Migrate to SFTP; enforce TLS if FTP must stay")
        if "vnc" in svcs or any(p.get("port") == 5900 for p in h.get("ports", [])):
            misc.append("VNC remote desktop exposed")
            recs.append("Bind VNC to localhost + SSH tunnel; enforce strong passwords")
        if any(p.get("port") == 3389 for p in h.get("ports", [])):
            misc.append("RDP exposed to network")
            recs.append("Patch RDP, enforce NLA + MFA, restrict via firewall/VPN")
        if any(p.get("port") in (139, 445) for p in h.get("ports", [])):
            misc.append("SMB ports (139/445) reachable")
            recs.append("Disable SMBv1, require SMB signing, segment file sharing")
        for v in vulns:
            recs.append(f"Remediate {v.get('cve')}: {v.get('description','')[:90]}")
        score = max(0, min(100, score))
        level = "Low" if score < 25 else "Medium" if score < 50 else "High" if score < 75 else "Critical"
        out_hosts.append({"ip": h.get("ip"), "risk_score": score, "risk_level": level,
                          "vulnerabilities": vulns, "misconfigurations": misc,
                          "recommendations": sorted(set(recs)) or ["No urgent action; maintain patching cadence."]})
    top = sorted(out_hosts, key=lambda x: x["risk_score"], reverse=True)[:3]
    return {"hosts": out_hosts,
            "network_summary": f"Heuristic (offline) analysis of {len(hosts)} host(s).",
            "top_priorities": [f"{h['ip']} ({h['risk_level']} {h['risk_score']})" for h in top],
            "provider": "heuristic-offline"}


def analyze_scan(hosts: list[dict], ai_cfg: dict) -> dict:
    """POST scan results to OpenRouter; fall back to heuristic on any failure."""
    api_key = (ai_cfg.get("api_key") or "").strip()
    if not api_key:
        return heuristic_analysis(hosts)
    payload_hosts = [
        {"ip": h.get("ip"), "hostname": h.get("hostname", ""), "os": h.get("os", []),
         "ports": h.get("ports", []), "cve_findings": h.get("cve_findings", [])}
        for h in hosts
    ]
    primary = ai_cfg.get("model", "openrouter/free")
    # Free-model IDs churn weekly; retry via the auto-router before giving up.
    # The router picks a random model per call, so several attempts help when
    # a reasoning-heavy pick returns thinking text instead of JSON.
    candidates = [primary]
    while len(candidates) < 3:
        candidates.append("openrouter/free")
    candidates = candidates[:3] if primary == "openrouter/free" else [primary, "openrouter/free"]
    errors = []
    result: dict | None = None
    for model in candidates:
        try:
            result = _post_openrouter(payload_hosts, {**ai_cfg, "api_key": api_key}, model)
            break
        except Exception as e:
            errors.append(f"{model}: {e}")
    if result is None:
        result = heuristic_analysis(hosts)
        result["provider"] = "heuristic-fallback (" + " | ".join(errors) + ")"
        return result
    # Backfill: if the model skipped hosts or the summary, patch from heuristic
    # so the UI never shows empty panels or "n/a" risk.
    heur = heuristic_analysis(hosts)
    heur_by_ip = {h["ip"]: h for h in heur["hosts"]}
    seen = {h.get("ip") for h in result.get("hosts", [])}
    for h in heur["hosts"]:
        if h["ip"] not in seen:
            h = dict(h)
            h["note"] = "scored offline — model omitted this host"
            result.setdefault("hosts", []).append(h)
    if not result.get("network_summary"):
        result["network_summary"] = heur["network_summary"]
    if not result.get("top_priorities"):
        result["top_priorities"] = heur["top_priorities"]
    return result
