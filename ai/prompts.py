"""Prompt templates for the OpenRouter analysis step."""

SYSTEM_PROMPT = (
    "You are a senior network security analyst. You analyse raw port-scan "
    "results and return ONLY valid JSON (no markdown fences, no commentary). "
    "Be conservative: never invent CVEs, flag cleartext/legacy services, "
    "and score risk 0-100 considering exposure, severity and exploitability."
)

ANALYSIS_PROMPT = """Analyze these network scan results. For each host, return JSON with: risk_score (0-100), vulnerabilities (list), misconfigurations (list), recommendations (list).

Scan results:
{scan_json}

Return a single JSON object shaped like:
{{
  "hosts": [
    {{
      "ip": "192.168.1.10",
      "risk_score": 75,
      "risk_level": "High",
      "vulnerabilities": [{{"cve": "CVE-XXXX-XXXX", "severity": "High", "description": "..."}}],
      "misconfigurations": ["Telnet exposed ..."],
      "recommendations": ["Disable ...", "Patch ..."]
    }}
  ],
  "network_summary": "...",
  "top_priorities": ["..."]
}}

Risk bands: 0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical.
Incorporate the pre-matched CVE findings (field "cve_findings") into your answer; do not contradict them.
ONLY output the JSON object."""


def build_analysis_prompt(scan_json: str) -> str:
    return ANALYSIS_PROMPT.format(scan_json=scan_json)
