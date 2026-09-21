"""Central YAML config loader with sane defaults."""
from __future__ import annotations

import os
from pathlib import Path

try:
    import yaml
    _YAML_OK = True
except ImportError:  # minimal installs: fall back to built-in defaults
    yaml = None  # type: ignore
    _YAML_OK = False

_DEFAULTS = {
    "scan": {
        "default_range": "auto",
        "timeout": 5,
        "threads": 50,
        "port_range": "1-1000",
        "common_ports": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
        "udp_top_ports": [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 1900, 4500, 500, 514, 520, 1434, 5353, 11211, 5060],
    },
    "ai": {
        "provider": "openrouter",
        "model": "openrouter/free",
        "api_key": "",
        "max_tokens": 2000,
        "base_url": "https://openrouter.ai/api/v1/chat/completions",
        "timeout": 60,
    },
    "report": {"format": "pdf", "output_dir": "reports_output"},
    "legal": {
        "require_authorization": True,
        "log_scans": True,
        "log_file": "scan_audit.log",
        "db_path": "db/scan_history.db",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def load_config(path: str | Path | None = None) -> dict:
    """Load config.yaml, overlay env vars, return merged dict."""
    cfg = {k: dict(v) for k, v in _DEFAULTS.items()}
    candidates = []
    if path:
        candidates.append(Path(path))
    candidates.append(Path(__file__).resolve().parents[1] / "config.yaml")
    candidates.append(Path.cwd() / "config.yaml")

    for c in candidates:
        if c.exists():
            if not _YAML_OK:
                break  # no pyyaml: use built-in defaults
            with open(c) as f:
                data = yaml.safe_load(f) or {}
            cfg = _deep_merge(cfg, data)
            break

    # Env overrides (so API key never has to live in the file)
    if os.getenv("OPENROUTER_API_KEY"):
        cfg["ai"]["api_key"] = os.getenv("OPENROUTER_API_KEY", "")
    if os.getenv("OPENROUTER_MODEL"):
        cfg["ai"]["model"] = os.getenv("OPENROUTER_MODEL", "")
    return cfg


def get_project_root() -> Path:
    return Path(__file__).resolve().parents[1]
