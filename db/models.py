"""SQLite schema + history helpers."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  scan_id    TEXT PRIMARY KEY,
  target     TEXT NOT NULL,
  timestamp  REAL NOT NULL,
  created_at TEXT NOT NULL,
  results_json TEXT NOT NULL
);
"""


def _connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(SCHEMA)
    return conn


def init_db(db_path: str) -> None:
    with _connect(db_path):
        pass
