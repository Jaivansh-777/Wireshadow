"""Persist / retrieve scan history."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from datetime import datetime

from .models import _connect, init_db


def save_scan(db_path: str, target: str, results: dict) -> str:
    init_db(db_path)
    scan_id = uuid.uuid4().hex[:12]
    now = time.time()
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT INTO scans (scan_id, target, timestamp, created_at, results_json) VALUES (?,?,?,?,?)",
            (scan_id, target, now, datetime.fromtimestamp(now).isoformat(timespec="seconds"), json.dumps(results)),
        )
        conn.commit()
    return scan_id


def list_scans(db_path: str, limit: int = 20) -> list[dict]:
    init_db(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT scan_id, target, created_at FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [{"scan_id": r[0], "target": r[1], "created_at": r[2]} for r in rows]


def get_scan(db_path: str, scan_id: str) -> dict | None:
    init_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute("SELECT results_json FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
    if not row:
        return None
    return json.loads(row[0])
