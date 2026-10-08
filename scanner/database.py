from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, target_url TEXT NOT NULL, duration_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, owasp_category TEXT NOT NULL, evidence TEXT NOT NULL, remediation TEXT NOT NULL, FOREIGN KEY(scan_id) REFERENCES scans(id));
"""


def connect(path: str | Path = "scans.db") -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript(SCHEMA)
    return db
