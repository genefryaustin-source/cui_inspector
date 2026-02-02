
import sqlite3
from pathlib import Path
from datetime import datetime

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "evidence_mt.db"

BASE_SCHEMA = '''
CREATE TABLE IF NOT EXISTS tenants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER,
  username TEXT UNIQUE,
  password_hash TEXT,
  role TEXT,
  is_active INTEGER DEFAULT 1,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER,
  user_id INTEGER,
  event_type TEXT,
  details_json TEXT,
  created_at TEXT
);
'''

def now_iso():
    return datetime.utcnow().isoformat()

def _ensure_column(con, table, coldef):
    name = coldef.split()[0]
    cols = {r[1] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}
    if name not in cols:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {coldef}")

def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.executescript(BASE_SCHEMA)
        _ensure_column(con, "users", "last_login_at TEXT")
        _ensure_column(con, "tenants", "is_active INTEGER DEFAULT 1")

def db():
    init_db()
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con
