import sqlite3
from pathlib import Path
from datetime import datetime

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "evidence_mt.db"

SCHEMA_BASE = '''
CREATE TABLE IF NOT EXISTS tenants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE,
  created_at TEXT,
  is_active INTEGER DEFAULT 1
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

def _ensure_columns(con):
    # add last_login_at if missing
    cols = {r[1] for r in con.execute("PRAGMA table_info(users)").fetchall()}
    if "last_login_at" not in cols:
        con.execute("ALTER TABLE users ADD COLUMN last_login_at TEXT")

def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.executescript(SCHEMA_BASE)
        _ensure_columns(con)

def db():
    init_db()
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con
