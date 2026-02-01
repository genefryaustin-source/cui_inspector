import sqlite3
from pathlib import Path
from datetime import datetime

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "evidence_mt.db"

SCHEMA_SQL = r'''
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS tenants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  last_login_at TEXT,
  FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER,
  user_id INTEGER,
  event_type TEXT NOT NULL,
  details_json TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE SET NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER NOT NULL,
  logical_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(tenant_id, logical_name),
  FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS artifact_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER NOT NULL,
  artifact_id INTEGER NOT NULL,
  version_int INTEGER NOT NULL,
  original_filename TEXT NOT NULL,
  object_relpath TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  mime TEXT,
  created_at TEXT NOT NULL,
  uploaded_by TEXT,
  UNIQUE(artifact_id, version_int),
  FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY(artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS inspections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER NOT NULL,
  artifact_version_id INTEGER,
  run_type TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  cui_detected INTEGER,
  risk_level TEXT,
  patterns_json TEXT,
  categories_json TEXT,
  summary_json TEXT,
  error TEXT,
  FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY(artifact_version_id) REFERENCES artifact_versions(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evidence_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER NOT NULL,
  inspection_id INTEGER NOT NULL,
  kind TEXT NOT NULL,
  filename TEXT NOT NULL,
  object_relpath TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY(inspection_id) REFERENCES inspections(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS inspection_text_index (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER NOT NULL,
  inspection_id INTEGER NOT NULL,
  artifact_version_id INTEGER,
  filename TEXT,
  file_ext TEXT,
  safe_excerpt TEXT,
  char_count INTEGER,
  word_count INTEGER,
  patterns_total INTEGER,
  categories_json TEXT,
  risk_level TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY(inspection_id) REFERENCES inspections(id) ON DELETE CASCADE,
  FOREIGN KEY(artifact_version_id) REFERENCES artifact_versions(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_inspections_tenant_started ON inspections(tenant_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_artifact_versions_tenant_sha ON artifact_versions(tenant_id, sha256);
CREATE INDEX IF NOT EXISTS idx_evidence_files_tenant_sha ON evidence_files(tenant_id, sha256);
CREATE INDEX IF NOT EXISTS idx_text_index_tenant_risk ON inspection_text_index(tenant_id, risk_level);
CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at DESC);
'''

def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def init_db() -> None:
    with sqlite3.connect(DB_PATH) as con:
        con.executescript(SCHEMA_SQL)

def db():
    init_db()
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON;")
    return con
