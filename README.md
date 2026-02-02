# CUI Inspector – Complete Multi-Tenant Build

## Streamlit Secrets (required)
Set in Streamlit Cloud -> App -> Settings -> Secrets:

SUPERADMIN_USERNAME = "superadmin"
SUPERADMIN_PASSWORD = "ChangeMeNow!123"

On first run, the app bootstraps the SuperAdmin user if the DB is empty.

## Completed features (including the last 2 options)
- Data Flow Mapper persisted per-tenant in SQLite (data_flows table)
- Safe excerpt indexing is configurable per run:
  - store_excerpt ON: excerpt saved (up to 1200 chars)
  - store_excerpt OFF: metadata-only indexing (no text stored)

Plus:
- Evidence vault: hashes + timestamps
- Verify Evidence Vault: recompute SHA-256 and compare
- Search (metadata + optional safe excerpts)
- Compare runs (pattern deltas + risk delta)
- Export manifest ZIP (CSV + sha list + optional objects)
