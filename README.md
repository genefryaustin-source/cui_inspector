# CUI Inspector – Modular Multi-Tenant (Full, Migrated)

This build merges the Hotfix v3 schema migrations into the full application.

## Included feature updates (all 4)
1. **Evidence integrity verification**: Verify Evidence Vault recomputes SHA-256 and compares to DB.
2. **Full text / metadata search**: inspection_text_index stores safe excerpts + metadata for filtering.
3. **Artifact diff + compare runs**: Compare Runs shows risk/pattern/category deltas between two inspections.
4. **Role-based access**: users table + login + audit trail + SuperAdmin + Tenant Admin + Auditor.

## Tenant Admin setup
- SuperAdmin creates a tenant (Tenants page).
- SuperAdmin selects that tenant in the sidebar.
- SuperAdmin creates a `tenant_admin` user in Users page.
- Tenant Admin logs in and can create `viewer` / `analyst` users for that tenant.

## Streamlit Cloud notes
- SQLite database persists on Streamlit Cloud volume.
- db.py auto-migrates legacy schemas (users.last_login_at, tenants.is_active).

## Optional break-glass recovery (Secrets)
SUPERADMIN_RECOVERY="ENABLED"
SUPERADMIN_RECOVERY_PASSWORD="StrongPasswordHere"
Remove these after recovery.
