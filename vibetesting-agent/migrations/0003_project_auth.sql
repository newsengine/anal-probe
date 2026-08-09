-- Authenticated / internal scan access (opt-in test account session)
ALTER TABLE projects ADD COLUMN auth_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE projects ADD COLUMN auth_mode TEXT;
ALTER TABLE projects ADD COLUMN auth_email TEXT;
ALTER TABLE projects ADD COLUMN auth_secret_enc TEXT;
ALTER TABLE projects ADD COLUMN auth_login_url TEXT;
ALTER TABLE projects ADD COLUMN auth_verified_at INTEGER;
ALTER TABLE projects ADD COLUMN auth_updated_at INTEGER;
