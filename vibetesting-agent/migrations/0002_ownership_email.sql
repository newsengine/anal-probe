-- Ownership: domain email + inbox click verify, track method
ALTER TABLE users ADD COLUMN email_verified_at INTEGER;
ALTER TABLE users ADD COLUMN email_verify_token TEXT;
ALTER TABLE users ADD COLUMN email_verify_expires_at INTEGER;
ALTER TABLE projects ADD COLUMN verify_method TEXT;
