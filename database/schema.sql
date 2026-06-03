-- DocuShield PostgreSQL schema for Neon, Render, Railway, and Koyeb.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  full_name TEXT NOT NULL DEFAULT 'Default User',
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role VARCHAR(50) NOT NULL DEFAULT 'editor' CHECK (role IN ('admin', 'editor', 'viewer')),
  department VARCHAR(100),
  is_active BOOLEAN NOT NULL DEFAULT true,
  status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  mfa_enabled BOOLEAN NOT NULL DEFAULT false,
  mfa_secret TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  encrypted_filename TEXT NOT NULL,
  file_size BIGINT NOT NULL,
  file_hash TEXT,
  encryption_key TEXT NOT NULL,
  folder_path TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS shared_links (
  id TEXT PRIMARY KEY,
  document_id TEXT REFERENCES documents(id) ON DELETE CASCADE,
  created_by INTEGER REFERENCES users(id) ON DELETE CASCADE,
  expiry_date TIMESTAMP,
  password_protected TEXT,
  allowed_ip TEXT,
  max_views INTEGER,
  current_views INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS document_shares (
  id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  document_id TEXT REFERENCES documents(id) ON DELETE CASCADE,
  shared_with_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  permission VARCHAR(50) NOT NULL DEFAULT 'viewer' CHECK (permission IN ('editor', 'viewer')),
  shared_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  share_token TEXT UNIQUE,
  allowed_ip TEXT,
  max_views INTEGER,
  current_views INTEGER NOT NULL DEFAULT 0,
  password_protected TEXT,
  expires_at TIMESTAMP,
  accepted BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  document_id TEXT REFERENCES documents(id) ON DELETE SET NULL,
  ip_address TEXT NOT NULL,
  device_info TEXT,
  user_agent TEXT,
  details JSONB,
  severity VARCHAR(50) NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_fingerprint TEXT,
  login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  is_active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS security_alerts (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  severity VARCHAR(50) NOT NULL DEFAULT 'warning' CHECK (severity IN ('info', 'warning', 'critical')),
  title TEXT NOT NULL,
  description TEXT,
  source TEXT NOT NULL DEFAULT 'system',
  is_resolved BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE VIEW sharing_links AS
SELECT * FROM shared_links;

CREATE OR REPLACE VIEW document_permissions AS
SELECT
  id,
  document_id,
  shared_with_user_id AS user_id,
  permission,
  shared_by_id,
  expires_at,
  accepted,
  created_at
FROM document_shares;

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_folder ON documents(folder_path);
CREATE INDEX IF NOT EXISTS idx_shared_links_doc ON shared_links(document_id);
CREATE INDEX IF NOT EXISTS idx_document_shares_doc ON document_shares(document_id);
CREATE INDEX IF NOT EXISTS idx_document_shares_user ON document_shares(shared_with_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_doc ON audit_logs(document_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_security_alerts_user ON security_alerts(user_id);
