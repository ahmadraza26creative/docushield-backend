const pool = require('../src/config/db');

async function initDb() {
  await pool.query('SELECT NOW()');
  await setupPostgresTables();
  console.log('Database connected successfully');
}

async function setupPostgresTables() {
  await pool.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto"');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      full_name TEXT NOT NULL DEFAULT 'Default User',
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'editor' CHECK (role IN ('admin', 'editor', 'viewer')),
      department TEXT,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
      mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
      mfa_secret TEXT,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      filename TEXT NOT NULL,
      encrypted_filename TEXT NOT NULL,
      file_size BIGINT NOT NULL,
      file_hash TEXT,
      encryption_key TEXT NOT NULL,
      folder_path TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      uploaded_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS shared_links (
      id TEXT PRIMARY KEY,
      document_id TEXT REFERENCES documents(id) ON DELETE CASCADE,
      created_by INTEGER REFERENCES users(id) ON DELETE CASCADE,
      expiry_date TIMESTAMPTZ,
      password_protected TEXT,
      allowed_ip TEXT,
      max_views INTEGER,
      current_views INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS document_shares (
      id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      document_id TEXT REFERENCES documents(id) ON DELETE CASCADE,
      shared_with_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      permission TEXT NOT NULL DEFAULT 'viewer' CHECK (permission IN ('editor', 'viewer')),
      shared_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      share_token TEXT UNIQUE,
      allowed_ip TEXT,
      max_views INTEGER,
      current_views INTEGER NOT NULL DEFAULT 0,
      password_protected TEXT,
      expires_at TIMESTAMPTZ,
      accepted BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      document_id TEXT REFERENCES documents(id) ON DELETE SET NULL,
      ip_address TEXT NOT NULL,
      device_info TEXT,
      user_agent TEXT,
      details JSONB,
      severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
      timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      device_fingerprint TEXT,
      login_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      last_activity TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      is_active BOOLEAN NOT NULL DEFAULT TRUE
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS security_alerts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      severity TEXT NOT NULL DEFAULT 'warning' CHECK (severity IN ('info', 'warning', 'critical')),
      title TEXT NOT NULL,
      description TEXT,
      source TEXT NOT NULL DEFAULT 'system',
      is_resolved BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const migrations = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name TEXT NOT NULL DEFAULT 'Default User'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS department TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT",
    "ALTER TABLE documents ADD COLUMN IF NOT EXISTS file_hash TEXT",
    "ALTER TABLE documents ADD COLUMN IF NOT EXISTS folder_path TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE documents ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP",
    "ALTER TABLE documents ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP",
    "ALTER TABLE documents ADD COLUMN IF NOT EXISTS uploaded_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP",
    "ALTER TABLE shared_links ADD COLUMN IF NOT EXISTS allowed_ip TEXT",
    "ALTER TABLE shared_links ADD COLUMN IF NOT EXISTS max_views INTEGER",
    "ALTER TABLE shared_links ADD COLUMN IF NOT EXISTS current_views INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE shared_links ADD COLUMN IF NOT EXISTS password_protected TEXT",
    "ALTER TABLE document_shares ADD COLUMN IF NOT EXISTS allowed_ip TEXT",
    "ALTER TABLE document_shares ADD COLUMN IF NOT EXISTS max_views INTEGER",
    "ALTER TABLE document_shares ADD COLUMN IF NOT EXISTS current_views INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE document_shares ADD COLUMN IF NOT EXISTS password_protected TEXT",
    "ALTER TABLE document_shares ADD COLUMN IF NOT EXISTS accepted BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS document_id TEXT REFERENCES documents(id) ON DELETE SET NULL",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS device_info TEXT",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS user_agent TEXT",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS details JSONB",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT 'info'",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP",
    "ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'system'",
    "ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS is_resolved BOOLEAN NOT NULL DEFAULT FALSE"
  ];

  for (const migration of migrations) {
    await pool.query(migration);
  }

  await pool.query(`
    CREATE OR REPLACE VIEW sharing_links AS
    SELECT * FROM shared_links
  `);

  await pool.query(`
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
    FROM document_shares
  `);

  await pool.query('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_documents_folder ON documents(folder_path)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_shared_links_doc ON shared_links(document_id)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_document_shares_doc ON document_shares(document_id)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_document_shares_user ON document_shares(shared_with_user_id)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_audit_logs_doc ON audit_logs(document_id)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_active)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_security_alerts_user ON security_alerts(user_id)');
}

async function query(text, params = []) {
  const result = await pool.query(text, params);
  return { rows: result.rows, rowCount: result.rowCount };
}

module.exports = {
  initDb,
  query,
  pool
};
