-- Optional DocuShield Neon seed.
-- Replace the placeholders before running this file.
-- Generate a password hash with bcrypt and never store a plain password here.

-- INSERT INTO users (full_name, email, password_hash, role, department)
-- VALUES (
--   'Admin User',
--   'admin@example.com',
--   '$2b$10$replace_with_real_bcrypt_hash',
--   'admin',
--   'Security'
-- )
-- ON CONFLICT (email) DO UPDATE
-- SET role = EXCLUDED.role,
--     full_name = EXCLUDED.full_name,
--     department = EXCLUDED.department;

INSERT INTO security_alerts (severity, title, description, source)
VALUES
  ('info', 'Deployment ready', 'DocuShield schema was initialized successfully.', 'seed')
ON CONFLICT DO NOTHING;
