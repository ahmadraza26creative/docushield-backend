require('dotenv').config();
const db = require('./config/db');
(async () => {
  if (db.initDb) await db.initDb();
  const email = 'ayazjutt126@gmail.com';
  const userRes = await db.query('SELECT id,email FROM users WHERE email = $1', [email]);
  console.log('User rows:', JSON.stringify(userRes.rows, null, 2));
  if (userRes.rowCount === 0) {
    console.log('No user found');
    process.exit(0);
  }
  const uid = userRes.rows[0].id;
  const shares = await db.query(
    'SELECT ds.id, ds.document_id, ds.permission, ds.expires_at, ds.accepted, ds.shared_by_id, sb.email as shared_by_email FROM document_shares ds LEFT JOIN users sb ON ds.shared_by_id = sb.id WHERE ds.shared_with_user_id = $1 ORDER BY ds.created_at DESC',
    [uid]
  );
  console.log('Shares rows:', JSON.stringify(shares.rows, null, 2));
  process.exit(0);
})();
