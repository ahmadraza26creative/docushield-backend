const db = require('./config/db');
(async () => {
  try {
    await db.initDb();
    const userId = 1;
    const acceptedValue = true;
    const queryText = `
      SELECT DISTINCT d.id, d.filename, d.file_size, d.folder_path, d.file_hash, d.encryption_key, d.uploaded_at as created_at, d.uploaded_at as updated_at,
             u.email as owner_email,
             CASE 
               WHEN d.owner_id = $1 THEN 'owner'
               ELSE ds.permission
             END as effective_permission
      FROM documents d
      LEFT JOIN users u ON d.owner_id = u.id
      LEFT JOIN document_shares ds ON d.id = ds.document_id AND ((ds.shared_with_user_id = $1 AND ds.accepted = $2) OR ds.share_token IS NOT NULL)
      WHERE (d.owner_id = $1 OR ds.shared_with_user_id = $1)
      ORDER BY d.created_at DESC
    `;
    console.log('Query text:', queryText);
    const res = await db.query(queryText, [userId, acceptedValue]);
    console.log('Rows:', res.rows.length);
  } catch (err) {
    console.error(err);
  } finally {
    process.exit(0);
  }
})();
