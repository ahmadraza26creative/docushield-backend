const db = require('./config/db');
(async () => {
  try {
    await db.initDb();
    const res = await db.query('SELECT id FROM document_shares WHERE accepted = $1 LIMIT 1', [true]);
    console.log('simple boolean query rows', res.rows.length);
    const res2 = await db.query('SELECT id FROM document_shares WHERE shared_with_user_id = $1 AND accepted = $2 LIMIT 1', [1, true]);
    console.log('simple combined query rows', res2.rows.length);
  } catch (err) {
    console.error(err);
  } finally {
    process.exit(0);
  }
})();
