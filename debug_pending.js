const db = require('./config/db');

(async () => {
  try {
    console.log('=== CHECKING PENDING SHARES ===\n');
    
    // Get all users
    const users = await db.query('SELECT id, email FROM users LIMIT 5');
    console.log('Users in database:', users.rows);
    
    // Get receiver user
    const receiver = await db.query('SELECT id, email FROM users WHERE email = $1', ['ayazjutt126@gmail.com']);
    if (!receiver.rows[0]) {
      console.log('Receiver not found');
      process.exit(1);
    }
    
    const receiverId = receiver.rows[0].id;
    console.log(`\nReceiver: ${receiver.rows[0].email} (ID: ${receiverId})`);
    
    // Check all document_shares for this user
    console.log(`\n--- ALL DOCUMENT_SHARES FOR USER ${receiverId} ---`);
    const allShares = await db.query(
      `SELECT ds.id, ds.document_id, ds.permission, ds.accepted, ds.shared_with_user_id, ds.shared_by_id, d.filename
       FROM document_shares ds
       LEFT JOIN documents d ON ds.document_id = d.id
       WHERE ds.shared_with_user_id = $1
       ORDER BY ds.created_at DESC`,
      [receiverId]
    );
    
    console.log(`Found ${allShares.rowCount} shares`);
    allShares.rows.forEach(row => {
      console.log(`- Share ID: ${row.id}, Doc: ${row.filename}, Accepted: ${row.accepted}, Permission: ${row.permission}`);
    });
    
    // Check pending shares (accepted = false)
    console.log(`\n--- PENDING SHARES (ACCEPTED = FALSE) ---`);
    const pending = await db.query(
      `SELECT ds.id, ds.document_id, ds.permission, ds.accepted, d.filename
       FROM document_shares ds
       LEFT JOIN documents d ON ds.document_id = d.id
       WHERE ds.shared_with_user_id = $1 AND ds.accepted = $2`,
      [receiverId, false]
    );
    
    console.log(`Found ${pending.rowCount} pending shares`);
    pending.rows.forEach(row => {
      console.log(`- Share ID: ${row.id}, Doc: ${row.filename}, Accepted: ${row.accepted}`);
    });
    
    process.exit(0);
  } catch (err) {
    console.error('Error:', err);
    process.exit(1);
  }
})();
