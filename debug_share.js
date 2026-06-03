const db = require('./config/db');

(async () => {
  try {
    console.log('Checking for share between ahmadraza26.creative@gmail.com and ayazjutt126@gmail.com...\n');
    
    // First check if both users exist
    const sender = await db.query('SELECT id, email FROM users WHERE email = $1', ['ahmadraza26.creative@gmail.com']);
    const receiver = await db.query('SELECT id, email FROM users WHERE email = $1', ['ayazjutt126@gmail.com']);
    
    console.log('Sender found:', sender.rows[0] ? sender.rows[0].email : 'NOT FOUND');
    console.log('Receiver found:', receiver.rows[0] ? receiver.rows[0].email : 'NOT FOUND');
    
    if (!sender.rows[0] || !receiver.rows[0]) {
      console.log('\nOne or both users not found in database');
      process.exit(1);
    }
    
    // Get all shares
    const shares = await db.query(
      `SELECT ds.id, ds.document_id, ds.permission, ds.accepted, u.email as shared_with, sb.email as shared_by, d.filename 
       FROM document_shares ds
       LEFT JOIN users u ON ds.shared_with_user_id = u.id
       LEFT JOIN users sb ON ds.shared_by_id = sb.id
       LEFT JOIN documents d ON ds.document_id = d.id
       WHERE (u.email = $1 OR sb.email = $2)
       ORDER BY ds.created_at DESC LIMIT 20`,
      ['ayazjutt126@gmail.com', 'ahmadraza26.creative@gmail.com']
    );
    
    console.log('\nShares found:', shares.rowCount);
    console.log(JSON.stringify(shares.rows, null, 2));
    
    // Also check pending shares specifically for the receiver
    console.log('\n\nChecking pending shares for ayazjutt126@gmail.com...');
    const pending = await db.query(
      `SELECT ds.id, ds.document_id, ds.permission, ds.accepted, d.filename, sb.email as shared_by_email
       FROM document_shares ds
       JOIN documents d ON ds.document_id = d.id
       LEFT JOIN users sb ON ds.shared_by_id = sb.id
       WHERE ds.shared_with_user_id = $1 AND ds.accepted = $2`,
      [receiver.rows[0].id, false]
    );
    
    console.log('Pending shares:', pending.rowCount);
    console.log(JSON.stringify(pending.rows, null, 2));
    
    process.exit(0);
  } catch (err) {
    console.error('Error:', err);
    process.exit(1);
  }
})();
