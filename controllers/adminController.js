const db = require('../config/db');
const { logSecurityEvent } = require('../utils/auditLogger');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const ENCRYPTED_DIR = path.resolve(__dirname, '..', 'uploads', 'encrypted');

/**
 * List all users (Admin only)
 */
async function listUsers(req, res) {
  try {
    const userRes = await db.query(
      'SELECT id, email, role, status, created_at, mfa_enabled FROM users ORDER BY created_at DESC'
    );
    res.json({ users: userRes.rows });
  } catch (err) {
    console.error('List Users Error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve user accounts.' });
  }
}

/**
 * Modify user role (Admin only)
 */
async function updateUserRole(req, res) {
  const { id } = req.params;
  const { role } = req.body;

  if (!['admin', 'editor', 'viewer'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role specified.' });
  }

  try {
    // Prevent self-demotion
    if (parseInt(id) === req.user.id) {
      return res.status(400).json({ error: 'Admins cannot change their own roles.' });
    }

    const currentRes = await db.query('SELECT email, role FROM users WHERE id = $1', [id]);
    if (currentRes.rowCount === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = currentRes.rows[0];

    await db.query('UPDATE users SET role = $1 WHERE id = $2', [role, id]);

    await logSecurityEvent({
      userId: req.user.id,
      action: 'USER_ROLE_CHANGE',
      req,
      details: { targetUserId: id, targetEmail: user.email, oldRole: user.role, newRole: role },
      severity: 'warning'
    });

    res.json({ message: `Successfully updated user role to ${role}.` });
  } catch (err) {
    console.error('Update User Role Error:', err.message);
    res.status(500).json({ error: 'Failed to update user role.' });
  }
}

/**
 * Suspend / Activate user (Admin only)
 */
async function updateUserStatus(req, res) {
  const { id } = req.params;
  const { status } = req.body;

  if (!['active', 'suspended'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status specified.' });
  }

  try {
    // Prevent self-suspension
    if (parseInt(id) === req.user.id) {
      return res.status(400).json({ error: 'Admins cannot suspend themselves.' });
    }

    const currentRes = await db.query('SELECT email, status FROM users WHERE id = $1', [id]);
    if (currentRes.rowCount === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = currentRes.rows[0];

    await db.query('UPDATE users SET status = $1 WHERE id = $2', [status, id]);

    await logSecurityEvent({
      userId: req.user.id,
      action: status === 'suspended' ? 'USER_SUSPEND' : 'USER_ACTIVATE',
      req,
      details: { targetUserId: id, targetEmail: user.email },
      severity: 'critical'
    });

    res.json({ message: `User account is now ${status}.` });
  } catch (err) {
    console.error('Update User Status Error:', err.message);
    res.status(500).json({ error: 'Failed to update user status.' });
  }
}

/**
 * Create a new user (Admin only)
 */
async function createUser(req, res) {
  const { email, password, full_name, role, department } = req.body;
  if (!email || !password || !full_name || !role) {
    return res.status(400).json({ error: 'Full name, email, password, and role are required.' });
  }
  
  try {
    const existing = await db.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rowCount > 0) {
      return res.status(400).json({ error: 'Email is already registered.' });
    }
    
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);
    await db.query(
      `INSERT INTO users (full_name, email, password_hash, role, department, is_active, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'active')`,
      [full_name, email, passwordHash, role, department || null, true]
    );
    
    await logSecurityEvent({
      userId: req.user.id,
      action: 'ADMIN_CREATE_USER',
      req,
      details: { createdEmail: email, role }
    });
    
    res.status(201).json({ message: 'User created successfully.' });
  } catch (err) {
    console.error('Admin Create User Error:', err.message);
    res.status(500).json({ error: 'Failed to create user account.' });
  }
}

/**
 * Delete a user account (Admin only)
 */
async function deleteUser(req, res) {
  const { id } = req.params;
  
  if (parseInt(id) === req.user.id) {
    return res.status(400).json({ error: 'Admins cannot delete their own accounts.' });
  }
  
  try {
    const currentRes = await db.query('SELECT email FROM users WHERE id = $1', [id]);
    if (currentRes.rowCount === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }
    const user = currentRes.rows[0];
    
    // Delete user
    await db.query('DELETE FROM users WHERE id = $1', [id]);
    
    await logSecurityEvent({
      userId: req.user.id,
      action: 'ADMIN_DELETE_USER',
      req,
      details: { deletedUserId: id, deletedEmail: user.email },
      severity: 'critical'
    });
    
    res.json({ message: 'User account deleted successfully.' });
  } catch (err) {
    console.error('Admin Delete User Error:', err.message);
    res.status(500).json({ error: 'Failed to delete user account.' });
  }
}

/**
 * List all documents globally (Admin only)
 */
async function listAllDocuments(req, res) {
  try {
    const docRes = await db.query(`
      SELECT d.id, d.filename as title, 
             d.encrypted_filename as encrypted_path, 
             d.file_size, d.file_hash, d.created_at, u.email as owner_email
      FROM documents d
      LEFT JOIN users u ON d.owner_id = u.id
      ORDER BY d.created_at DESC
    `);
    res.json({ documents: docRes.rows });
  } catch (err) {
    console.error('Admin List Documents Error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve all documents.' });
  }
}

/**
 * Revoke and delete document (Admin only)
 */
async function revokeDocument(req, res) {
  const { id } = req.params;
  
  try {
    const docRes = await db.query('SELECT * FROM documents WHERE id = $1', [id]);
    if (docRes.rowCount === 0) {
      return res.status(404).json({ error: 'Document not found.' });
    }
    const doc = docRes.rows[0];
    
    // Delete from disk
    const encryptedFileName = doc.encrypted_filename;
    const encryptedFilePath = path.join(ENCRYPTED_DIR, encryptedFileName);
    if (fs.existsSync(encryptedFilePath)) {
      fs.unlinkSync(encryptedFilePath);
    }
    
    // Delete from DB
    await db.query('DELETE FROM documents WHERE id = $1', [id]);
    
    const filename = doc.filename;
    await logSecurityEvent({
      userId: req.user.id,
      action: 'ADMIN_REVOKE_DOCUMENT',
      req,
      details: { documentId: id, title: filename },
      severity: 'critical'
    });
    
    res.json({ message: 'Document access successfully revoked and purged.' });
  } catch (err) {
    console.error('Admin Revoke Document Error:', err.message);
    res.status(500).json({ error: 'Failed to revoke document access.' });
  }
}

/**
 * Get System-wide Telemetry & Metrics (Admin only)
 */
async function getSystemMetrics(req, res) {
  try {
    // Count totals
    const userCountRes = await db.query('SELECT COUNT(*) as count FROM users');
    const docCountRes = await db.query('SELECT COUNT(*) as count, SUM(file_size) as total_size FROM documents');
    const sharesCountRes = await db.query('SELECT COUNT(*) as count FROM document_shares');
    const logsCountRes = await db.query('SELECT COUNT(*) as count FROM audit_logs');
    
    // Critical alert counts (warnings/criticals)
    const alertCountRes = await db.query(
      "SELECT COUNT(*) as count FROM audit_logs WHERE severity IN ('warning', 'critical')"
    );

    // Recent critical logs
    const recentAlertsRes = await db.query(
      `SELECT al.*, u.email as user_email 
       FROM audit_logs al
       LEFT JOIN users u ON al.user_id = u.id
       WHERE al.severity IN ('warning', 'critical')
       ORDER BY al.created_at DESC
       LIMIT 5`
    );

    const recentAlerts = recentAlertsRes.rows.map(row => {
      if (typeof row.details === 'string') {
        try { row.details = JSON.parse(row.details); } catch {}
      }
      return row;
    });

    res.json({
      metrics: {
        totalUsers: parseInt(userCountRes.rows[0].count || 0),
        totalDocuments: parseInt(docCountRes.rows[0].count || 0),
        totalStorage: parseInt(docCountRes.rows[0].total_size || 0),
        totalShares: parseInt(sharesCountRes.rows[0].count || 0),
        totalAuditLogs: parseInt(logsCountRes.rows[0].count || 0),
        criticalAlertsCount: parseInt(alertCountRes.rows[0].count || 0)
      },
      recentAlerts
    });

  } catch (err) {
    console.error('Get System Metrics Error:', err.message);
    res.status(500).json({ error: 'Failed to compile system metrics.' });
  }
}

module.exports = {
  listUsers,
  updateUserRole,
  updateUserStatus,
  createUser,
  deleteUser,
  listAllDocuments,
  revokeDocument,
  getSystemMetrics
};
