const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../config/db');
const { logSecurityEvent } = require('../utils/auditLogger');

/**
 * Share a document with another user or generate a secure public link
 */
async function shareDocument(req, res) {
  const { documentId } = req.body;
  const { targetEmail, permission, generateLink, expiresHours, allowedIp, maxViews, password } = req.body;
  const userId = req.user.id;
  const userRole = req.user.role;

  try {
    // 1. Verify document ownership / permissions
    const docRes = await db.query('SELECT * FROM documents WHERE id = $1', [documentId]);
    if (docRes.rowCount === 0) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    const doc = docRes.rows[0];

    // Only owner or admin can share (Least Privilege)
    if (doc.owner_id !== userId && userRole !== 'admin') {
      await logSecurityEvent({
        userId,
        action: 'ACCESS_DENIED',
        req,
        details: { documentId, action: 'Share document attempt' },
        severity: 'critical'
      });
      return res.status(403).json({ error: 'Unauthorized to share this document.' });
    }

    // Expiry calculation
    let expiresAt = null;
    if (expiresHours) {
      expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + parseInt(expiresHours));
    }

    // Hash password if provided for protected links
    let hashedPassword = null;
    if (password) {
      const salt = await bcrypt.genSalt(10);
      hashedPassword = await bcrypt.hash(password, salt);
    }

    // A. Direct User-to-User Share
    if (targetEmail) {
      // Find recipient
      const recipientRes = await db.query('SELECT id FROM users WHERE email = $1', [targetEmail]);
      if (recipientRes.rowCount === 0) {
        return res.status(404).json({ error: 'Recipient user email not found.' });
      }

      const recipientId = recipientRes.rows[0].id;
      console.log(`[SHARE DEBUG] Creating invitation: doc=${documentId}, from=${userId}, to=${recipientId} (${targetEmail}), accepted=false`);

      if (recipientId === doc.owner_id) {
        return res.status(400).json({ error: 'Cannot share a document with its owner.' });
      }

      const existingShare = await db.query(
        'SELECT id, accepted FROM document_shares WHERE document_id = $1 AND shared_with_user_id = $2',
        [documentId, recipientId]
      );

      if (existingShare.rowCount > 0) {
        const wasAccepted = existingShare.rows[0].accepted;
        console.log(`[SHARE DEBUG] Updating existing share: ${existingShare.rows[0].id}, keeping accepted=${wasAccepted}`);
        await db.query(
          'UPDATE document_shares SET permission = $1, expires_at = $2, accepted = $3 WHERE document_id = $4 AND shared_with_user_id = $5',
          [permission || 'viewer', expiresAt, wasAccepted, documentId, recipientId]
        );
      } else {
        const shareId = crypto.randomUUID();
        console.log(`[SHARE DEBUG] Inserting new share: ${shareId}`);
        await db.query(
          `INSERT INTO document_shares (id, document_id, shared_with_user_id, permission, shared_by_id, expires_at, accepted)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [shareId, documentId, recipientId, permission || 'viewer', userId, expiresAt, false]
        );
      }

      await logSecurityEvent({
        userId,
        action: 'SHARE_GRANT',
        req,
        details: { documentId, recipientEmail: targetEmail, permission: permission || 'viewer', pending: true }
      });

      return res.json({ message: `Successfully created share invitation for ${targetEmail}. They must accept access to complete the transfer.` });
    }

    // B. Create a secure public share link token
    if (generateLink) {
      const shareToken = crypto.randomUUID();

      await db.query(
        `INSERT INTO shared_links (id, document_id, created_by, expiry_date, password_protected, allowed_ip, max_views, current_views)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 0)`,
        [shareToken, documentId, userId, expiresAt, hashedPassword, allowedIp || null, maxViews ? parseInt(maxViews) : null]
      );

      await logSecurityEvent({
        userId,
        action: 'SHARE_LINK_GENERATE',
        req,
        details: { documentId, permission: permission || 'viewer', expiresAt, allowedIp, maxViews }
      });

      return res.json({ 
        message: 'Secure share link generated successfully.',
        shareToken,
        expiresAt
      });
    }

    res.status(400).json({ error: 'Please specify targetEmail or generateLink parameter.' });

  } catch (err) {
    console.error('Share Document Error:', err.message);
    res.status(500).json({ error: 'Failed to share document.' });
  }
}

/**
 * List all shares associated with a document
 */
async function listDocumentShares(req, res) {
  const { documentId } = req.params;
  const userId = req.user.id;
  const userRole = req.user.role;

  try {
    // Verify document permission
    const docRes = await db.query('SELECT owner_id FROM documents WHERE id = $1', [documentId]);
    if (docRes.rowCount === 0) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    if (docRes.rows[0].owner_id !== userId && userRole !== 'admin') {
      return res.status(403).json({ error: 'Access denied.' });
    }

    const linkSharesRes = await db.query(
      `SELECT sl.id, sl.expiry_date as expires_at, sl.allowed_ip, sl.max_views, sl.current_views, sl.password_protected,
              u.email as shared_by_email
       FROM shared_links sl
       LEFT JOIN users u ON sl.created_by = u.id
       WHERE sl.document_id = $1 AND (sl.allowed_ip IS NULL OR sl.allowed_ip NOT LIKE 'user:%')`,
      [documentId]
    );
    const directSharesRes = await db.query(
      `SELECT ds.id, ds.permission, ds.share_token, ds.expires_at, ds.created_at, ds.allowed_ip, ds.max_views, ds.current_views, ds.password_protected, ds.accepted::BOOLEAN as accepted,
              u.email as shared_with_email, sb.email as shared_by_email
       FROM document_shares ds
       LEFT JOIN users u ON ds.shared_with_user_id = u.id
       LEFT JOIN users sb ON ds.shared_by_id = sb.id
       WHERE ds.document_id = $1`,
      [documentId]
    );
    const shares = directSharesRes.rows.map(row => ({
      id: row.id,
      permission: row.permission,
      share_token: row.share_token,
      allowed_ip: row.allowed_ip,
      max_views: row.max_views,
      current_views: row.current_views,
      password_protected: !!row.password_protected,
      accepted: !!row.accepted,
      expires_at: row.expires_at,
      shared_with_email: row.shared_with_email,
      shared_by_email: row.shared_by_email
    }));
    shares.push(...linkSharesRes.rows.map(row => ({
      id: row.id,
      permission: 'link',
      share_token: row.id,
      allowed_ip: row.allowed_ip,
      max_views: row.max_views,
      current_views: row.current_views,
      password_protected: !!row.password_protected,
      expires_at: row.expires_at,
      shared_with_email: null,
      shared_by_email: row.shared_by_email
    })));

    res.json({ shares });
  } catch (err) {
    console.error('List shares error:', err.message);
    res.status(500).json({ error: 'Failed to fetch shares.' });
  }
}

async function listPendingShares(req, res) {
  const userId = req.user.id;

  try {
    const pendingRes = await db.query(
      `SELECT ds.id, ds.document_id, ds.permission, ds.expires_at, ds.created_at,
              d.filename AS title,
              u.email AS owner_email,
              sb.email AS shared_by_email
       FROM document_shares ds
       JOIN documents d ON ds.document_id = d.id
       LEFT JOIN users u ON d.owner_id = u.id
       LEFT JOIN users sb ON ds.shared_by_id = sb.id
       WHERE ds.shared_with_user_id = $1
         AND ds.accepted::BOOLEAN = $2`,
      [userId, false]
    );

    console.log(`[PENDING DEBUG] User ${userId} - Query returned ${pendingRes.rowCount} pending shares`);
    if (pendingRes.rowCount > 0) {
      console.log(`[PENDING DEBUG] Rows:`, pendingRes.rows.map(r => ({ id: r.id, doc: r.document_id, accepted: r.accepted })));
    }
    
    const pendingShares = pendingRes.rows.map(row => ({
      id: row.id,
      documentId: row.document_id,
      title: row.title,
      permission: row.permission,
      expires_at: row.expires_at,
      created_at: row.created_at,
      owner_email: row.owner_email,
      shared_by_email: row.shared_by_email
    }));

    res.json({ pendingShares });
  } catch (err) {
    console.error('List pending shares error:', err.message);
    res.status(500).json({ error: 'Failed to fetch pending share invitations.' });
  }
}

async function acceptShare(req, res) {
  const { shareId } = req.params;
  const userId = req.user.id;

  try {
    const shareRes = await db.query(
      'SELECT id, document_id, expires_at, accepted FROM document_shares WHERE id = $1 AND shared_with_user_id = $2',
      [shareId, userId]
    );

    if (shareRes.rowCount === 0) {
      return res.status(404).json({ error: 'Share invitation not found.' });
    }

    const share = shareRes.rows[0];
    const expiresAt = share.expires_at ? new Date(share.expires_at) : null;
    if (expiresAt && expiresAt <= new Date()) {
      return res.status(403).json({ error: 'This share invitation has expired.' });
    }

    if (share.accepted) {
      return res.json({ message: 'This share invitation was already accepted.' });
    }

    await db.query('UPDATE document_shares SET accepted = $1 WHERE id = $2', [true, shareId]);

    await logSecurityEvent({
      userId,
      action: 'SHARE_ACCEPTED',
      req,
      details: { documentId: share.document_id, shareId }
    });

    res.json({ message: 'Share invitation accepted. The document is now visible in your Shared With Me list.' });
  } catch (err) {
    console.error('Accept share error:', err.message);
    res.status(500).json({ error: 'Failed to accept the share invitation.' });
  }
}

/**
 * Revoke shares
 */
async function revokeShare(req, res) {
  const { shareId } = req.params;
  const userId = req.user.id;
  const userRole = req.user.role;

  try {
    let share = null;

    const shareRes = await db.query(
      `SELECT sl.*, d.owner_id, 'shared_links' as source_table
       FROM shared_links sl 
       JOIN documents d ON sl.document_id = d.id 
       WHERE sl.id = $1`,
      [shareId]
    );
    if (shareRes.rowCount > 0) {
      share = shareRes.rows[0];
    } else {
      const directShareRes = await db.query(
        `SELECT ds.*, d.owner_id, 'document_shares' as source_table
         FROM document_shares ds
         JOIN documents d ON ds.document_id = d.id
         WHERE ds.id = $1`,
        [shareId]
      );
      if (directShareRes.rowCount > 0) {
        share = directShareRes.rows[0];
      }
    }

    if (!share) {
      return res.status(404).json({ error: 'Share record not found.' });
    }

    // Only owner of document or admin can revoke shares
    if (share.owner_id !== userId && userRole !== 'admin') {
      return res.status(403).json({ error: 'Access denied.' });
    }

    if (share.source_table === 'document_shares') {
      await db.query('DELETE FROM document_shares WHERE id = $1', [shareId]);
    } else {
      await db.query('DELETE FROM shared_links WHERE id = $1', [shareId]);
    }

    await logSecurityEvent({
      userId,
      action: 'SHARE_REVOKE',
      req,
      details: { documentId: share.document_id, revokedUserId: share.shared_with_user_id || share.allowed_ip, shareToken: !!share.share_token || !share.allowed_ip }
    });

    res.json({ message: 'Share access revoked successfully.' });

  } catch (err) {
    console.error('Revoke share error:', err.message);
    res.status(500).json({ error: 'Failed to revoke share.' });
  }
}

module.exports = {
  shareDocument,
  listDocumentShares,
  listPendingShares,
  acceptShare,
  revokeShare
};
