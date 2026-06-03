const db = require('../config/db');
const { logSecurityEvent } = require('../utils/auditLogger');
const bcrypt = require('bcryptjs');

/**
 * Helper to match requester IP against allowed IP or CIDR block
 */
function ipMatches(requesterIp, allowedIp) {
  if (!allowedIp) return true;
  
  // Clean up IPv6 loopback or standard representations
  const cleanRequester = requesterIp.replace('::ffff:', '').trim();
  const cleanAllowed = allowedIp.replace('::ffff:', '').trim();
  
  if (cleanAllowed === '*' || cleanAllowed === '0.0.0.0/0') return true;
  
  // Basic equality check
  if (cleanRequester === cleanAllowed) return true;
  
  // Support CIDR blocks (e.g. 192.168.1.0/24)
  if (cleanAllowed.includes('/')) {
    try {
      const [subnet, mask] = cleanAllowed.split('/');
      const maskBits = parseInt(mask);
      
      const requesterParts = cleanRequester.split('.').map(Number);
      const subnetParts = subnet.split('.').map(Number);
      
      if (requesterParts.some(isNaN) || subnetParts.some(isNaN)) return false;
      
      const requesterNum = (requesterParts[0] << 24) + (requesterParts[1] << 16) + (requesterParts[2] << 8) + requesterParts[3];
      const subnetNum = (subnetParts[0] << 24) + (subnetParts[1] << 16) + (subnetParts[2] << 8) + subnetParts[3];
      
      const maskVal = ~((1 << (32 - maskBits)) - 1);
      
      return (requesterNum & maskVal) === (subnetNum & maskVal);
    } catch {
      return false;
    }
  }
  
  return false;
}

/**
 * Zero-Trust Policy Engine Middleware: verifyAccess()
 * 
 * Intercepts every document access (download, preview, delete, rename, move) and evaluates
 * cryptographic, contextual, behavioral, and lifecycle policies dynamically.
 */
async function verifyAccess(req, res, next) {
  const docId = req.params.id || req.body.documentId || req.query.documentId;
  const userId = req.user?.id;
  const userRole = req.user?.role;
  const sessionId = req.sessionId;
  const shareToken = req.query.share_token || req.body.share_token;

  if (!docId) {
    return res.status(400).json({ error: 'Zero-Trust Engine Denied: Document ID is missing.' });
  }

  try {
    // -------------------------------------------------------------
    // POLICY CONTROLS 1 & 2: JWT & Session Validation
    // -------------------------------------------------------------
    if (!userId || !sessionId) {
      return res.status(401).json({ error: 'Zero-Trust Engine Denied: Invalid authentication state.' });
    }

    const sessionRes = await db.query(
      'SELECT is_active, device_fingerprint FROM sessions WHERE id = $1',
      [sessionId]
    );

    if (sessionRes.rowCount === 0) {
      return res.status(401).json({ error: 'Zero-Trust Engine Denied: Active session not found.' });
    }

    const session = sessionRes.rows[0];
    const isSessionActive = session.is_active === true || session.is_active === 1 || session.is_active === '1';
    
    if (!isSessionActive) {
      return res.status(401).json({ error: 'Zero-Trust Engine Denied: Session is suspended or revoked.' });
    }

    // -------------------------------------------------------------
    // POLICY CONTROL 3: Device Fingerprint Binding
    // -------------------------------------------------------------
    // Extract request fingerprint to match against session signature
    const requestFingerprint = req.headers['x-device-fingerprint'] || req.query.device_fingerprint || req.body.device_fingerprint || 'unknown';
    
    if (session.device_fingerprint && session.device_fingerprint !== 'unknown' && requestFingerprint !== 'unknown') {
      if (session.device_fingerprint !== requestFingerprint) {
        await logSecurityEvent({
          userId,
          action: 'TOKEN_HIJACK_ATTEMPT',
          req,
          details: { sessionId, storedFingerprint: session.device_fingerprint, requestFingerprint },
          severity: 'critical'
        });
        return res.status(403).json({ 
          error: 'Zero-Trust Engine Denied: Session hijack attempt blocked (Device signature mismatch).' 
        });
      }
    }

    // Fetch document metadata to resolve owner
    const docRes = await db.query('SELECT owner_id FROM documents WHERE id = $1', [docId]);
    if (docRes.rowCount === 0) {
      return res.status(404).json({ error: 'Zero-Trust Engine Denied: Secure document not found.' });
    }
    const doc = docRes.rows[0];

    // Determine the type of request action (Read vs Write)
    const isWriteAction = ['DELETE', 'PUT', 'PATCH'].includes(req.method) || (req.path && (req.path.endsWith('/rename') || req.path.endsWith('/move')));

    // -------------------------------------------------------------
    // POLICY CONTROLS 4 & 5: Role-Based Access Controls & Owner Privilege
    // -------------------------------------------------------------
    let hasDirectAccess = false;
    let accessRole = 'unauthorized';

    if (userRole === 'admin') {
      hasDirectAccess = true;
      accessRole = 'admin';
    } else if (doc.owner_id === userId) {
      hasDirectAccess = true;
      accessRole = 'owner';
    }

    if (hasDirectAccess) {
      // Admins and owners possess continuous clearance
      req.accessTag = { role: accessRole, permission: 'owner' };
      return next();
    }

    // -------------------------------------------------------------
    // POLICY CONTROLS 6 & 7: Permission Matrix & Share Contexts
    // -------------------------------------------------------------
    const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

    // Scenario A: Access via a Secure Shared Link (Token ABAC controls)
    if (shareToken) {
      let shareRecord = null;

      const shareRes = await db.query(
        `SELECT id, document_id, expiry_date, allowed_ip, max_views, current_views, password_protected 
         FROM shared_links WHERE id = $1 AND document_id = $2`,
        [shareToken, docId]
      );
      if (shareRes.rowCount > 0) {
        const row = shareRes.rows[0];
        shareRecord = {
          id: row.id,
          expires_at: row.expiry_date,
          allowed_ip: row.allowed_ip,
          max_views: row.max_views,
          current_views: row.current_views,
          password_protected: row.password_protected,
          permission: 'viewer'
        };
      }

      if (!shareRecord) {
        return res.status(403).json({ error: 'Zero-Trust Engine Denied: Invalid sharing link token.' });
      }

      // Check Password Protection Policies (Bcrypt Comparison)
      if (shareRecord.password_protected) {
        const providedPassword = req.headers['x-share-password'] || req.query.share_password || req.body.share_password;
        if (!providedPassword) {
          return res.status(401).json({ 
            password_required: true, 
            error: 'Zero-Trust Policy: This shared link is password-protected.' 
          });
        }
        const isPasswordCorrect = await bcrypt.compare(providedPassword, shareRecord.password_protected);
        if (!isPasswordCorrect) {
          return res.status(401).json({ 
            password_required: true, 
            error: 'Zero-Trust Policy: Incorrect password for shared link.' 
          });
        }
      }

      // Check Expiration Policies
      if (shareRecord.expires_at && new Date(shareRecord.expires_at) < new Date()) {
        await logSecurityEvent({
          userId,
          action: 'LINK_EXPIRED_ACCESS',
          req,
          details: { documentId: docId, shareId: shareRecord.id, expiry: shareRecord.expires_at },
          severity: 'warning'
        });
        return res.status(403).json({ error: 'Zero-Trust Engine Denied: The shared access link has expired.' });
      }

      // Check IP CIDR restrictions
      if (shareRecord.allowed_ip && !ipMatches(ipAddress, shareRecord.allowed_ip)) {
        await logSecurityEvent({
          userId,
          action: 'IP_RESTRICTION_VIOLATION',
          req,
          details: { documentId: docId, allowedIp: shareRecord.allowed_ip, requesterIp: ipAddress },
          severity: 'critical'
        });
        return res.status(403).json({ 
          error: `Zero-Trust Engine Denied: IP address not authorized. Access limited to: ${shareRecord.allowed_ip}` 
        });
      }

      // Check View Count Limits
      if (shareRecord.max_views !== null && shareRecord.max_views !== undefined) {
        if (shareRecord.current_views >= shareRecord.max_views) {
          await logSecurityEvent({
            userId,
            action: 'VIEW_LIMIT_VIOLATION',
            req,
            details: { documentId: docId, maxViews: shareRecord.max_views, currentViews: shareRecord.current_views },
            severity: 'warning'
          });
          return res.status(403).json({ error: 'Zero-Trust Engine Denied: Sharing link view limit reached.' });
        }
      }

      // Action Permission check (public links cannot modify files)
      if (isWriteAction && shareRecord.permission !== 'editor') {
        return res.status(403).json({ error: 'Zero-Trust Engine Denied: Shared links only grant read-only clearance.' });
      }

      // If all policies clear, slide view metrics forward
      await db.query('UPDATE shared_links SET current_views = current_views + 1 WHERE id = $1', [shareRecord.id]);

      req.accessTag = { role: 'guest', permission: shareRecord.permission };
      return next();
    }

    // Scenario B: Direct User Share Matrix Verification
    let directShare = null;
    const shareRes = await db.query(
      `SELECT permission, expires_at FROM document_shares 
       WHERE document_id = $1 AND shared_with_user_id = $2 AND accepted::BOOLEAN = $3`,
      [docId, userId, true]
    );
    if (shareRes.rowCount > 0) {
      directShare = shareRes.rows[0];
    } else {
      const legacyShareRes = await db.query(
        `SELECT expiry_date FROM shared_links WHERE document_id = $1 AND allowed_ip = $2`,
        [docId, `user:${req.user.email}`]
      );
      if (legacyShareRes.rowCount > 0) {
        directShare = {
          expires_at: legacyShareRes.rows[0].expiry_date,
          permission: 'viewer'
        };
      }
    }

    if (!directShare) {
      await logSecurityEvent({
        userId,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        req,
        details: { documentId: docId, actionType: req.method },
        severity: 'critical'
      });
      return res.status(403).json({ error: 'Zero-Trust Engine Denied: Access Denied. No authorization clearance.' });
    }

    // Check direct grant expiration
    if (directShare.expires_at && new Date(directShare.expires_at) < new Date()) {
      return res.status(403).json({ error: 'Zero-Trust Engine Denied: Shared access lifetime has expired.' });
    }

    // Verify permission rights (Viewer cannot modify/delete)
    if (isWriteAction && directShare.permission !== 'editor') {
      return res.status(403).json({ error: 'Zero-Trust Engine Denied: Editor permissions required to modify files.' });
    }

    req.accessTag = { role: 'collaborator', permission: directShare.permission };
    next();

  } catch (err) {
    console.error('Zero-Trust Engine Evaluation Error:', err.message);
    res.status(500).json({ error: 'Internal Zero-Trust Engine policy evaluation error.' });
  }
}

module.exports = {
  verifyAccess
};
