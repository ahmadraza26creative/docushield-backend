const jwt = require('jsonwebtoken');
const db = require('../config/db');

require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET || 'docushield_jwt_secret_key_2026_x1';

/**
 * Middleware to authenticate requests via JWT
 */
async function authenticateToken(req, res, next) {
  let token = req.cookies?.token || req.cookies?.accessToken;

  // Fallback to Authorization Header
  if (!token && req.headers['authorization']) {
    const authHeader = req.headers['authorization'];
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }
  }

  if (!token) {
    return res.status(401).json({ error: 'Authentication required. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Continuous Verification: Check if session and user exist and are active
    let user = null;
    let sessionId = decoded.sessionId || null;

    if (sessionId) {
      // Check session and user state
      const sessionRes = await db.query(
        `SELECT s.is_active as session_active, s.last_activity, u.id, u.email, u.role, u.mfa_enabled, u.is_active as user_active, u.status 
         FROM sessions s 
         JOIN users u ON s.user_id = u.id 
         WHERE s.id = $1 AND u.id = $2`,
        [sessionId, decoded.id]
      );

      if (sessionRes.rowCount === 0) {
        return res.status(401).json({ error: 'Session is invalid or has expired.' });
      }

      const row = sessionRes.rows[0];
      const isSessionActive = row.session_active === true || row.session_active === 1 || row.session_active === '1';
      const isUserActive = row.user_active === true || row.user_active === 1 || row.user_active === '1' || row.user_active === null;
      const isSuspended = row.status === 'suspended';

      if (!isSessionActive) {
        return res.status(401).json({ error: 'Session has been invalidated.' });
      }

      if (!isUserActive || isSuspended) {
        return res.status(403).json({ error: 'Your account has been suspended or deactivated.' });
      }

      // Enforce Inactivity Session Timeout: 15 minutes (900,000 ms)
      const INACTIVITY_TIMEOUT = 15 * 60 * 1000;
      
      const lastActivityStr = typeof row.last_activity === 'string' && !row.last_activity.endsWith('Z')
        ? row.last_activity + ' Z' 
        : row.last_activity;

      const lastActivityTime = new Date(lastActivityStr).getTime();
      const currentTime = Date.now();

      if (currentTime - lastActivityTime > INACTIVITY_TIMEOUT) {
        await db.query(
          'UPDATE sessions SET is_active = $1 WHERE id = $2',
          [false, sessionId]
        );
        return res.status(401).json({ error: 'Session expired due to inactivity. Please log in again.' });
      }

      // Slide Inactivity window forward
      await db.query(
        'UPDATE sessions SET last_activity = CURRENT_TIMESTAMP WHERE id = $1',
        [sessionId]
      );

      user = {
        id: row.id,
        email: row.email,
        role: row.role,
        mfa_enabled: row.mfa_enabled === true || row.mfa_enabled === 1 || row.mfa_enabled === '1',
        status: row.status,
        is_active: row.user_active
      };
      
      req.sessionId = sessionId;
    } else {
      // Direct user fallback verification (in case token was signed without sessionId)
      const userRes = await db.query(
        'SELECT id, email, role, mfa_enabled, is_active, status FROM users WHERE id = $1', 
        [decoded.id]
      );
      
      if (userRes.rowCount === 0) {
        return res.status(401).json({ error: 'User account no longer exists.' });
      }

      const row = userRes.rows[0];
      const isUserActive = row.is_active === true || row.is_active === 1 || row.is_active === '1' || row.is_active === null;
      const isSuspended = row.status === 'suspended';

      if (!isUserActive || isSuspended) {
        return res.status(403).json({ error: 'Your account has been suspended or deactivated.' });
      }

      user = row;
    }

    // Attach verified user to request
    req.user = user;
    next();
  } catch (err) {
    console.error('JWT Verification Error:', err.message);
    return res.status(401).json({ error: 'Session expired or invalid token.' });
  }
}

/**
 * Middleware to enforce Role-Based Access Control (RBAC)
 * @param {string[]} allowedRoles - Roles allowed to access the route ('admin', 'editor', 'viewer')
 */
function requireRole(allowedRoles = []) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ 
        error: `Access Denied. Required role: ${allowedRoles.join(' or ')}. Your role: ${req.user.role}` 
      });
    }

    next();
  };
}

module.exports = {
  authenticateToken,
  requireRole,
  JWT_SECRET
};
