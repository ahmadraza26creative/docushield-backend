const db = require('../config/db');

/**
 * Registers an audit event in the database for compliance and continuous monitoring.
 * 
 * @param {Object} params
 * @param {number|null} params.userId - ID of the user performing the action, or null
 * @param {string} params.action - The security event code (e.g. AUTH_LOGIN, FILE_UPLOAD)
 * @param {Object} req - Express request object to extract IP and User Agent from
 * @param {Object} params.details - Arbitrary details object
 * @param {string} params.severity - 'info', 'warning', 'critical'
 */
async function logSecurityEvent({ userId, action, req, details = {}, severity = 'info' }) {
  try {
    const ipAddress = req ? (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown') : 'system';
    const deviceInfo = req ? req.headers['user-agent'] : 'system';
    const docId = details.documentId || null;

    const dbDetails = JSON.stringify(details);

    await db.query(
      `INSERT INTO audit_logs (user_id, action, document_id, ip_address, device_info, user_agent, details, severity)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [userId || null, action, docId, ipAddress, deviceInfo, deviceInfo, dbDetails, severity]
    );
  } catch (err) {
    console.error('❌ Failed to write audit log event:', err.message);
  }
}

module.exports = {
  logSecurityEvent
};
