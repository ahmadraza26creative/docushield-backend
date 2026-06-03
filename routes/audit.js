const express = require('express');
const router = express.Router();
const auditController = require('../controllers/auditController');
const { authenticateToken, requireRole } = require('../middleware/auth');

// Audit Routes under /api/audit
router.get('/', authenticateToken, requireRole(['admin']), auditController.getAuditLogs);
router.get('/stats', authenticateToken, requireRole(['admin']), auditController.getAuditStats);

module.exports = router;
