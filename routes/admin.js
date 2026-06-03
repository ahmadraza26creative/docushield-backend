const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const aiSecurityController = require('../controllers/aiSecurityController');
const { authenticateToken, requireRole } = require('../middleware/auth');

// All routes here require Admin privilege (Least Privilege Access check)
router.use(authenticateToken, requireRole(['admin']));

router.get('/users', adminController.listUsers);
router.post('/users', adminController.createUser);
router.put('/users/:id/role', adminController.updateUserRole);
router.put('/users/:id/status', adminController.updateUserStatus);
router.delete('/users/:id', adminController.deleteUser);

router.get('/documents', adminController.listAllDocuments);
router.delete('/documents/:id', adminController.revokeDocument);

router.get('/metrics', adminController.getSystemMetrics);

// AI Security Monitoring Analysis endpoint
router.get('/ai-analysis', aiSecurityController.getAiAnalysis);

module.exports = router;
