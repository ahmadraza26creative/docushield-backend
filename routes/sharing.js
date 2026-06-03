const express = require('express');
const router = express.Router();
const shareController = require('../controllers/shareController');
const { authenticateToken } = require('../middleware/auth');

router.post('/', authenticateToken, shareController.shareDocument);
router.get('/pending', authenticateToken, shareController.listPendingShares);
router.post('/:shareId/accept', authenticateToken, shareController.acceptShare);
router.get('/:documentId', authenticateToken, shareController.listDocumentShares);
router.delete('/:shareId', authenticateToken, shareController.revokeShare);

module.exports = router;
