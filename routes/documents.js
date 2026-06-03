const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const documentController = require('../controllers/documentController');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { verifyAccess } = require('../middleware/policyEngine');

// Configure Multer for secure temporary file landing
const TEMP_DIR = path.resolve(__dirname, '..', 'uploads', 'temp');
if (!fs.existsSync(TEMP_DIR)) {
  fs.mkdirSync(TEMP_DIR, { recursive: true });
}

const upload = multer({
  dest: TEMP_DIR,
  limits: { fileSize: 50 * 1024 * 1024 } // limit 50MB
});

router.get('/', authenticateToken, documentController.listDocuments);

// Only editor or admin can upload files (Least Privilege Access)
router.post('/upload', 
  authenticateToken, 
  requireRole(['admin', 'editor']), 
  upload.single('file'), 
  documentController.uploadDocument
);

// Decrypt & Download (Zero Trust Policy Evaluated)
router.get('/:id/preview-data', authenticateToken, verifyAccess, documentController.getPreviewData);
router.get('/:id/download', authenticateToken, verifyAccess, documentController.downloadDocument);

// Rename (Zero Trust Policy Evaluated)
router.put('/:id/rename', authenticateToken, verifyAccess, documentController.renameDocument);

// Move (Zero Trust Policy Evaluated)
router.put('/:id/move', authenticateToken, verifyAccess, documentController.moveDocument);

// Delete (Zero Trust Policy Evaluated)
router.delete('/:id', authenticateToken, verifyAccess, documentController.deleteDocument);

module.exports = router;
