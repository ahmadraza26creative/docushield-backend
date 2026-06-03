const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const AdmZip = require('adm-zip');
const mammoth = require('mammoth');
const db = require('../config/db');
const cryptoUtils = require('../utils/crypto');
const { logSecurityEvent } = require('../utils/auditLogger');
const storageService = require('../src/services/storageService');

// Config paths
const ENCRYPTED_DIR = path.resolve(__dirname, '..', 'uploads', 'encrypted');

// Ensure encrypted folder exists
if (!fs.existsSync(ENCRYPTED_DIR)) {
  fs.mkdirSync(ENCRYPTED_DIR, { recursive: true });
}

// Allowed file types for validation (Defense in Depth)
const ALLOWED_MIME_TYPES = [
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'image/png',
  'image/jpeg',
  'text/plain',
  'application/zip',
  'application/x-zip-compressed',
  'multipart/x-zip',
  'application/x-xip'
];
const ALLOWED_EXTENSIONS = ['.pdf', '.docx', '.png', '.jpg', '.jpeg', '.txt', '.zip', '.xip'];
const ARCHIVE_EXTENSIONS_WITH_GENERIC_MIME = ['.zip', '.xip'];

function isAllowedUploadType(ext, mimeType) {
  if (!ALLOWED_EXTENSIONS.includes(ext)) return false;
  if (ALLOWED_MIME_TYPES.includes(mimeType)) return true;
  return mimeType === 'application/octet-stream' && ARCHIVE_EXTENSIONS_WITH_GENERIC_MIME.includes(ext);
}

/**
 * Helper to compute SHA-256 hash of a file for integrity verification
 */
function calculateFileHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (data) => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', (err) => reject(err));
  });
}

/**
 * Database Mapper: Translates PostgreSQL structured rows to standard SaaS schema objects
 */
function mapDocumentRow(row) {
  const parts = row.encryption_key ? row.encryption_key.split(':') : [];
  return {
    id: row.id,
    title: row.filename,
    original_name: row.filename,
    file_size: row.file_size,
    mime_type: parts[parts.length - 1] || 'application/octet-stream',
    owner_id: row.owner_id,
    owner_email: row.owner_email,
    folder_path: row.folder_path || '',
    file_hash: row.file_hash,
    effective_permission: row.effective_permission,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function getDocumentCryptoContext(doc) {
  const parts = doc.encryption_key ? doc.encryption_key.split(':') : [];
  return {
    fileKeyEncrypted: `${parts[0]}:${parts[1]}:${parts[2]}`,
    ivHex: parts[3],
    tagHex: parts[4],
    mimeType: parts[5] || 'application/octet-stream',
    filename: doc.filename,
    encryptedFileName: doc.encrypted_filename
  };
}

function stripUnsafeHtml(html) {
  return html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/\son\w+="[^"]*"/gi, '')
    .replace(/\son\w+='[^']*'/gi, '')
    .replace(/javascript:/gi, '');
}

/**
 * Authorization Helper: Verifies write/modify permissions on a document
 */
async function checkWritePermission(docId, userId, userRole) {
  if (userRole === 'admin') return true;
  
  const docRes = await db.query('SELECT owner_id FROM documents WHERE id = $1', [docId]);
  if (docRes.rowCount === 0) return false;
  
  if (docRes.rows[0].owner_id === userId) return true;
  
  // Editors with direct sharing rights also possess write authorization only after accepting the invitation
  const shareRes = await db.query(
    "SELECT permission FROM document_shares WHERE document_id = $1 AND shared_with_user_id = $2 AND permission = 'editor' AND accepted::BOOLEAN = $3",
    [docId, userId, true]
  );
  return shareRes.rowCount > 0;
}

/**
 * List all documents (Zero Trust Access Control)
 */
async function listDocuments(req, res) {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { folder = '', search = '', all = 'false' } = req.query;

  try {
    let queryText;
    let params = [];
    let whereClauses = [];

    if (userRole === 'admin') {
      queryText = `
        SELECT d.id, d.filename, d.file_size, d.folder_path, d.file_hash, d.encryption_key, d.uploaded_at as created_at, d.uploaded_at as updated_at,
               u.email as owner_email, 'admin' as effective_permission
        FROM documents d
        LEFT JOIN users u ON d.owner_id = u.id
      `;
    } else {
      const acceptedValue = true;
      queryText = `
        SELECT DISTINCT d.id, d.filename, d.file_size, d.folder_path, d.file_hash, d.encryption_key, d.uploaded_at as created_at, d.uploaded_at as updated_at,
               u.email as owner_email,
               CASE 
                 WHEN d.owner_id = $1 THEN 'owner'
                 ELSE ds.permission
               END as effective_permission
        FROM documents d
        LEFT JOIN users u ON d.owner_id = u.id
        LEFT JOIN document_shares ds ON d.id = ds.document_id AND ((ds.shared_with_user_id = $1 AND ds.accepted = $2) OR ds.share_token IS NOT NULL)
      `;
      params.push(userId);
      params.push(acceptedValue);
      whereClauses.push('(d.owner_id = $1 OR ds.shared_with_user_id = $1)');
    }

    // Apply folder filtering (only if not listing all documents across folders)
    if (all !== 'true') {
      params.push(folder);
      whereClauses.push(`d.folder_path = $${params.length}`);
    }

    // Apply search query
    if (search) {
      params.push(`%${search}%`);
      whereClauses.push(`(d.filename LIKE $${params.length} OR u.email LIKE $${params.length})`);
    }

    // Combine WHERE clauses
    if (whereClauses.length > 0) {
      queryText += ` WHERE ` + whereClauses.join(' AND ');
    }

    queryText += ` ORDER BY created_at DESC`;

    const docRes = await db.query(queryText, params);
    const documents = docRes.rows.map(mapDocumentRow);

    res.json({ documents });
  } catch (err) {
    console.error('List Documents Error:', err.message);
    res.status(500).json({ error: 'Internal server error listing documents.' });
  }
}

/**
 * Upload and Encrypt File (Zero Trust validation & Malware Hooks)
 */
async function uploadDocument(req, res) {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  const { title, folder_path = '' } = req.body;
  const userId = req.user.id;
  const tempPath = req.file.path;

  // 1. File Type Validation (Defense in depth)
  const ext = path.extname(req.file.originalname).toLowerCase();
  if (!isAllowedUploadType(ext, req.file.mimetype)) {
    if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);
    return res.status(400).json({ error: 'File type not allowed. Approved formats: PDF, DOCX, PNG, JPG, TXT, ZIP, XIP.' });
  }

  // 2. Malware Scan Hook simulation
  const basename = req.file.originalname.toLowerCase();
  if (basename.includes('virus') || basename.includes('infected') || basename.includes('malware')) {
    if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);
    await logSecurityEvent({
      userId,
      action: 'MALWARE_DETECTED',
      req,
      details: { filename: req.file.originalname, size: req.file.size },
      severity: 'critical'
    });
    return res.status(400).json({ error: 'Malware Threat Detected! Security scan blocked this commit.' });
  }

  const fileId = crypto.randomUUID().slice(0, 16); // Safe unique ID
  const encryptedFileName = `${fileId}.enc`;
  const encryptedPath = path.join(ENCRYPTED_DIR, encryptedFileName);
  let storageKey = encryptedFileName;

  try {
    // 3. File Hash Generation (SHA-256 integrity verification)
    const fileHash = await calculateFileHash(tempPath);

    // 4. AES-256 Envelope Encryption
    const encryptionDetails = await cryptoUtils.encryptFileStream(tempPath, encryptedPath);
    storageKey = await storageService.uploadFile(encryptedPath, encryptedFileName);

    // 5. Commit Metadata into Database
    const pgEncryptionKey = `${encryptionDetails.fileKeyEncrypted}:${encryptionDetails.ivHex}:${encryptionDetails.tagHex}:${req.file.mimetype}`;
    await db.query(
      `INSERT INTO documents (id, owner_id, filename, encrypted_filename, file_size, file_hash, encryption_key, folder_path)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        fileId,
        userId,
        title || req.file.originalname,
        storageKey,
        req.file.size,
        fileHash,
        pgEncryptionKey,
        folder_path
      ]
    );

    // 6. Security Event Logging
    await logSecurityEvent({
      userId,
      action: 'FILE_UPLOAD',
      req,
      details: { documentId: fileId, title: title || req.file.originalname, size: req.file.size, hash: fileHash }
    });

    if (storageKey !== encryptedFileName && fs.existsSync(encryptedPath)) {
      fs.unlinkSync(encryptedPath);
    }

    res.status(201).json({
      message: 'File uploaded and secured successfully.',
      documentId: fileId
    });

  } catch (err) {
    console.error('File Upload/Encrypt Error:', err.message);
    if (fs.existsSync(encryptedPath)) {
      fs.unlinkSync(encryptedPath);
    }
    if (storageKey !== encryptedFileName) {
      await storageService.deleteFile(storageKey).catch(() => {});
    }
    res.status(500).json({ error: 'Failed to encrypt and store document.' });
  } finally {
    // ALWAYS remove raw temporary file from disk immediately (Assume Breach principle)
    if (fs.existsSync(tempPath)) {
      fs.unlinkSync(tempPath);
    }
  }
}

/**
 * Stream Decrypt & Download (Never Trust, Always Verify; supports inline previews)
 */
async function downloadDocument(req, res) {
  const { id } = req.params;
  const userId = req.user.id;
  const userRole = req.user.role;
  const { share_token, preview } = req.query; 

  try {
    // 1. Fetch document metadata
    const docRes = await db.query('SELECT * FROM documents WHERE id = $1', [id]);
    if (docRes.rowCount === 0) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    const doc = docRes.rows[0];

    // 2. Verify authorization
    let hasAccess = false;
    let accessReason = '';

    if (userRole === 'admin') {
      hasAccess = true;
      accessReason = 'Admin system access';
    } else if (doc.owner_id === userId) {
      hasAccess = true;
      accessReason = 'Document owner';
    } else {
      // Check direct user shares
      const shareRes = await db.query(
        'SELECT id FROM document_shares WHERE document_id = $1 AND shared_with_user_id = $2 AND accepted = $3',
        [id, userId, true]
      );
      if (shareRes.rowCount > 0) {
        hasAccess = true;
        accessReason = 'Direct shared user';
      } else if (share_token) {
        // Check anonymous token share
        const tokenRes = await db.query(
          'SELECT id, expires_at FROM document_shares WHERE document_id = $1 AND share_token = $2',
          [id, share_token]
        );
        if (tokenRes.rowCount > 0) {
          const share = tokenRes.rows[0];
          if (!share.expires_at || new Date(share.expires_at) > new Date()) {
            hasAccess = true;
            accessReason = 'Valid shared link token';
          } else {
            accessReason = 'Expired shared link token';
          }
        }
      }
    }

    if (!hasAccess) {
      await logSecurityEvent({
        userId,
        action: 'ACCESS_DENIED',
        req,
        details: { documentId: id, reason: accessReason || 'Unauthorized attempt' },
        severity: 'critical'
      });
      return res.status(403).json({ error: 'Access Denied. You do not have permissions for this document.' });
    }

    // 3. Parse Cryptographic Envelope details
    const { fileKeyEncrypted, ivHex, tagHex, mimeType, filename, encryptedFileName } = getDocumentCryptoContext(doc);

    // 4. Setup streaming decryption response
    const encryptedFilePath = await storageService.getFilePath(encryptedFileName);
    
    if (!fs.existsSync(encryptedFilePath)) {
      return res.status(404).json({ error: 'Physical secure archive file not found.' });
    }

    res.setHeader('Content-Type', mimeType || 'application/octet-stream');
    
    // Set headers: preview inline vs download attachment
    if (preview === 'true') {
      res.setHeader('Content-Disposition', 'inline');
    } else {
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);
    }

    // Stream decrypt directly to client
    await cryptoUtils.decryptFileStream(
      encryptedFilePath,
      res,
      fileKeyEncrypted,
      ivHex,
      tagHex
    );

    // 5. Log successful download/preview
    await logSecurityEvent({
      userId,
      action: preview === 'true' ? 'FILE_PREVIEW' : 'FILE_DOWNLOAD',
      req,
      details: { documentId: id, title: filename, reason: accessReason }
    });

  } catch (err) {
    console.error('File Download/Decrypt Error:', err.message);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to decrypt and download file.' });
    }
  }
}

async function getPreviewData(req, res) {
  const { id } = req.params;
  const userId = req.user.id;

  try {
    const docRes = await db.query('SELECT * FROM documents WHERE id = $1', [id]);
    if (docRes.rowCount === 0) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    const doc = docRes.rows[0];
    const { fileKeyEncrypted, ivHex, tagHex, mimeType, filename, encryptedFileName } = getDocumentCryptoContext(doc);
    const encryptedFilePath = await storageService.getFilePath(encryptedFileName);

    if (!fs.existsSync(encryptedFilePath)) {
      return res.status(404).json({ error: 'Physical secure archive file not found.' });
    }

    const decryptedBuffer = await cryptoUtils.decryptFileToBuffer(
      encryptedFilePath,
      fileKeyEncrypted,
      ivHex,
      tagHex
    );

    if (mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' || filename.toLowerCase().endsWith('.docx')) {
      const converted = await mammoth.convertToHtml({ buffer: decryptedBuffer });
      await logSecurityEvent({
        userId,
        action: 'FILE_PREVIEW',
        req,
        details: { documentId: id, title: filename, previewType: 'docx-html' }
      });
      return res.json({
        type: 'docx',
        filename,
        html: stripUnsafeHtml(converted.value),
        warnings: converted.messages || []
      });
    }

    if (mimeType === 'application/zip' || mimeType === 'application/x-zip-compressed' || filename.toLowerCase().endsWith('.zip')) {
      const zip = new AdmZip(decryptedBuffer);
      const entries = zip.getEntries().map(entry => ({
        name: entry.entryName,
        size: entry.header.size,
        compressedSize: entry.header.compressedSize,
        isDirectory: entry.isDirectory
      }));
      await logSecurityEvent({
        userId,
        action: 'FILE_PREVIEW',
        req,
        details: { documentId: id, title: filename, previewType: 'zip-list', fileCount: entries.length }
      });
      return res.json({
        type: 'zip',
        filename,
        entries
      });
    }

    if (filename.toLowerCase().endsWith('.xip')) {
      return res.json({
        type: 'archive',
        filename,
        message: 'XIP archives can be uploaded and downloaded, but their internal file list cannot be inspected by the ZIP preview engine.'
      });
    }

    return res.status(415).json({ error: 'Structured preview data is only available for DOCX and ZIP files.' });
  } catch (err) {
    console.error('Preview Data Error:', err.message);
    res.status(500).json({ error: 'Failed to prepare secure preview data.' });
  }
}

/**
 * Rename Document (Requires Edit privileges)
 */
async function renameDocument(req, res) {
  const { id } = req.params;
  const { title } = req.body;
  const userId = req.user.id;
  const userRole = req.user.role;

  if (!title) {
    return res.status(400).json({ error: 'New document title is required.' });
  }

  try {
    // 1. Authorize: Check write permission
    const hasWritePermission = await checkWritePermission(id, userId, userRole);
    if (!hasWritePermission) {
      return res.status(403).json({ error: 'Access Denied. You do not have permission to modify this document.' });
    }

    // 2. Perform Rename
    await db.query(
      'UPDATE documents SET filename = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [title, id]
    );

    // 3. Log Audit Log
    await logSecurityEvent({
      userId,
      action: 'FILE_RENAME',
      req,
      details: { documentId: id, newTitle: title }
    });

    res.json({ message: 'Document renamed successfully.' });

  } catch (err) {
    console.error('Rename Document Error:', err.message);
    res.status(500).json({ error: 'Failed to rename document.' });
  }
}

/**
 * Move Document into Folder (Requires Edit privileges)
 */
async function moveDocument(req, res) {
  const { id } = req.params;
  const { folder_path = '' } = req.body;
  const userId = req.user.id;
  const userRole = req.user.role;

  try {
    // 1. Authorize: Check write permission
    const hasWritePermission = await checkWritePermission(id, userId, userRole);
    if (!hasWritePermission) {
      return res.status(403).json({ error: 'Access Denied. You do not have permission to modify this document.' });
    }

    // Sanitize folder path (e.g. assure clean strings, trim slash endings)
    let sanitizedPath = folder_path.trim();
    if (sanitizedPath && !sanitizedPath.startsWith('/')) {
      sanitizedPath = '/' + sanitizedPath;
    }
    if (sanitizedPath.endsWith('/') && sanitizedPath !== '/') {
      sanitizedPath = sanitizedPath.slice(0, -1);
    }

    // 2. Perform Move
    await db.query(
      'UPDATE documents SET folder_path = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [sanitizedPath, id]
    );

    // 3. Log Audit Log
    await logSecurityEvent({
      userId,
      action: 'FILE_MOVE',
      req,
      details: { documentId: id, destination: sanitizedPath || 'Root' }
    });

    res.json({ message: `Document successfully moved to ${sanitizedPath || 'Root'}.` });

  } catch (err) {
    console.error('Move Document Error:', err.message);
    res.status(500).json({ error: 'Failed to move document.' });
  }
}

/**
 * Securely Purge/Delete Document (Owner or Admin only)
 */
async function deleteDocument(req, res) {
  const { id } = req.params;
  const userId = req.user.id;
  const userRole = req.user.role;

  try {
    const docRes = await db.query('SELECT * FROM documents WHERE id = $1', [id]);
    if (docRes.rowCount === 0) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    const doc = docRes.rows[0];

    // Authorize: Owner or Admin only (Least Privilege deletion)
    if (doc.owner_id !== userId && userRole !== 'admin') {
      await logSecurityEvent({
        userId,
        action: 'ACCESS_DENIED',
        req,
        details: { documentId: id, action: 'Delete document attempt' },
        severity: 'critical'
      });
      return res.status(403).json({ error: 'Unauthorized. Only the owner or an admin can delete this document.' });
    }

    // Delete encrypted archive file from disk
    const encryptedFileName = doc.encrypted_filename;
    await storageService.deleteFile(encryptedFileName);

    // Delete database records
    await db.query('DELETE FROM documents WHERE id = $1', [id]);

    // Log deletion
    const filename = doc.filename;
    await logSecurityEvent({
      userId,
      action: 'FILE_DELETE',
      req,
      details: { documentId: id, title: filename }
    });

    res.json({ message: 'Document deleted successfully.' });

  } catch (err) {
    console.error('Delete Document Error:', err.message);
    res.status(500).json({ error: 'Failed to delete document.' });
  }
}

module.exports = {
  listDocuments,
  uploadDocument,
  downloadDocument,
  getPreviewData,
  renameDocument,
  moveDocument,
  deleteDocument
};
