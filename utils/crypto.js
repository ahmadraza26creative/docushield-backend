const crypto = require('crypto');
const fs = require('fs');
const { pipeline } = require('stream/promises');

require('dotenv').config();

// Standard fallback master key if not provided in environment
const MASTER_KEY_RAW = process.env.MASTER_ENCRYPTION_KEY || 'docushield_super_secure_master_key_2026_99';
// Ensure key is exactly 32 bytes for AES-256
const MASTER_ENCRYPTION_KEY = crypto.createHash('sha256').update(MASTER_KEY_RAW).digest();

/**
 * Encrypts a buffer (e.g. file key) using the Master Key.
 * Returns an envelope string: "iv_hex:tag_hex:encrypted_hex"
 */
function encryptKey(keyBuffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_ENCRYPTION_KEY, iv);
  
  const encrypted = Buffer.concat([cipher.update(keyBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  
  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Decrypts an envelope string using the Master Key.
 * Returns the original key buffer.
 */
function decryptKey(envelopeString) {
  const [ivHex, tagHex, encryptedHex] = envelopeString.split(':');
  if (!ivHex || !tagHex || !encryptedHex) {
    throw new Error('Invalid key envelope format');
  }

  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_ENCRYPTION_KEY, iv);
  decipher.setAuthTag(tag);

  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

/**
 * Encrypts a file stream from sourcePath to destPath.
 * Returns { fileKeyEncrypted, ivHex, tagHex }
 */
async function encryptFileStream(sourcePath, destPath) {
  // Generate random 256-bit key for this file
  const fileKey = crypto.randomBytes(32);
  // Generate 12-byte IV
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', fileKey, iv);

  const readStream = fs.createReadStream(sourcePath);
  const writeStream = fs.createWriteStream(destPath);

  // Run pipeline to encrypt file stream
  await pipeline(readStream, cipher, writeStream);

  const tag = cipher.getAuthTag();

  // Envelope encrypt the file key
  const fileKeyEncrypted = encryptKey(fileKey);

  return {
    fileKeyEncrypted,
    ivHex: iv.toString('hex'),
    tagHex: tag.toString('hex')
  };
}

/**
 * Decrypts a file stream from sourcePath directly into a writeable destination stream (e.g. response res).
 */
async function decryptFileStream(sourcePath, destStream, fileKeyEncrypted, ivHex, tagHex) {
  // Decrypt the file key
  const fileKey = decryptKey(fileKeyEncrypted);
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', fileKey, iv);
  decipher.setAuthTag(tag);

  const readStream = fs.createReadStream(sourcePath);

  await pipeline(readStream, decipher, destStream);
}

async function decryptFileToBuffer(sourcePath, fileKeyEncrypted, ivHex, tagHex) {
  const chunks = [];
  const fileKey = decryptKey(fileKeyEncrypted);
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', fileKey, iv);
  decipher.setAuthTag(tag);

  for await (const chunk of fs.createReadStream(sourcePath).pipe(decipher)) {
    chunks.push(chunk);
  }

  return Buffer.concat(chunks);
}

module.exports = {
  encryptKey,
  decryptKey,
  encryptFileStream,
  decryptFileStream,
  decryptFileToBuffer
};
