const fs = require('fs');
const path = require('path');
const cloudinary = require('cloudinary').v2;

const encryptedDir = path.resolve(__dirname, '..', '..', 'uploads', 'encrypted');
const tempDir = path.resolve(__dirname, '..', '..', 'uploads', 'temp');

function hasCloudinaryConfig() {
  return Boolean(
    process.env.CLOUDINARY_CLOUD_NAME &&
    process.env.CLOUDINARY_API_KEY &&
    process.env.CLOUDINARY_API_SECRET
  );
}

function configureCloudinary() {
  if (!hasCloudinaryConfig()) return false;
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  });
  return true;
}

function cloudinaryPublicId(storageKey) {
  return storageKey.startsWith('docushield/')
    ? storageKey
    : `docushield/${path.basename(storageKey, path.extname(storageKey))}`;
}

async function uploadFile(localPath, fileName) {
  if (!configureCloudinary()) {
    return fileName;
  }

  const publicId = cloudinaryPublicId(fileName);
  await cloudinary.uploader.upload(localPath, {
    resource_type: 'raw',
    public_id: publicId,
    overwrite: true
  });
  return publicId;
}

async function deleteFile(storageKey) {
  if (configureCloudinary() && storageKey.startsWith('docushield/')) {
    await cloudinary.uploader.destroy(storageKey, { resource_type: 'raw' });
    return;
  }

  const localPath = path.join(encryptedDir, storageKey);
  if (fs.existsSync(localPath)) {
    fs.unlinkSync(localPath);
  }
}

async function getFileUrl(storageKey) {
  if (configureCloudinary() && storageKey.startsWith('docushield/')) {
    return cloudinary.url(storageKey, { resource_type: 'raw', secure: true });
  }
  return null;
}

async function getFilePath(storageKey) {
  const localPath = path.join(encryptedDir, storageKey);
  if (fs.existsSync(localPath)) {
    return localPath;
  }

  const fileUrl = await getFileUrl(storageKey);
  if (!fileUrl) {
    return localPath;
  }

  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
  }

  const tempPath = path.join(tempDir, `${path.basename(storageKey)}.download`);
  const response = await fetch(fileUrl);
  if (!response.ok) {
    throw new Error('Failed to download encrypted file from Cloudinary.');
  }
  const buffer = Buffer.from(await response.arrayBuffer());
  fs.writeFileSync(tempPath, buffer);
  return tempPath;
}

module.exports = {
  uploadFile,
  deleteFile,
  getFileUrl,
  getFilePath,
  hasCloudinaryConfig
};
