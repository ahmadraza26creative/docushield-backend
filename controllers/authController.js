const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const QRCode = require('qrcode');
const speakeasy = require('speakeasy');
const db = require('../config/db');
const { JWT_SECRET } = require('../middleware/auth');
const { logSecurityEvent } = require('../utils/auditLogger');

/**
 * Robust Input Validation helper for registration & password change
 */
function validatePasswordStrength(password) {
  if (password.length < 8) {
    return 'Password must be at least 8 characters long.';
  }
  if (!/[A-Z]/.test(password)) {
    return 'Password must contain at least one uppercase letter.';
  }
  if (!/[a-z]/.test(password)) {
    return 'Password must contain at least one lowercase letter.';
  }
  if (!/\d/.test(password)) {
    return 'Password must contain at least one number.';
  }
  if (!/[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/]/.test(password)) {
    return 'Password must contain at least one special character.';
  }
  return null;
}

function validateEmailFormat(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function verifyTotpCode(secret, token) {
  if (!secret || !token) return false;
  return speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token: String(token).replace(/\D/g, ''),
    window: 2
  });
}

/**
 * Register User
 */
async function register(req, res) {
  const { email, password, full_name, department } = req.body;

  if (!email || !password || !full_name) {
    return res.status(400).json({ error: 'Full name, email, and password are required.' });
  }

  if (!validateEmailFormat(email)) {
    return res.status(400).json({ error: 'Invalid email address format.' });
  }

  const pwdError = validatePasswordStrength(password);
  if (pwdError) {
    return res.status(400).json({ error: pwdError });
  }

  try {
    // Check if user already exists
    const existing = await db.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rowCount > 0) {
      await logSecurityEvent({
        action: 'AUTH_REGISTER_FAILED',
        req,
        details: { email, reason: 'Email already registered' },
        severity: 'warning'
      });
      return res.status(400).json({ error: 'Email is already registered.' });
    }

    // First user is admin, others are editors
    const userCount = await db.query('SELECT COUNT(*) as count FROM users');
    const isFirstUser = parseInt(userCount.rows[0].count || 0) === 0;
    const assignedRole = isFirstUser ? 'admin' : 'editor';

    // Hash password using bcryptjs
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    await db.query(
      `INSERT INTO users (full_name, email, password_hash, role, department, is_active, status) 
       VALUES ($1, $2, $3, $4, $5, $6, 'active')`,
      [full_name, email, passwordHash, assignedRole, department || null, true]
    );

    // Dynamic, database-agnostic fetch to obtain the newly inserted user details
    const fetchRes = await db.query('SELECT id, full_name, email, role, department FROM users WHERE email = $1', [email]);
    const newUser = fetchRes.rows[0];

    // Create unique database session for a newly registered user
    const sessionId = crypto.randomUUID();
    await db.query(
      `INSERT INTO sessions (id, user_id, device_fingerprint, is_active)
       VALUES ($1, $2, $3, $4)`,
      [sessionId, newUser.id, 'registration', true]
    );

    const accessToken = jwt.sign(
      { id: newUser.id, email: newUser.email, role: newUser.role, sessionId },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: JWT_EXPIRES_IN_MS
    });

    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: JWT_EXPIRES_IN_MS
    });

    await logSecurityEvent({
      userId: newUser.id,
      action: 'AUTH_REGISTER_SUCCESS',
      req,
      details: { email, role: assignedRole }
    });

    res.status(201).json({
      message: 'Registration successful.',
      accessToken,
      user: {
        id: newUser.id,
        full_name: newUser.full_name,
        email: newUser.email,
        role: newUser.role
      }
    });

  } catch (err) {
    console.error('Registration Error:', err.message);
    res.status(500).json({ error: 'An internal error occurred during registration.' });
  }
}

/**
 * Login User
 */
async function login(req, res) {
  const { email, password, device_fingerprint, mfa_code } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    // Fetch user (including status and is_active check)
    const userRes = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userRes.rowCount === 0) {
      await logSecurityEvent({
        action: 'AUTH_LOGIN_FAILED',
        req,
        details: { email, reason: 'Invalid email' },
        severity: 'warning'
      });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const user = userRes.rows[0];

    // Verify user account status
    const isUserActive = user.is_active === true || user.is_active === 1 || user.is_active === '1' || user.is_active === null || user.is_active === undefined;
    const isSuspended = user.status === 'suspended';

    if (!isUserActive || isSuspended) {
      await logSecurityEvent({
        userId: user.id,
        action: 'AUTH_LOGIN_FAILED',
        req,
        details: { email, reason: 'Account suspended/deactivated' },
        severity: 'critical'
      });
      return res.status(403).json({ error: 'Your account is suspended or inactive. Contact admin.' });
    }

    // Verify password
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      await logSecurityEvent({
        userId: user.id,
        action: 'AUTH_LOGIN_FAILED',
        req,
        details: { email, reason: 'Incorrect password' },
        severity: 'warning'
      });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const isMfaEnabled = user.mfa_enabled === true || user.mfa_enabled === 1 || user.mfa_enabled === '1';
    if (isMfaEnabled) {
      if (!mfa_code) {
        return res.status(401).json({
          error: 'MFA code required.',
          mfa_required: true
        });
      }

      const verifiedMfa = verifyTotpCode(user.mfa_secret, mfa_code);

      if (!verifiedMfa) {
        await logSecurityEvent({
          userId: user.id,
          action: 'MFA_LOGIN_FAILED',
          req,
          details: { email },
          severity: 'warning'
        });
        return res.status(401).json({
          error: 'Invalid MFA code.',
          mfa_required: true
        });
      }
    }

    // Enforce Concurrent Session Limit: maximum 3 active sessions per user (revoke oldest)
    const MAX_CONCURRENT_SESSIONS = 3;
    const activeSessionsRes = await db.query(
      "SELECT id FROM sessions WHERE user_id = $1 AND is_active = $2 ORDER BY login_time ASC",
      [user.id, true]
    );

    if (activeSessionsRes.rowCount >= MAX_CONCURRENT_SESSIONS) {
      const toRevokeCount = activeSessionsRes.rowCount - MAX_CONCURRENT_SESSIONS + 1;
      for (let i = 0; i < toRevokeCount; i++) {
        const oldestSessionId = activeSessionsRes.rows[i].id;
        await db.query(
          "UPDATE sessions SET is_active = $1 WHERE id = $2",
          [false, oldestSessionId]
        );
        
        await logSecurityEvent({
          userId: user.id,
          action: 'CONCURRENT_SESSION_REVOKE',
          req,
          details: { email: user.email, reason: 'Concurrent session limit exceeded. Oldest session revoked.', revokedSessionId: oldestSessionId },
          severity: 'warning'
        });
      }
    }

    // Create unique database session for Zero Trust session validation & revocation
    const sessionId = crypto.randomUUID();
    await db.query(
      `INSERT INTO sessions (id, user_id, device_fingerprint, is_active)
       VALUES ($1, $2, $3, $4)`,
      [sessionId, user.id, device_fingerprint || 'unknown', true]
    );

    // Generate JWT Access Token using configured expiration
    const accessToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role, sessionId },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // Set secure HTTP-only cookies
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: JWT_EXPIRES_IN_MS
    });

    res.cookie('refreshToken', sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    // Retro-compatibility token cookie
    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: JWT_EXPIRES_IN_MS
    });

    await logSecurityEvent({
      userId: user.id,
      action: 'AUTH_LOGIN_SUCCESS',
      req,
      details: { email, role: user.role, sessionId }
    });

    res.json({
      message: 'Login successful.',
      accessToken,
      user: {
        id: user.id,
        full_name: user.full_name,
        email: user.email,
        role: user.role,
        department: user.department,
        mfa_enabled: user.mfa_enabled === true || user.mfa_enabled === 1 || user.mfa_enabled === '1'
      }
    });

  } catch (err) {
    console.error('Login Error:', err.message);
    res.status(500).json({ error: 'An internal error occurred during login.' });
  }
}

/**
 * Logout User (Revokes Active Session in Database)
 */
async function logout(req, res) {
  try {
    const sessionId = req.sessionId || req.cookies?.refreshToken;

    if (sessionId) {
      await db.query(
        'UPDATE sessions SET is_active = $1 WHERE id = $2',
        [false, sessionId]
      );

      if (req.user) {
        await logSecurityEvent({
          userId: req.user.id,
          action: 'AUTH_LOGOUT',
          req,
          details: { sessionId }
        });
      }
    }

    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.clearCookie('token');

    res.json({ message: 'Logged out successfully.' });
  } catch (err) {
    console.error('Logout Error:', err.message);
    res.status(500).json({ error: 'An internal error occurred during logout.' });
  }
}

/**
 * Token Rotation / Silent Refresh
 */
async function refresh(req, res) {
  const refreshToken = req.cookies?.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token is missing. Please log in again.' });
  }

  try {
    // Validate session and retrieve user
    const sessionRes = await db.query(
      `SELECT s.id, s.is_active as session_active, u.id as user_id, u.email, u.role, u.is_active as user_active, u.status 
       FROM sessions s 
       JOIN users u ON s.user_id = u.id 
       WHERE s.id = $1`,
      [refreshToken]
    );

    if (sessionRes.rowCount === 0) {
      return res.status(401).json({ error: 'Invalid or expired session.' });
    }

    const row = sessionRes.rows[0];
    const isSessionActive = row.session_active === true || row.session_active === 1 || row.session_active === '1';
    const isUserActive = row.user_active === true || row.user_active === 1 || row.user_active === '1' || row.user_active === null;
    const isSuspended = row.status === 'suspended';

    if (!isSessionActive) {
      return res.status(401).json({ error: 'Session has been invalidated. Please log in again.' });
    }

    if (!isUserActive || isSuspended) {
      return res.status(403).json({ error: 'User account has been suspended or deactivated.' });
    }

    // Slide session activity timestamp forward
    await db.query(
      'UPDATE sessions SET last_activity = CURRENT_TIMESTAMP WHERE id = $1',
      [refreshToken]
    );

    // Issue brand new short-lived JWT Access Token
    const newAccessToken = jwt.sign(
      { id: row.user_id, email: row.email, role: row.role, sessionId: row.id },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // Set updated access token in cookies
    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: JWT_EXPIRES_IN_MS
    });

    res.cookie('token', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: JWT_EXPIRES_IN_MS
    });

    res.json({
      message: 'Token refreshed successfully.',
      accessToken: newAccessToken
    });

  } catch (err) {
    console.error('Refresh Error:', err.message);
    res.status(500).json({ error: 'Failed to refresh authentication session.' });
  }
}

/**
 * Forgot Password (Stateless Token tied to Password Hash)
 */
async function forgotPassword(req, res) {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email address is required.' });
  }

  try {
    const userRes = await db.query('SELECT id, email, password_hash FROM users WHERE email = $1', [email]);
    
    // Safety Principle: To prevent user enumeration, ALWAYS return 200 OK with a generic message
    const genericResponse = {
      message: 'If this email exists in our system, a password reset link has been generated.'
    };

    if (userRes.rowCount === 0) {
      return res.json(genericResponse);
    }

    const user = userRes.rows[0];

    // Cryptographic dynamic secret: JWT_SECRET + current password_hash
    // Once the user's password changes, this token instantly becomes invalid!
    const resetSecret = JWT_SECRET + user.password_hash;
    const resetToken = jwt.sign(
      { email: user.email, action: 'password_reset' },
      resetSecret,
      { expiresIn: '15m' }
    );

    await logSecurityEvent({
      userId: user.id,
      action: 'AUTH_FORGOT_PASSWORD_REQUEST',
      req,
      details: { email }
    });

    // In local development or demonstration, we return the token in the response JSON
    if (process.env.NODE_ENV !== 'production') {
      genericResponse.resetToken = resetToken;
      genericResponse.resetLink = `/reset-password?token=${resetToken}`;
      genericResponse._devNote = 'For demonstration / API testing, reset link is exposed in the JSON response.';
    }

    res.json(genericResponse);

  } catch (err) {
    console.error('Forgot Password Error:', err.message);
    res.status(500).json({ error: 'An internal error occurred while generating reset link.' });
  }
}

/**
 * Reset Password
 */
async function resetPassword(req, res) {
  const { token, new_password } = req.body;

  if (!token || !new_password) {
    return res.status(400).json({ error: 'Token and new password are required.' });
  }

  const pwdError = validatePasswordStrength(new_password);
  if (pwdError) {
    return res.status(400).json({ error: pwdError });
  }

  try {
    // 1. Decode token statelessly to find user email
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.email || decoded.action !== 'password_reset') {
      return res.status(400).json({ error: 'Invalid or malformed reset token.' });
    }

    // 2. Fetch user information
    const userRes = await db.query('SELECT * FROM users WHERE email = $1', [decoded.email]);
    if (userRes.rowCount === 0) {
      return res.status(400).json({ error: 'User does not exist.' });
    }

    const user = userRes.rows[0];

    // 3. Cryptographically verify the reset token using the dynamic secret
    try {
      jwt.verify(token, JWT_SECRET + user.password_hash);
    } catch (err) {
      return res.status(400).json({ error: 'Password reset link has expired, is invalid, or has already been used.' });
    }

    // 4. Hash new password
    const salt = await bcrypt.genSalt(12);
    const newPasswordHash = await bcrypt.hash(new_password, salt);

    // 5. Update password in the database
    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newPasswordHash, user.id]);

    // 6. Force immediate global session revocation for this user (Multi-Session logout)
    await db.query(
      'UPDATE sessions SET is_active = $1 WHERE user_id = $2',
      [false, user.id]
    );

    // 7. Log audit event
    await logSecurityEvent({
      userId: user.id,
      action: 'AUTH_RESET_PASSWORD_SUCCESS',
      req,
      details: { email: user.email }
    });

    res.json({ message: 'Password reset successfully. All active sessions have been signed out.' });

  } catch (err) {
    console.error('Reset Password Error:', err.message);
    res.status(500).json({ error: 'An internal error occurred during password reset.' });
  }
}

/**
 * Get Profile
 */
async function getProfile(req, res) {
  res.json({ user: req.user });
}

async function setupMfa(req, res) {
  const userId = req.user.id;

  try {
    const userRes = await db.query('SELECT id, email, mfa_enabled FROM users WHERE id = $1', [userId]);
    if (userRes.rowCount === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = userRes.rows[0];
    const isMfaEnabled = user.mfa_enabled === true || user.mfa_enabled === 1 || user.mfa_enabled === '1';
    if (isMfaEnabled && user.mfa_secret) {
      return res.status(400).json({ error: 'MFA is already enabled. Disable or reset MFA before generating a new setup QR.' });
    }

    const secret = speakeasy.generateSecret({
      name: `DocuShield (${user.email})`,
      issuer: 'DocuShield',
      length: 20
    });

    await db.query('UPDATE users SET mfa_secret = $1 WHERE id = $2', [secret.base32, userId]);

    const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url, {
      errorCorrectionLevel: 'M',
      margin: 2,
      width: 240
    });

    res.json({
      otpauthUrl: secret.otpauth_url,
      qrCodeDataUrl,
      manualEntryKey: secret.base32,
      mfa_enabled: user.mfa_enabled === true || user.mfa_enabled === 1 || user.mfa_enabled === '1'
    });
  } catch (err) {
    console.error('MFA Setup Error:', err.message);
    res.status(500).json({ error: 'Failed to initialize MFA setup.' });
  }
}

async function verifyMfa(req, res) {
  const userId = req.user.id;
  const { token } = req.body;

  if (!token || !/^\d{6}$/.test(String(token))) {
    return res.status(400).json({ error: 'Enter the 6-digit authenticator code.' });
  }

  try {
    const userRes = await db.query('SELECT id, email, mfa_secret FROM users WHERE id = $1', [userId]);
    if (userRes.rowCount === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = userRes.rows[0];
    if (!user.mfa_secret) {
      return res.status(400).json({ error: 'MFA setup has not been initialized.' });
    }

    const verified = verifyTotpCode(user.mfa_secret, token);

    if (!verified) {
      await logSecurityEvent({
        userId,
        action: 'MFA_VERIFY_FAILED',
        req,
        details: { email: user.email },
        severity: 'warning'
      });
      return res.status(400).json({ error: 'Invalid MFA code. Check your phone time sync and try again.' });
    }

    await db.query('UPDATE users SET mfa_enabled = $1 WHERE id = $2', [true, userId]);

    await logSecurityEvent({
      userId,
      action: 'MFA_ENABLED',
      req,
      details: { email: user.email }
    });

    res.json({ message: 'MFA enabled successfully.', mfa_enabled: true });
  } catch (err) {
    console.error('MFA Verify Error:', err.message);
    res.status(500).json({ error: 'Failed to verify MFA code.' });
  }
}

module.exports = {
  register,
  login,
  logout,
  refresh,
  forgotPassword,
  resetPassword,
  getProfile,
  setupMfa,
  verifyMfa
};
