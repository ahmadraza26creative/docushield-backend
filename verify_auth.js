const db = require('./config/db');
const authController = require('./controllers/authController');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Mock request and response objects
function mockResponse() {
  const res = {
    statusCode: 200,
    headers: {},
    cookies: {},
    body: null,
    status: function (code) {
      this.statusCode = code;
      return this;
    },
    json: function (data) {
      this.body = data;
      return this;
    },
    cookie: function (name, val, options) {
      this.cookies[name] = { val, options };
      return this;
    },
    clearCookie: function (name) {
      delete this.cookies[name];
      return this;
    }
  };
  return res;
}

function mockRequest(body = {}, cookies = {}, headers = {}, user = null, sessionId = null) {
  return {
    body,
    cookies,
    headers: {
      'user-agent': 'Automated Test Harness',
      'x-forwarded-for': '127.0.0.1',
      ...headers
    },
    user,
    sessionId
  };
}

async function runTests() {
  console.log('🚀 Starting Authentication Module Integration Tests...');

  // 1. Initialize DB
  await db.initDb();
  console.log('✅ DB initialized.');

  // Clean tables before test to ensure reproducible run
  try {
    await db.query('DELETE FROM sessions');
    await db.query('DELETE FROM audit_logs');
    await db.query('DELETE FROM users');
    console.log('🧹 Cleaned existing test tables.');
  } catch (err) {
    console.log('⚠️ Failed to clean tables (could be first run):', err.message);
  }

  // 2. Test Registration Validation (Weak Password)
  console.log('\n--- Test 2: Register with Weak Password ---');
  let req = mockRequest({
    full_name: 'Adeeb Test',
    email: 'test@docushield.io',
    password: '123'
  });
  let res = mockResponse();
  await authController.register(req, res);
  console.log('Response Status:', res.statusCode);
  console.log('Response Error:', res.body?.error);
  if (res.statusCode === 400 && res.body?.error.includes('Password must be at least 8 characters')) {
    console.log('✅ Test 2 Passed: Weak password rejected successfully.');
  } else {
    throw new Error('Test 2 Failed');
  }

  // 3. Test Registration Success
  console.log('\n--- Test 3: Successful Registration ---');
  req = mockRequest({
    full_name: 'Adeeb Adeeb',
    email: 'adeeb@docushield.io',
    password: 'SecurePassWord123!'
  });
  res = mockResponse();
  await authController.register(req, res);
  console.log('Response Status:', res.statusCode);
  console.log('Registered User:', res.body?.user);
  if (res.statusCode === 201 && res.body?.user?.email === 'adeeb@docushield.io') {
    console.log('✅ Test 3 Passed: User registered successfully.');
  } else {
    throw new Error('Test 3 Failed');
  }

  // 4. Test Registration Duplicate Email
  console.log('\n--- Test 4: Duplicate Email Registration ---');
  req = mockRequest({
    full_name: 'Adeeb Duplicate',
    email: 'adeeb@docushield.io',
    password: 'SecurePassWord123!'
  });
  res = mockResponse();
  await authController.register(req, res);
  console.log('Response Status:', res.statusCode);
  console.log('Response Error:', res.body?.error);
  if (res.statusCode === 400 && res.body?.error.includes('already registered')) {
    console.log('✅ Test 4 Passed: Duplicate email registration blocked.');
  } else {
    throw new Error('Test 4 Failed');
  }

  // 5. Test Login Success & Cookies Setting
  console.log('\n--- Test 5: Successful Login ---');
  req = mockRequest({
    email: 'adeeb@docushield.io',
    password: 'SecurePassWord123!',
    device_fingerprint: 'Adeeb-Test-Browser'
  });
  res = mockResponse();
  await authController.login(req, res);
  console.log('Response Status:', res.statusCode);
  console.log('AccessToken in cookies:', !!res.cookies?.accessToken?.val);
  console.log('RefreshToken in cookies:', res.cookies?.refreshToken?.val);
  console.log('AccessToken in body:', !!res.body?.accessToken);
  if (res.statusCode === 200 && res.cookies?.refreshToken?.val) {
    console.log('✅ Test 5 Passed: Login successful, cookies set, session created.');
  } else {
    throw new Error('Test 5 Failed');
  }

  const activeSessionId = res.cookies?.refreshToken?.val;
  const activeAccessToken = res.cookies?.accessToken?.val;

  // 6. Verify Session Exists in Database
  console.log('\n--- Test 6: Verify Session in DB ---');
  const sessionCheck = await db.query('SELECT * FROM sessions WHERE id = $1', [activeSessionId]);
  console.log('Sessions found:', sessionCheck.rowCount);
  console.log('Session Active status:', sessionCheck.rows[0]?.is_active);
  if (sessionCheck.rowCount === 1 && (sessionCheck.rows[0]?.is_active === 1 || sessionCheck.rows[0]?.is_active === true)) {
    console.log('✅ Test 6 Passed: Session recorded and active in DB.');
  } else {
    throw new Error('Test 6 Failed');
  }

  // 7. Test Forgot Password
  console.log('\n--- Test 7: Forgot Password Link Generation ---');
  req = mockRequest({ email: 'adeeb@docushield.io' });
  res = mockResponse();
  await authController.forgotPassword(req, res);
  console.log('Response Message:', res.body?.message);
  console.log('Reset Token generated:', !!res.body?.resetToken);
  if (res.body?.resetToken) {
    console.log('✅ Test 7 Passed: Forgot password generated token statelessly.');
  } else {
    throw new Error('Test 7 Failed');
  }

  const resetToken = res.body?.resetToken;

  // 8. Test Reset Password Success
  console.log('\n--- Test 8: Reset Password Success ---');
  req = mockRequest({
    token: resetToken,
    new_password: 'NewStrongPassword456$'
  });
  res = mockResponse();
  await authController.resetPassword(req, res);
  console.log('Response Status:', res.statusCode);
  console.log('Response Message:', res.body?.message);
  if (res.statusCode === 200 && res.body?.message.includes('Password reset successfully')) {
    console.log('✅ Test 8 Passed: Password reset successful.');
  } else {
    throw new Error('Test 8 Failed');
  }

  // 9. Verify Sessions Invalidated globally after Password Reset
  console.log('\n--- Test 9: Global Session Revocation Verification ---');
  const sessionRevocationCheck = await db.query('SELECT * FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1)', ['adeeb@docushield.io']);
  console.log('Sessions count:', sessionRevocationCheck.rowCount);
  const activeSessions = sessionRevocationCheck.rows.filter(s => s.is_active === 1 || s.is_active === true);
  console.log('Active Sessions remaining:', activeSessions.length);
  if (activeSessions.length === 0) {
    console.log('✅ Test 9 Passed: All active sessions revoked globally for security.');
  } else {
    throw new Error('Test 9 Failed');
  }

  // 10. Attempt to Use Same Reset Token Again (Should fail because password hash changed!)
  console.log('\n--- Test 10: Replay Reset Token Protection ---');
  req = mockRequest({
    token: resetToken,
    new_password: 'AnotherNewPassword789!'
  });
  res = mockResponse();
  await authController.resetPassword(req, res);
  console.log('Response Status:', res.statusCode);
  console.log('Response Error:', res.body?.error);
  if (res.statusCode === 400 && res.body?.error.includes('expired, is invalid, or has already been used')) {
    console.log('✅ Test 10 Passed: Replay reset attack blocked via dynamic secrets.');
  } else {
    throw new Error('Test 10 Failed');
  }

  // 11. Login with New Password
  console.log('\n--- Test 11: Login with New Password ---');
  req = mockRequest({
    email: 'adeeb@docushield.io',
    password: 'NewStrongPassword456$'
  });
  res = mockResponse();
  await authController.login(req, res);
  console.log('Response Status:', res.statusCode);
  if (res.statusCode === 200) {
    console.log('✅ Test 11 Passed: Login with new password succeeded.');
  } else {
    throw new Error('Test 11 Failed');
  }

  console.log('\n🌟 ALL Integration Tests Completed Successfully! 🌟');
  process.exit(0);
}

runTests().catch(err => {
  console.error('\n💥 Test Suite Failed:', err.message);
  process.exit(1);
});
