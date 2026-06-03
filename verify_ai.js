const db = require('./config/db');
const AiSecurityService = require('./services/aiSecurityService');
const bcrypt = require('bcryptjs');

async function runTests() {
  console.log('🚀 Starting AI Security Monitoring Module Integration Tests...');

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

  // 2. Insert Test Users
  console.log('\n--- Seeding Test Accounts ---');
  const salt = await bcrypt.genSalt(10);
  const passwordHash = await bcrypt.hash('SecurePassWord123!', salt);
  
  // Seed an Editor and a Viewer
  const user1 = await db.query(
    `INSERT INTO users (full_name, email, password_hash, role, department, status) 
     VALUES ($1, $2, $3, $4, $5, $6)`,
    ['Adeeb Editor', 'editor@docushield.io', passwordHash, 'editor', 'Engineering', 'active']
  );
  const user2 = await db.query(
    `INSERT INTO users (full_name, email, password_hash, role, department, status) 
     VALUES ($1, $2, $3, $4, $5, $6)`,
    ['Adeeb Viewer', 'viewer@docushield.io', passwordHash, 'viewer', 'Legal', 'active']
  );

  const editorRows = await db.query("SELECT id FROM users WHERE email = 'editor@docushield.io'");
  const viewerRows = await db.query("SELECT id FROM users WHERE email = 'viewer@docushield.io'");
  
  const editorId = editorRows.rows[0].id;
  const viewerId = viewerRows.rows[0].id;
  console.log(`✅ Seeded users. Editor ID: ${editorId}, Viewer ID: ${viewerId}`);

  // 3. Seed Target Logs representing Anomaly Detection (Malware)
  console.log('\n--- Seeding Anomaly (Malware Quarantined) ---');
  await db.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, device_info, user_agent, details, severity, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, datetime('now'))`,
    [
      editorId,
      'MALWARE_DETECTED',
      '192.168.1.100',
      'Windows Chrome',
      'Mozilla/5.0',
      JSON.stringify({ filename: 'financial_report_virus.xlsx', hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }),
      'critical'
    ]
  );
  console.log('✅ Seeded MALWARE_DETECTED log.');

  // 4. Seed Target Logs representing Suspicious Download Detection (Download bursts)
  console.log('\n--- Seeding Suspicious Download Burst (>= 3 downloads in 2 min) ---');
  // We insert 3 downloads very close to each other
  const now = new Date();
  for (let i = 0; i < 3; i++) {
    const timeStr = new Date(now.getTime() - i * 10 * 1000).toISOString().replace('T', ' ').substring(0, 19); // 10s gap
    await db.query(
      `INSERT INTO audit_logs (user_id, action, ip_address, device_info, user_agent, details, severity, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        viewerId,
        'FILE_DOWNLOAD',
        '192.168.1.105',
        'Mac Safari',
        'Mozilla/5.0',
        JSON.stringify({ documentId: `doc-uuid-${i}`, title: `Confidential Document ${i}.pdf` }),
        'info',
        timeStr
      ]
    );
  }
  console.log('✅ Seeded 3 fast FILE_DOWNLOAD logs.');

  // 5. Seed Target Logs representing Unusual Login Alerts (AUTH_LOGIN_FAILED)
  console.log('\n--- Seeding Unusual Login Alerts (Failed Passkeys) ---');
  await db.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, device_info, user_agent, details, severity, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, datetime('now'))`,
    [
      null, // Guest account or non-logged-in
      'AUTH_LOGIN_FAILED',
      '198.51.100.45',
      'Unknown Linux',
      'curl/7.68.0',
      JSON.stringify({ reason: 'Incorrect passkey or bad security MFA signature', email: 'editor@docushield.io' }),
      'warning'
    ]
  );
  console.log('✅ Seeded AUTH_LOGIN_FAILED log.');

  // 6. Seed Target Logs representing Insider Threat Detection (Access boundary breaches)
  console.log('\n--- Seeding Insider Threat (Zero-Trust boundary breach) ---');
  await db.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, device_info, user_agent, details, severity, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, datetime('now'))`,
    [
      viewerId,
      'ACCESS_DENIED',
      '192.168.1.105',
      'Mac Safari',
      'Mozilla/5.0',
      JSON.stringify({ action: 'Repeated unauthorised editor write access attempts to private ledger files', documentId: 'ledger-999' }),
      'warning'
    ]
  );
  console.log('✅ Seeded ACCESS_DENIED boundary violation log.');

  // 7. Run AI Heuristics/Completions Audit
  console.log('\n--- Running AI Security Audit Engine ---');
  // Check if process.env.OPENAI_API_KEY exists
  const hasKey = !!process.env.OPENAI_API_KEY;
  console.log(`OpenAI API Key configuration state: ${hasKey ? 'CONFIGURED (Online completions)' : 'ABSENT (Offline heuristics fallback)'}`);
  
  const report = await AiSecurityService.runSecurityAudit();
  
  console.log('\n==================================================');
  console.log('🛡️  AI SECURITY MONITOR REPORT RESOLVED:');
  console.log('==================================================');
  console.log(`Risk Score:   ${report.riskScore}%`);
  console.log(`Threat Level: ${report.threatLevel.toUpperCase()}`);
  console.log(`Summary:      ${report.summary}`);
  
  console.log('\n🔍 Anomalies Found:', report.anomalies.length);
  report.anomalies.forEach((a, i) => {
    console.log(`  [${i+1}] Type: ${a.type} | User: ${a.user} | Severity: ${a.severity.toUpperCase()}\n      Desc: ${a.description}`);
  });

  console.log('\n📦 Suspicious Downloads Found:', report.suspiciousDownloads.length);
  report.suspiciousDownloads.forEach((d, i) => {
    console.log(`  [${i+1}] User: ${d.user} | Count: ${d.count} in ${d.timeframe} | Risk: ${d.riskLevel.toUpperCase()}`);
  });

  console.log('\n🚨 Unusual Logins Found:', report.unusualLogins.length);
  report.unusualLogins.forEach((l, i) => {
    console.log(`  [${i+1}] User: ${l.user} | IP: ${l.ip} | Reason: ${l.reason}`);
  });

  console.log('\n👥 Insider Threats Detected:', report.insiderThreats.length);
  report.insiderThreats.forEach((t, i) => {
    console.log(`  [${i+1}] User: ${t.user} | Behavior: ${t.behavior} | Confidence: ${t.confidenceScore}% | Level: ${t.threatLevel.toUpperCase()}`);
  });

  console.log('\n🛠️  AI Recommended Remediation Actions:');
  report.remediations.forEach((r, i) => {
    console.log(`  ${i+1}. ${r}`);
  });

  console.log('\n==================================================');

  // Verify basic assertions
  if (report.riskScore > 35 && report.anomalies.length > 0 && report.suspiciousDownloads.length > 0 && report.unusualLogins.length > 0 && report.insiderThreats.length > 0) {
    console.log('🌟 ALL AI SECURITY AUDIT CHECKS COMPLETED AND ASSERTS PASSED PERFECTLY! 🌟');
    process.exit(0);
  } else {
    console.error('❌ Test failed: Risk score or threat detections were not computed properly.');
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('\n💥 AI Security Test Suite Failed:', err.message);
  process.exit(1);
});
