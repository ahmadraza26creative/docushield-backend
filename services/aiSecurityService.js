const db = require('../config/db');

/**
 * Enterprise AI Security Monitoring Service
 */
class AiSecurityService {
  /**
   * Run AI security audit scanning on the latest compliance logs
   */
  static async runSecurityAudit() {
    try {
      // 1. Fetch latest 50 audit logs
      const logRes = await db.query(`
        SELECT al.id, al.action, al.ip_address, al.user_agent, al.device_info, al.details, al.severity, al.created_at,
               u.email as user_email
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.created_at DESC
        LIMIT 50
      `);

      const logs = logRes.rows.map(row => {
        if (typeof row.details === 'string') {
          try { row.details = JSON.parse(row.details); } catch {}
        }
        return row;
      });

      // 2. Resolve OpenAI API execution or intelligent fallback
      const apiKey = process.env.OPENAI_API_KEY;
      if (apiKey) {
        return await this.callOpenAiApi(logs, apiKey);
      } else {
        return this.runHeuristicsScanner(logs);
      }
    } catch (err) {
      console.error('AiSecurityService.runSecurityAudit Error:', err.message);
      throw err;
    }
  }

  /**
   * Make dynamic HTTP API call to OpenAI completions endpoint
   */
  static async callOpenAiApi(logs, apiKey) {
    const prompt = `
      You are an enterprise cybersecurity analyst auditing a Zero-Trust document sharing platform.
      Analyze the following array of security audit logs and identify threat models.
      Specifically track:
      1. Anomaly Detection (strange events or multiple high-severity warnings)
      2. Suspicious Download Detection (mass downloads of files by a user in a short period)
      3. Unusual Login Alerts (logins from different IPs within minutes, or suspended accounts trying to login)
      4. Insider Threat Detection (users accessing files they don't own or trying to perform unauthorized write operations repeatedly)

      Logs payload:
      ${JSON.stringify(logs, null, 2)}

      You MUST respond with a strict, valid JSON object ONLY. Do not wrap in markdown quotes. The JSON must match this structure:
      {
        "riskScore": 45, // Integer 0 to 100 representing overall system risk
        "threatLevel": "moderate", // "low", "moderate", "high", "critical"
        "summary": "AI security audit summary of the system state...",
        "anomalies": [
          { "type": "Malware Detected / Bulk Access Denied / etc", "description": "Details...", "severity": "critical/warning/info", "user": "user@email.com" }
        ],
        "suspiciousDownloads": [
          { "user": "user@email.com", "documentId": "uuid", "count": 5, "timeframe": "1 min", "riskLevel": "high" }
        ],
        "unusualLogins": [
          { "user": "user@email.com", "ip": "192.168.1.50", "reason": "Fingerprint signature mismatch", "time": "2026-06-02T12:00:00" }
        ],
        "insiderThreats": [
          { "user": "user@email.com", "behavior": "Repeated edit attempts on non-owned files", "confidenceScore": 85, "threatLevel": "high" }
        ],
        "remediations": [
          "Suggest action 1...",
          "Suggest action 2..."
        ]
      }
    `;

    try {
      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          messages: [
            { role: 'system', content: 'You are an advanced cybersecurity AI engine. You output strict JSON analysis.' },
            { role: 'user', content: prompt }
          ],
          temperature: 0.1,
          response_format: { type: 'json_object' }
        })
      });

      if (!response.ok) {
        throw new Error(`OpenAI API returned status ${response.status}`);
      }

      const resData = await response.json();
      const content = resData.choices[0].message.content.trim();
      return JSON.parse(content);
    } catch (err) {
      console.warn('⚠️ OpenAI API call failed, falling back to heuristics engine.', err.message);
      return this.runHeuristicsScanner(logs);
    }
  }

  /**
   * Deterministic, intelligent heuristics scanner (high-fidelity mock system)
   * Evaluates standard security threat vectors locally
   */
  static runHeuristicsScanner(logs) {
    let riskScore = 15;
    const anomalies = [];
    const suspiciousDownloads = [];
    const unusualLogins = [];
    const insiderThreats = [];
    const remediations = [];

    // Map helpers to track download bursts
    const userDownloads = {};
    const ipLogins = {};
    let malwareIncidents = 0;
    let authFailures = 0;
    let accessDenials = 0;

    // Scan through recent logs to extract telemetry patterns
    logs.forEach(log => {
      const email = log.user_email || 'GUEST / SYSTEM';
      
      // A. Malware scan indicators
      if (log.action === 'MALWARE_DETECTED') {
        malwareIncidents++;
        riskScore += 25;
        anomalies.push({
          type: 'Malware containment trigger',
          description: `A malicious signature was quarantined in file: ${log.details?.filename || 'quarantined'}`,
          severity: 'critical',
          user: email
        });
        remediations.push(`Revoke the user node account ${email} immediately and inspect local upload containers.`);
      }

      // B. Authentication failures
      if (log.action === 'AUTH_LOGIN_FAILED') {
        authFailures++;
        riskScore += 8;
        
        // Track multiple failed logins from one user
        unusualLogins.push({
          user: email,
          ip: log.ip_address,
          reason: `Failed authorization: ${log.details?.reason || 'Incorrect passkey'}`,
          time: log.created_at
        });
      }

      // C. Access Denials (Privilege abuse / token hijacks)
      if (log.action === 'ACCESS_DENIED' || log.action === 'TOKEN_HIJACK_ATTEMPT' || log.action === 'IP_RESTRICTION_VIOLATION') {
        accessDenials++;
        riskScore += 15;
        
        insiderThreats.push({
          user: email,
          behavior: `Abusing authorization boundaries: ${log.details?.action || 'unauthorized view access attempt'}`,
          confidenceScore: 78,
          threatLevel: log.action === 'TOKEN_HIJACK_ATTEMPT' ? 'high' : 'medium'
        });
      }

      // D. Suspicious download burst tracking
      if (log.action === 'FILE_DOWNLOAD') {
        const timeBucket = new Date(log.created_at).getTime();
        if (!userDownloads[email]) {
          userDownloads[email] = [];
        }
        userDownloads[email].push(timeBucket);
      }
    });

    // Evaluate download burst thresholds (mass files downloaded in short timeframe)
    Object.keys(userDownloads).forEach(email => {
      const times = userDownloads[email];
      if (times.length >= 3) {
        // Simple heuristic: if 3 or more downloads happen in 2 minutes, trigger alert
        const isBurst = (times[0] - times[times.length - 1]) <= 2 * 60 * 1000;
        if (isBurst) {
          riskScore += 20;
          suspiciousDownloads.push({
            user: email,
            count: times.length,
            timeframe: '2 minutes',
            riskLevel: 'high'
          });
          remediations.push(`Enforce rate-limiting restrictions or suspend ${email} pending key leak audits.`);
        }
      }
    });

    // Establish general remediation suggestions
    if (authFailures > 2) {
      remediations.push('IP address lockout policy is recommended due to brute-force credential stuffing alerts.');
    }
    if (accessDenials > 1) {
      remediations.push('Re-verify document sharing privileges and inspect the zero-trust policy engine matrix.');
    }
    if (riskScore === 15) {
      remediations.push('DocuShield systems report nominal operational compliance status. Continue standard audits.');
    }

    // Risk mapping
    riskScore = Math.min(riskScore, 100);
    let threatLevel = 'low';
    if (riskScore > 75) threatLevel = 'critical';
    else if (riskScore > 50) threatLevel = 'high';
    else if (riskScore > 25) threatLevel = 'moderate';

    const summary = riskScore > 35 
      ? `Continuous monitoring has detected anomalous activities. System risk index has elevated to ${riskScore} due to ${malwareIncidents} malware threat, ${authFailures} failed authorizations, and ${suspiciousDownloads.length} suspicious download bursts.`
      : 'AI security agents report system state is fully nominal. Access boundaries are intact with zero suspicious events.';

    return {
      riskScore,
      threatLevel,
      summary,
      anomalies,
      suspiciousDownloads,
      unusualLogins,
      insiderThreats,
      remediations
    };
  }
}

module.exports = AiSecurityService;
