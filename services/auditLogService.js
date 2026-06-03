const db = require('../config/db');

/**
 * Enterprise Audit Log Service
 */
class AuditLogService {
  /**
   * Retrieve list of logs with filters and pagination
   */
  static async getLogs({ limit = 50, offset = 0, search = '', severity = '', action = '' }) {
    let queryText = `
      SELECT al.id, al.action, al.ip_address, al.user_agent, al.device_info, al.details, al.severity, al.created_at,
             u.email as user_email
      FROM audit_logs al
      LEFT JOIN users u ON al.user_id = u.id
    `;
    const params = [];
    const clauses = [];

    if (search) {
      params.push(`%${search}%`);
      clauses.push(`(al.action LIKE $${params.length} OR u.email LIKE $${params.length} OR al.ip_address LIKE $${params.length} OR al.details LIKE $${params.length})`);
    }

    if (severity) {
      params.push(severity);
      clauses.push(`al.severity = $${params.length}`);
    }

    if (action) {
      params.push(action);
      clauses.push(`al.action = $${params.length}`);
    }

    if (clauses.length > 0) {
      queryText += ' WHERE ' + clauses.join(' AND ');
    }

    // Total Count query
    let countQueryText = `
      SELECT COUNT(*) as count 
      FROM audit_logs al
      LEFT JOIN users u ON al.user_id = u.id
    `;
    if (clauses.length > 0) {
      countQueryText += ' WHERE ' + clauses.join(' AND ');
    }
    const countRes = await db.query(countQueryText, params);
    const totalCount = parseInt(countRes.rows[0]?.count || 0);

    // Add pagination
    queryText += ` ORDER BY al.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(parseInt(limit), parseInt(offset));

    const logRes = await db.query(queryText, params);

    const logs = logRes.rows.map(row => {
      if (typeof row.details === 'string') {
        try {
          row.details = JSON.parse(row.details);
        } catch {
          // keep as is
        }
      }
      return row;
    });

    return { logs, totalCount };
  }

  /**
   * Get analytical stats for the Security Dashboard
   */
  static async getStats() {
    // 1. Severity Counts
    const severityRes = await db.query(`
      SELECT severity, COUNT(*) as count 
      FROM audit_logs 
      GROUP BY severity
    `);
    const severityBreakdown = { info: 0, warning: 0, critical: 0 };
    severityRes.rows.forEach(r => {
      severityBreakdown[r.severity] = parseInt(r.count || 0);
    });

    // 2. Action Counts (Top Actions)
    const actionRes = await db.query(`
      SELECT action, COUNT(*) as count 
      FROM audit_logs 
      GROUP BY action 
      ORDER BY count DESC 
      LIMIT 10
    `);
    const topActions = actionRes.rows.map(r => ({
      action: r.action,
      count: parseInt(r.count || 0)
    }));

    // 3. Top Active IPs
    const ipRes = await db.query(`
      SELECT ip_address, COUNT(*) as count 
      FROM audit_logs 
      GROUP BY ip_address 
      ORDER BY count DESC 
      LIMIT 5
    `);
    const topIps = ipRes.rows.map(r => ({
      ip_address: r.ip_address,
      count: parseInt(r.count || 0)
    }));

    // 4. Hourly / Daily Timeline (Last 7 days of events)
    const timelineRes = await db.query(`
      SELECT created_at as timestamp
      FROM audit_logs 
      ORDER BY created_at ASC
    `);

    const timelineMap = {};
    const last7Days = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().split('T')[0];
      timelineMap[dateStr] = 0;
      last7Days.push(dateStr);
    }

    timelineRes.rows.forEach(row => {
      try {
        const dateStr = new Date(row.timestamp).toISOString().split('T')[0];
        if (timelineMap[dateStr] !== undefined) {
          timelineMap[dateStr]++;
        }
      } catch (e) {
        // ignore parsing err
      }
    });

    const eventTimeline = last7Days.map(date => ({
      date,
      count: timelineMap[date] || 0
    }));

    // 5. Overall System Stats
    const totalLogsRes = await db.query('SELECT COUNT(*) as count FROM audit_logs');
    const totalEvents = parseInt(totalLogsRes.rows[0]?.count || 0);

    const activeUsersRes = await db.query('SELECT COUNT(DISTINCT user_id) as count FROM audit_logs WHERE user_id IS NOT NULL');
    const activeUsersCount = parseInt(activeUsersRes.rows[0]?.count || 0);

    return {
      totalEvents,
      activeUsersCount,
      severityBreakdown,
      topActions,
      topIps,
      eventTimeline
    };
  }
}

module.exports = AuditLogService;
