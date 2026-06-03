const AuditLogService = require('../services/auditLogService');

/**
 * AuditLogController handles enterprise-grade compliance auditing requests
 */
async function getAuditLogs(req, res) {
  const { limit = 50, offset = 0, search = '', severity = '', action = '' } = req.query;

  try {
    const { logs, totalCount } = await AuditLogService.getLogs({
      limit,
      offset,
      search,
      severity,
      action
    });

    res.json({
      logs,
      totalCount,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
  } catch (err) {
    console.error('AuditLogController.getAuditLogs Error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve compliance audit logs.' });
  }
}

/**
 * Fetch compliance analytics and security incident telemetry
 */
async function getAuditStats(req, res) {
  try {
    const stats = await AuditLogService.getStats();
    res.json(stats);
  } catch (err) {
    console.error('AuditLogController.getAuditStats Error:', err.message);
    res.status(500).json({ error: 'Failed to compile security log telemetry.' });
  }
}

module.exports = {
  getAuditLogs,
  getAuditStats
};
