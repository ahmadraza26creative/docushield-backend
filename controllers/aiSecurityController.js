const AiSecurityService = require('../services/aiSecurityService');

/**
 * AI Security Controller
 */
async function getAiAnalysis(req, res) {
  try {
    const report = await AiSecurityService.runSecurityAudit();
    res.json(report);
  } catch (err) {
    console.error('aiSecurityController.getAiAnalysis Error:', err.message);
    res.status(500).json({ error: 'Failed to complete AI security audit scanning.' });
  }
}

module.exports = {
  getAiAnalysis
};
