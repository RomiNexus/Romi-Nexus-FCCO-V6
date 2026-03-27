/**
 * ROMI NEXUS AUDIT LOGGER MODULE (Vanilla JS)
 * ISSUE-11: Security Logging & Monitoring (OWASP #9)
 * DIFC Compliance: Record-Keeping & Audit Trail
 */

const AUDIT_CONFIG = {
  logLevel: 'INFO',
  retentionDays: 90,
  siem_enabled: false,
  siem_endpoint: 'https://siem.rominexus.com/api/events',
};

/**
 * Create audit log entry
 */
function createAuditLog(eventType, details, severity = 'INFO') {
  const timestamp = new Date().toISOString();
  
  // Try to get session data if available
  let sessionData = {};
  try {
    const email = typeof getSessionEmail === 'function' ? getSessionEmail() : localStorage.getItem('user_email');
    const token = typeof getSessionToken === 'function' ? getSessionToken() : localStorage.getItem('sessionToken');
    sessionData = {
      email,
      sessionId: token ? token.substring(0, 8) : 'UNKNOWN',
    };
  } catch (e) {
    sessionData = { email: 'ANONYMOUS', sessionId: 'UNKNOWN' };
  }
  
  return {
    timestamp,
    eventType,
    severity,
    userId: sessionData.email || 'ANONYMOUS',
    sessionId: sessionData.sessionId || 'UNKNOWN',
    userAgent: navigator.userAgent,
    details,
  };
}

/**
 * Log authentication attempt
 */
function logAuthenticationAttempt(email, success, method = 'OTP') {
  const log = createAuditLog(
    'AUTHENTICATION_ATTEMPT',
    {
      email,
      success,
      method,
      timestamp: new Date().toISOString(),
    },
    success ? 'INFO' : 'WARN'
  );
  
  persistLog(log);
  if (!success) {
    sendToSIEM(log);
  }
}

/**
 * Log API calls
 */
function logAPICall(endpoint, method, statusCode, durationMs) {
  const log = createAuditLog(
    'API_CALL',
    {
      endpoint,
      method,
      statusCode,
      durationMs,
    },
    statusCode >= 400 ? 'WARN' : 'INFO'
  );
  
  persistLog(log);
}

/**
 * Log data access
 */
function logDataAccess(userId, resourceType, resourceId, action) {
  const log = createAuditLog(
    'DATA_ACCESS',
    {
      userId,
      resourceType,
      resourceId,
      action,
    },
    'INFO'
  );
  
  persistLog(log);
}

/**
 * Log security alerts
 */
function logSecurityAlert(alertType, severity, details) {
  const log = createAuditLog(alertType, details, severity);
  persistLog(log);
  sendToSIEM(log);
}

/**
 * Persist log locally
 */
function persistLog(log) {
  try {
    const logs = JSON.parse(localStorage.getItem('audit_logs') || '[]');
    logs.push(log);
    
    // Keep only recent logs (90 days)
    const recentLogs = logs.filter((l) => {
      const age = Date.now() - new Date(l.timestamp).getTime();
      return age < AUDIT_CONFIG.retentionDays * 24 * 60 * 60 * 1000;
    });
    
    localStorage.setItem('audit_logs', JSON.stringify(recentLogs.slice(-1000)));
  } catch (error) {
    console.error('[ERROR] Failed to persist audit log:', error);
  }
}

/**
 * Send critical events to SIEM
 */
async function sendToSIEM(log) {
  if (!AUDIT_CONFIG.siem_enabled) return;
  
  try {
    await fetch(AUDIT_CONFIG.siem_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(log),
    });
  } catch (error) {
    console.error('[ERROR] SIEM delivery failed:', error);
  }
}

/**
 * Export audit logs for compliance
 */
function exportAuditLogs(startDate, endDate) {
  const logs = JSON.parse(localStorage.getItem('audit_logs') || '[]');
  
  const filtered = logs.filter((log) => {
    const logDate = new Date(log.timestamp);
    return logDate >= startDate && logDate <= endDate;
  });
  
  return {
    exportDate: new Date().toISOString(),
    period: { startDate, endDate },
    totalRecords: filtered.length,
    logs: filtered,
  };
}

/**
 * Clear old audit logs (cleanup)
 */
function cleanupOldLogs() {
  const logs = JSON.parse(localStorage.getItem('audit_logs') || '[]');
  const cutoffDate = new Date(Date.now() - AUDIT_CONFIG.retentionDays * 24 * 60 * 60 * 1000);
  
  const retained = logs.filter((log) => new Date(log.timestamp) >= cutoffDate);
  localStorage.setItem('audit_logs', JSON.stringify(retained));
  
  console.log(`[AUDIT] Cleaned up ${logs.length - retained.length} old logs`);
  
  return { deleted: logs.length - retained.length, retained: retained.length };
}

/**
 * Enable/disable SIEM integration
 */
function enableSIEM(endpoint) {
  AUDIT_CONFIG.siem_enabled = true;
  AUDIT_CONFIG.siem_endpoint = endpoint;
  console.log('[AUDIT] SIEM integration enabled');
}

/**
 * Get audit logs summary
 */
function getAuditSummary() {
  const logs = JSON.parse(localStorage.getItem('audit_logs') || '[]');
  
  return {
    totalLogs: logs.length,
    byType: logs.reduce((acc, log) => {
      acc[log.eventType] = (acc[log.eventType] || 0) + 1;
      return acc;
    }, {}),
    bySeverity: logs.reduce((acc, log) => {
      acc[log.severity] = (acc[log.severity] || 0) + 1;
      return acc;
    }, {}),
    lastLog: logs[logs.length - 1] || null,
  };
}

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    logAuthenticationAttempt,
    logAPICall,
    logDataAccess,
    logSecurityAlert,
    exportAuditLogs,
    cleanupOldLogs,
    enableSIEM,
    getAuditSummary,
  };
}
