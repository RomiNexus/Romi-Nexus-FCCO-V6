/**
 * ROMI NEXUS DATA RETENTION & PRIVACY MODULE (Vanilla JS)
 * DIFC Compliance: Data Protection & GDPR Alignment
 */

const DATA_RETENTION_POLICIES = {
  PERSONAL_DATA: 1825,
  TRANSACTION_DATA: 2555,
  SESSION_LOGS: 90,
  FAILED_LOGIN_ATTEMPTS: 30,
  AUDIT_LOGS: 365,
};

function _generateToken(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < length; i++) token += chars[Math.floor(Math.random() * chars.length)];
  return token;
}

function setRetentionPolicy(dataType, retentionDays) {
  DATA_RETENTION_POLICIES[dataType] = retentionDays;
  if (typeof logSecurityAlert === 'function') logSecurityAlert('RETENTION_POLICY_UPDATED', 'INFO', { dataType, retentionDays });
}

function scheduleDataDeletion(userId, dataType, delayDays = 30) {
  const deletionDate = new Date(Date.now() + delayDays * 24 * 60 * 60 * 1000);
  const task = { id: _generateToken(16), userId, dataType, scheduledFor: deletionDate.toISOString(), createdAt: new Date().toISOString() };
  const tasks = JSON.parse(localStorage.getItem('deletion_tasks') || '[]');
  tasks.push(task);
  localStorage.setItem('deletion_tasks', JSON.stringify(tasks));
  if (typeof logSecurityAlert === 'function') logSecurityAlert('DATA_DELETION_SCHEDULED', 'WARN', { userId, dataType, scheduledFor: deletionDate.toISOString() });
  return task;
}

function exportUserData(userId) {
  const exportDate = new Date().toISOString();
  const allLogs = JSON.parse(localStorage.getItem('audit_logs') || '[]');
  const userData = {
    exportDate, userId,
    dataTypes: {
      auditLogs: allLogs.filter((l) => l.userId === userId),
      preferences: { language: 'en', timezone: 'UTC+4', notifications: true },
    },
  };
  if (typeof logSecurityAlert === 'function') logSecurityAlert('USER_DATA_EXPORT', 'WARN', { userId, exportDate });
  return userData;
}

function deleteUserData(userId) {
  const deletionDate = new Date().toISOString();
  const logs = JSON.parse(localStorage.getItem('audit_logs') || '[]');
  localStorage.setItem('audit_logs', JSON.stringify(logs.filter((log) => log.userId !== userId)));
  if (typeof logSecurityAlert === 'function') logSecurityAlert('USER_DATA_DELETED', 'WARN', { userId, deletionDate });
  return { success: true, userId, deletionDate };
}

function anonymizeData(userId) {
  const logs = JSON.parse(localStorage.getItem('audit_logs') || '[]');
  const anonymized = logs.map((log) => log.userId === userId ? { ...log, userId: 'ANONYMOUS_' + _generateToken(8) } : log);
  localStorage.setItem('audit_logs', JSON.stringify(anonymized));
  if (typeof logSecurityAlert === 'function') logSecurityAlert('USER_DATA_ANONYMIZED', 'INFO', { userId });
  return { success: true, userId };
}

function enforceRetentionPolicies() {
  const logs = JSON.parse(localStorage.getItem('audit_logs') || '[]');
  const now = Date.now();
  const retained = logs.filter((log) => {
    const logAge = now - new Date(log.timestamp).getTime();
    let retentionMs = DATA_RETENTION_POLICIES.AUDIT_LOGS * 24 * 60 * 60 * 1000;
    if (log.eventType === 'AUTHENTICATION_ATTEMPT') retentionMs = DATA_RETENTION_POLICIES.FAILED_LOGIN_ATTEMPTS * 24 * 60 * 60 * 1000;
    return logAge < retentionMs;
  });
  localStorage.setItem('audit_logs', JSON.stringify(retained));
  return { deleted: logs.length - retained.length, retained: retained.length };
}

function createDataProcessingConsent(userId, purposes) {
  const consent = { id: _generateToken(16), userId, purposes, grantedAt: new Date().toISOString(), version: '1.0', status: 'ACCEPTED' };
  if (typeof logSecurityAlert === 'function') logSecurityAlert('DATA_PROCESSING_CONSENT_GIVEN', 'INFO', { userId, purposes });
  return consent;
}

function revokeDataProcessingConsent(userId) {
  if (typeof logSecurityAlert === 'function') logSecurityAlert('DATA_PROCESSING_CONSENT_REVOKED', 'WARN', { userId });
  scheduleDataDeletion(userId, 'ALL');
  return { success: true, userId };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { setRetentionPolicy, scheduleDataDeletion, exportUserData, deleteUserData, anonymizeData, enforceRetentionPolicies, createDataProcessingConsent, revokeDataProcessingConsent };
}
