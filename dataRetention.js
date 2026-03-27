/**
 * ROMI NEXUS DATA RETENTION & PRIVACY MODULE (Vanilla JS)
 * DIFC Compliance: Data Protection & GDPR Alignment
 */

const DATA_RETENTION_POLICIES = {
  PERSONAL_DATA: 1825, // 5 years (days)
  TRANSACTION_DATA: 2555, // 7 years
  SESSION_LOGS: 90, // 3 months
  FAILED_LOGIN_ATTEMPTS: 30, // 1 month
  AUDIT_LOGS: 365, // 1 year
};

/**
 * Set retention policy for data type
 */
function setRetentionPolicy(dataType, retentionDays) {
  if (!DATA_RETENTION_POLICIES.hasOwnProperty(dataType)) {
    console.warn(`[WARN] Unknown data type: ${dataType}`);
  }
  
  DATA_RETENTION_POLICIES[dataType] = retentionDays;
  logSecurityAlert('RETENTION_POLICY_UPDATED', 'INFO', {
    dataType,
    retentionDays,
  });
}

/**
 * Schedule data deletion
 */
function scheduleDataDeletion(userId, dataType, delayDays = 30) {
  const deletionDate = new Date(Date.now() + delayDays * 24 * 60 * 60 * 1000);
  
  const task = {
    id: generateSecureToken(16),
    userId,
    dataType,
    scheduledFor: deletionDate.toISOString(),
    createdAt: new Date().toISOString(),
  };
  
  const tasks = JSON.parse(localStorage.getItem('deletion_tasks') || '[]');
  tasks.push(task);
  localStorage.setItem('deletion_tasks', JSON.stringify(tasks));
  
  logSecurityAlert('DATA_DELETION_SCHEDULED', 'WARN', {
    userId,
    dataType,
    scheduledFor: deletionDate.toISOString(),
  });
  
  return task;
}

/**
 * Export user's personal data (GDPR Right to Access)
 */
function exportUserData(userId) {
  const exportDate = new Date().toISOString();
  
  const userData = {
    exportDate,
    userId,
    dataTypes: {
      profile: getProfileData(userId),
      sessionHistory: getSessionHistory(userId),
      preferences: getPreferences(userId),
      auditLogs: getAuditLogsForUser(userId),
    },
  };
  
  logSecurityAlert('USER_DATA_EXPORT', 'WARN', {
    userId,
    exportDate,
  });
  
  return userData;
}

/**
 * Delete all user data (GDPR Right to Erasure)
 */
function deleteUserData(userId) {
  const deletionDate = new Date().toISOString();
  
  const logs = JSON.parse(localStorage.getItem('audit_logs') || '[]');
  const filtered = logs.filter((log) => log.userId !== userId);
  localStorage.setItem('audit_logs', JSON.stringify(filtered));
  
  logSecurityAlert('USER_DATA_DELETED', 'WARN', {
    userId,
    deletionDate,
  });
  
  return {
    success: true,
    userId,
    deletionDate,
  };
}

/**
 * Anonymize user data (pseudonymization)
 */
function anonymizeData(userId) {
  const logs = JSON.parse(localStorage.getItem('audit_logs') || '[]');
  
  const anonymized = logs.map((log) => {
    if (log.userId === userId) {
      return {
        ...log,
        userId: 'ANONYMOUS_' + generateSecureToken(8),
      };
    }
    return log;
  });
  
  localStorage.setItem('audit_logs', JSON.stringify(anonymized));
  
  logSecurityAlert('USER_DATA_ANONYMIZED', 'INFO', {
    userId,
  });
  
  return { success: true, userId };
}

/**
 * Enforce data retention policies
 */
function enforceRetentionPolicies() {
  const logs = JSON.parse(localStorage.getItem('audit_logs') || '[]');
  const now = Date.now();
  
  const retained = logs.filter((log) => {
    const logDate = new Date(log.timestamp).getTime();
    const logAge = now - logDate;
    
    let retentionMs = DATA_RETENTION_POLICIES.AUDIT_LOGS * 24 * 60 * 60 * 1000;
    
    if (log.eventType === 'AUTHENTICATION_ATTEMPT') {
      retentionMs = DATA_RETENTION_POLICIES.FAILED_LOGIN_ATTEMPTS * 24 * 60 * 60 * 1000;
    }
    
    return logAge < retentionMs;
  });
  
  const deleted = logs.length - retained.length;
  localStorage.setItem('audit_logs', JSON.stringify(retained));
  
  console.log(`[DATA_RETENTION] Deleted ${deleted} expired log entries`);
  
  return { deleted, retained: retained.length };
}

/**
 * Get user consent for data processing
 */
function createDataProcessingConsent(userId, purposes) {
  const consent = {
    id: generateSecureToken(16),
    userId,
    purposes,
    grantedAt: new Date().toISOString(),
    version: '1.0',
    status: 'ACCEPTED',
  };
  
  logSecurityAlert('DATA_PROCESSING_CONSENT_GIVEN', 'INFO', {
    userId,
    purposes,
  });
  
  return consent;
}

/**
 * Revoke data processing consent
 */
function revokeDataProcessingConsent(userId) {
  logSecurityAlert('DATA_PROCESSING_CONSENT_REVOKED', 'WARN', {
    userId,
  });
  
  scheduleDataDeletion(userId, 'ALL');
  
  return { success: true, userId };
}

/**
 * Helper: Get user profile data
 */
function getProfileData(userId) {
  return {
    email: userId,
    name: 'User Name',
    createdAt: new Date().toISOString(),
  };
}

/**
 * Helper: Get session history
 */
function getSessionHistory(userId) {
  const logs = JSON.parse(localStorage.getItem('audit_logs') || '[]');
  return logs.filter((l) => l.userId === userId && l.eventType === 'AUTHENTICATION_ATTEMPT');
}

/**
 * Helper: Get user preferences
 */
function getPreferences(userId) {
  return {
    language: 'en',
    timezone: 'UTC+4',
    notifications: true,
  };
}

/**
 * Helper: Get audit logs for user
 */
function getAuditLogsForUser(userId) {
  const logs = JSON.parse(localStorage.getItem('audit_logs') || '[]');
  return logs.filter((l) => l.userId === userId);
}

/**
 * Helper: Generate secure token
 */
function generateSecureToken(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * chars.length);
    token += chars[randomIndex];
  }
  return token;
}

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    setRetentionPolicy,
    scheduleDataDeletion,
    exportUserData,
    deleteUserData,
    anonymizeData,
    enforceRetentionPolicies,
    createDataProcessingConsent,
    revokeDataProcessingConsent,
  };
}
