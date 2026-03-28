/**
 * ROMI NEXUS SECURITY MODULE — BARREL EXPORTS
 * ISSUE-11: Session Token & Security Hardening
 * FCCO Dashboard
 */

// Note: This project uses vanilla JS (non-module scripts loaded via <script> tags)
// Functions are globally available after loading individual security files.
// This index serves as documentation of all exported security functions.

/*
  From encryption.js:      encryptData, decryptData, encryptSessionToken, decryptSessionToken, generateSecureToken, hashValue
  From inputValidator.js:  validateEmail, validateOTP, validatePhoneNumber, validateCommodity, validateVolume, validatePrice, sanitizeInput, escapeHTML, validateURL, validateJSON, checkRateLimit
  From auditLogger.js:     logAuthenticationAttempt, logAPICall, logDataAccess, logSecurityAlert, exportAuditLogs, cleanupOldLogs, enableSIEM, getAuditSummary
  From amlKyc.js:          performKYCCheck, checkSanctionsList, monitorTransaction, detectSuspiciousActivity, generateAMLReport, reportSuspiciousTransaction
  From dataRetention.js:   setRetentionPolicy, scheduleDataDeletion, exportUserData, deleteUserData, anonymizeData, enforceRetentionPolicies, createDataProcessingConsent, revokeDataProcessingConsent
  From cspHeaders.js:      enforceHTTPS, applySecurityHeaders, isHTTPSEnforced, disableDangerousFeatures, enableSTS, getSecurityHeaders, logSecurityStatus, preventClickjacking, initializeSecurityMeasures, SECURITY_HEADERS
*/
