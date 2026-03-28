/**
 * ROMI NEXUS AML/KYC COMPLIANCE MODULE (Vanilla JS)
 * DIFC Requirement: Anti-Money Laundering & Know Your Customer
 */

const AML_CONFIG = {
  kycApiEndpoint: 'https://api.rominexus.com/kyc/verify',
  sanctionListEndpoint: 'https://api.rominexus.com/sanctions/check',
  transactionThreshold: 10000,
};

async function performKYCCheck(userEmail, kycData) {
  if (!kycData || !kycData.fullName || !kycData.documentId) {
    return { passed: false, reason: 'Incomplete KYC data provided' };
  }
  try {
    const token = typeof getSessionToken === 'function' ? getSessionToken() : 'UNKNOWN';
    const response = await fetch(AML_CONFIG.kycApiEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify({ email: userEmail, fullName: kycData.fullName, documentType: kycData.documentType, documentId: kycData.documentId, dateOfBirth: kycData.dateOfBirth }),
    });
    if (!response.ok) throw new Error(`KYC verification failed: ${response.statusText}`);
    const result = await response.json();
    if (typeof logSecurityAlert === 'function') logSecurityAlert('KYC_VERIFICATION', 'INFO', { email: userEmail, result: result.passed ? 'PASSED' : 'FAILED', reason: result.reason });
    return result;
  } catch (error) {
    console.error('[ERROR] KYC check failed:', error);
    return { passed: false, reason: 'KYC verification service unavailable' };
  }
}

async function checkSanctionsList(customerName) {
  try {
    const response = await fetch(AML_CONFIG.sanctionListEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: customerName }),
    });
    if (!response.ok) throw new Error('Sanctions check failed');
    const result = await response.json();
    if (result.isSanctioned && typeof logSecurityAlert === 'function') logSecurityAlert('SANCTIONS_HIT', 'CRITICAL', { customerName, reason: result.reason });
    return result.isSanctioned;
  } catch (error) {
    console.error('[ERROR] Sanctions check failed:', error);
    return true;
  }
}

async function monitorTransaction(transaction) {
  const riskScore = calculateTransactionRisk(transaction);
  if (riskScore >= 75) {
    if (typeof logSecurityAlert === 'function') logSecurityAlert('SUSPICIOUS_TRANSACTION', 'HIGH', { transactionId: transaction.id, riskScore, details: transaction });
    return { flagged: true, riskScore };
  }
  return { flagged: false, riskScore };
}

function calculateTransactionRisk(transaction) {
  let riskScore = 0;
  if (transaction.amount > AML_CONFIG.transactionThreshold) riskScore += 25;
  if (transaction.destination && isHighRiskJurisdiction(transaction.destination)) riskScore += 30;
  if (transaction.consecutiveCount > 5) riskScore += 20;
  if (transaction.customerAge < 30) riskScore += 10;
  return Math.min(riskScore, 100);
}

function isHighRiskJurisdiction(jurisdiction) {
  const highRiskList = ['KP', 'IR', 'SY', 'CU'];
  return highRiskList.includes(jurisdiction?.toUpperCase());
}

function detectSuspiciousActivity(userActivity) {
  const indicators = [];
  if (userActivity.transactionAmount > userActivity.averageTransaction * 5) indicators.push('UNUSUAL_AMOUNT');
  if (userActivity.failedLogins > 3) indicators.push('FAILED_LOGINS');
  if (userActivity.unusualLocation) indicators.push('UNUSUAL_LOCATION');
  return { suspicious: indicators.length > 0, indicators };
}

function generateAMLReport(startDate, endDate) {
  const logs = JSON.parse(localStorage.getItem('audit_logs') || '[]');
  const amlLogs = logs.filter((log) => {
    const logDate = new Date(log.timestamp);
    return ['KYC_VERIFICATION', 'SANCTIONS_HIT', 'SUSPICIOUS_TRANSACTION'].includes(log.eventType) && logDate >= startDate && logDate <= endDate;
  });
  return {
    reportDate: new Date().toISOString(), period: { startDate, endDate },
    kycVerifications: amlLogs.filter((l) => l.eventType === 'KYC_VERIFICATION').length,
    sanctionsHits: amlLogs.filter((l) => l.eventType === 'SANCTIONS_HIT').length,
    suspiciousTransactions: amlLogs.filter((l) => l.eventType === 'SUSPICIOUS_TRANSACTION').length,
    details: amlLogs,
  };
}

async function reportSuspiciousTransaction(transactionId, reason) {
  const report = {
    transactionId, reason,
    reportedAt: new Date().toISOString(),
    reportedBy: typeof getSessionEmail === 'function' ? getSessionEmail() : 'SYSTEM',
  };
  if (typeof logSecurityAlert === 'function') logSecurityAlert('SUSPICIOUS_TRANSACTION_REPORTED', 'CRITICAL', report);
  return report;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { performKYCCheck, checkSanctionsList, monitorTransaction, detectSuspiciousActivity, generateAMLReport, reportSuspiciousTransaction };
}
