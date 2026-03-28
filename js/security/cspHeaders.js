/**
 * ROMI NEXUS SECURITY HEADERS MODULE (Vanilla JS)
 * OWASP #5: Security Misconfiguration
 * FCCO Dashboard — no TradingView, private tool
 */

const SECURITY_HEADERS = {
  'Content-Security-Policy': `default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self' https://rominexus-gateway-v6.vacorp-inquiries.workers.dev; img-src 'self' data:; object-src 'none'; frame-ancestors 'none';`,
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
};

function enforceHTTPS() {
  if (typeof window !== 'undefined' && window.location.protocol !== 'https:') {
    if (typeof process !== 'undefined' && process.env && process.env.NODE_ENV === 'production') {
      window.location.replace('https:' + window.location.href.substring(5));
    }
  }
}

function applySecurityHeaders() {
  if (typeof document === 'undefined') return;
  const existing = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  if (!existing) {
    const cspMeta = document.createElement('meta');
    cspMeta.httpEquiv = 'Content-Security-Policy';
    cspMeta.content = SECURITY_HEADERS['Content-Security-Policy'];
    document.head.appendChild(cspMeta);
  }
  console.log('[SECURITY] Content Security Policy applied');
}

function isHTTPSEnforced() {
  if (typeof window === 'undefined') return true;
  return window.location.protocol === 'https:' || (typeof process !== 'undefined' && process.env && process.env.NODE_ENV !== 'production');
}

function disableDangerousFeatures() {
  if (typeof window === 'undefined') return;
  if (typeof process !== 'undefined' && process.env && process.env.NODE_ENV === 'production') {
    const checkDevTools = () => {
      const threshold = 160;
      if (window.outerHeight - window.innerHeight > threshold || window.outerWidth - window.innerWidth > threshold) {
        console.warn('[SECURITY] Developer tools detected');
      }
    };
    setInterval(checkDevTools, 500);
  }
}

function enableSTS() {
  console.log('[SECURITY] HSTS should be enabled by server: Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

function getSecurityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
  };
}

function logSecurityStatus() {
  const status = {
    https: isHTTPSEnforced(),
    csp: typeof document !== 'undefined' && !!document.querySelector('meta[http-equiv="Content-Security-Policy"]'),
    userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : 'N/A',
    timestamp: new Date().toISOString(),
  };
  console.log('[SECURITY] Security Status:', status);
  return status;
}

function preventClickjacking() {
  if (typeof window !== 'undefined' && window.self !== window.top) {
    window.top.location = window.self.location;
  }
}

function initializeSecurityMeasures() {
  enforceHTTPS();
  applySecurityHeaders();
  disableDangerousFeatures();
  preventClickjacking();
  logSecurityStatus();
  console.log('[SECURITY] All security measures initialized');
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { enforceHTTPS, applySecurityHeaders, isHTTPSEnforced, disableDangerousFeatures, enableSTS, getSecurityHeaders, logSecurityStatus, preventClickjacking, initializeSecurityMeasures, SECURITY_HEADERS };
}
