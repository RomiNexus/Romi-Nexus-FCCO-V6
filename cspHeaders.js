/**
 * ROMI NEXUS SECURITY HEADERS MODULE (Vanilla JS)
 * OWASP #5: Security Misconfiguration
 */

const SECURITY_HEADERS = {
  'Content-Security-Policy': `
    default-src 'self';
    script-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com;
    style-src 'self' https://fonts.googleapis.com 'unsafe-inline';
    font-src https://fonts.gstatic.com;
    connect-src 'self' https://rominexus-gateway-v6.vacorp-inquiries.workers.dev;
    img-src 'self' data:;
    object-src 'none';
    frame-ancestors 'none';
  `.trim(),
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
};

/**
 * Enforce HTTPS
 */
function enforceHTTPS() {
  if (typeof window !== 'undefined' && window.location.protocol !== 'https:') {
    if (typeof process !== 'undefined' && process.env.NODE_ENV === 'production') {
      window.location.replace('https:' + window.location.href.substring(5));
    }
  }
}

/**
 * Apply security headers (client-side)
 */
function applySecurityHeaders() {
  if (typeof document === 'undefined') return;
  
  // Add CSP meta tag
  const cspMeta = document.createElement('meta');
  cspMeta.httpEquiv = 'Content-Security-Policy';
  cspMeta.content = SECURITY_HEADERS['Content-Security-Policy'];
  document.head.appendChild(cspMeta);
  
  console.log('[SECURITY] Content Security Policy applied');
}

/**
 * Check if HTTPS is enforced
 */
function isHTTPSEnforced() {
  if (typeof window === 'undefined') return true;
  
  return window.location.protocol === 'https:' || 
    (typeof process !== 'undefined' && process.env.NODE_ENV !== 'production');
}

/**
 * Disable dangerous browser features
 */
function disableDangerousFeatures() {
  if (typeof window === 'undefined') return;
  
  // Detect dev tools in production
  if (typeof process !== 'undefined' && process.env.NODE_ENV === 'production') {
    const checkDevTools = () => {
      const threshold = 160;
      if (window.outerHeight - window.innerHeight > threshold ||
          window.outerWidth - window.innerWidth > threshold) {
        console.warn('[SECURITY] Developer tools detected');
      }
    };
    setInterval(checkDevTools, 500);
  }
}

/**
 * Set Strict Transport Security (client awareness)
 */
function enableSTS() {
  console.log('[SECURITY] HSTS should be enabled by server');
  // Server must set: Strict-Transport-Security: max-age=31536000; includeSubDomains
}

/**
 * Add security headers to fetch requests
 */
function getSecurityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
  };
}

/**
 * Log security header status
 */
function logSecurityStatus() {
  const status = {
    https: isHTTPSEnforced(),
    csp: !!document.querySelector('meta[http-equiv="Content-Security-Policy"]'),
    userAgent: navigator.userAgent,
    timestamp: new Date().toISOString(),
  };
  
  console.log('[SECURITY] Security Status:', status);
  return status;
}

/**
 * Check for iframe embedding (clickjacking prevention)
 */
function preventClickjacking() {
  if (typeof window !== 'undefined' && window.self !== window.top) {
    window.top.location = window.self.location;
  }
}

/**
 * Initialize all security measures
 */
function initializeSecurityMeasures() {
  enforceHTTPS();
  applySecurityHeaders();
  disableDangerousFeatures();
  preventClickjacking();
  logSecurityStatus();
  
  console.log('[SECURITY] All security measures initialized');
}

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    enforceHTTPS,
    applySecurityHeaders,
    isHTTPSEnforced,
    disableDangerousFeatures,
    enableSTS,
    getSecurityHeaders,
    logSecurityStatus,
    preventClickjacking,
    initializeSecurityMeasures,
    SECURITY_HEADERS,
  };
}
