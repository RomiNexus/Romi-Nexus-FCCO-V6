/**
 * ROMI NEXUS INPUT VALIDATION MODULE (Vanilla JS)
 * ISSUE-11: Injection Prevention (OWASP #3)
 * XSS Prevention (OWASP #1)
 */

/**
 * Validate email format
 */
function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
}

/**
 * Validate OTP (6 digits)
 */
function validateOTP(otp) {
  return /^\d{6}$/.test(otp);
}

/**
 * Validate phone number (international format)
 */
function validatePhoneNumber(phone) {
  return /^\+?[1-9]\d{1,14}$/.test(phone);
}

/**
 * Validate commodity name (alphanumeric + spaces)
 */
function validateCommodity(commodity) {
  return /^[a-zA-Z0-9\s]{1,100}$/.test(commodity);
}

/**
 * Validate volume (numeric, positive)
 */
function validateVolume(volume) {
  const num = parseFloat(volume);
  return !isNaN(num) && num > 0 && num <= 999999999;
}

/**
 * Validate price (numeric, positive, max 2 decimals)
 */
function validatePrice(price) {
  const num = parseFloat(price);
  return !isNaN(num) && num > 0 && /^\d+(\.\d{1,2})?$/.test(price);
}

/**
 * Sanitize string input (remove dangerous characters)
 */
function sanitizeInput(userInput) {
  if (typeof userInput !== 'string') {
    return '';
  }

  let sanitized = userInput
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/on\w+\s*=\s*"[^"]*"/gi, '')
    .replace(/on\w+\s*=\s*'[^']*'/gi, '')
    .trim();

  return sanitized;
}

/**
 * Escape HTML special characters
 */
function escapeHTML(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };
  return text.replace(/[&<>"']/g, (char) => map[char]);
}

/**
 * Validate URL (prevent SSRF)
 */
function validateURL(url) {
  try {
    const parsedUrl = new URL(url);
    
    const allowedProtocols = ['https:', 'http:'];
    if (!allowedProtocols.includes(parsedUrl.protocol)) {
      return false;
    }
    
    const blockedHosts = ['localhost', '127.0.0.1', '0.0.0.0'];
    if (blockedHosts.includes(parsedUrl.hostname)) {
      return false;
    }
    
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Validate JSON structure
 */
function validateJSON(jsonString) {
  try {
    JSON.parse(jsonString);
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Rate limiting check (client-side warning)
 */
const rateLimitStore = {};

function checkRateLimit(key, limit = 5, windowMs = 60000) {
  const now = Date.now();
  
  if (!rateLimitStore[key]) {
    rateLimitStore[key] = [];
  }
  
  rateLimitStore[key] = rateLimitStore[key].filter(
    (timestamp) => now - timestamp < windowMs
  );
  
  if (rateLimitStore[key].length >= limit) {
    return false;
  }
  
  rateLimitStore[key].push(now);
  return true;
}

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    validateEmail,
    validateOTP,
    validatePhoneNumber,
    validateCommodity,
    validateVolume,
    validatePrice,
    sanitizeInput,
    escapeHTML,
    validateURL,
    validateJSON,
    checkRateLimit,
  };
}
