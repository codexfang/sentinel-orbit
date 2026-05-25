/**
 * Sentinel Orbit — URL Feature Extraction Engine
 * Extracts structural, domain, and content-based signals from a URL
 */

import domainRiskDB from '../data/domainRiskDB.json';

const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'bank', 'secure', 'update', 'account',
  'password', 'confirm', 'signin', 'validate', 'billing',
  'payment', 'paypal', 'apple', 'microsoft', 'amazon', 'google',
  'support', 'help', 'recover', 'reset', 'unlock', 'suspended',
  'urgent', 'alert', 'notice', 'claim', 'free', 'bonus', 'gift',
  'winner', 'won', 'prize', 'limited', 'offer', 'deal'
];

const IP_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;
const DATA_URI_REGEX = /^data:/i;

/**
 * Calculate Shannon entropy of a string
 * High entropy indicates randomized/obfuscated domains
 */
function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(4));
}

/**
 * Parse URL safely, returning null if invalid
 */
function parseUrlSafe(rawUrl) {
  try {
    // Prepend protocol if missing
    const url = rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`;
    return new URL(url);
  } catch {
    return null;
  }
}

/**
 * Extract TLD from hostname
 */
function extractTLD(hostname) {
  const parts = hostname.split('.');
  return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : '';
}

/**
 * Get base domain (last two parts of hostname, excluding IP)
 */
function getBaseDomain(hostname) {
  if (IP_REGEX.test(hostname)) return hostname;
  const parts = hostname.split('.');
  return parts.length >= 2
    ? parts.slice(parts.length - 2).join('.')
    : hostname;
}

/**
 * Count subdomains in a hostname
 */
function countSubdomains(hostname) {
  if (IP_REGEX.test(hostname)) return 0;
  const parts = hostname.split('.');
  return Math.max(0, parts.length - 2);
}

/**
 * Compute TLD risk score (0–100)
 */
function getTLDRisk(tld) {
  if (domainRiskDB.highRisk.includes(tld)) return 70;
  if (domainRiskDB.mediumRisk.includes(tld)) return 25;
  if (domainRiskDB.lowRisk.includes(tld)) return 5;
  return 40; // Unknown TLD = elevated risk
}

/**
 * Check if hostname is a known benign domain
 */
function isKnownBenign(hostname, baseDomain) {
  return domainRiskDB.knownBenign.some(
    (d) => hostname === d || hostname.endsWith(`.${d}`) || baseDomain === d
  );
}

/**
 * Check if any known malicious pattern appears in the hostname
 */
function isKnownMalicious(hostname) {
  return domainRiskDB.knownMalicious.some((d) =>
    hostname.includes(d.split('.')[0])
  );
}

/**
 * Extract suspicious keywords found in the full URL
 */
function detectSuspiciousKeywords(urlString) {
  const lower = urlString.toLowerCase();
  return SUSPICIOUS_KEYWORDS.filter((kw) => lower.includes(kw));
}

/**
 * Count special characters in URL path + query
 */
function countSpecialChars(str) {
  const specials = str.match(/[=&%@!$^*{}|\\<>[\]]/g) || [];
  return specials.length;
}

/**
 * Detect lookalike domain tactics (e.g. "paypa1", "g00gle")
 */
function detectHomoglyphs(hostname) {
  const patterns = [
    /[0-9](?=[a-z])|[a-z](?=[0-9])/i,  // alphanumeric mixing
    /(.)\1{3,}/,                          // repeated chars
  ];
  const score = patterns.reduce((acc, p) => acc + (p.test(hostname) ? 1 : 0), 0);
  return { detected: score > 0, count: score };
}

/**
 * Check for @ symbol in URL (common phishing trick)
 */
function hasAtSymbol(urlString) {
  const urlPart = urlString.split('?')[0];
  return urlPart.includes('@');
}

/**
 * Check for double slash redirect tricks
 */
function hasDoubleSlashRedirect(urlString) {
  return /https?:\/\/.*\/\//.test(urlString);
}

/**
 * Detect brand impersonation: known brand in subdomain but different base
 */
function detectBrandImpersonation(hostname, baseDomain) {
  const brands = [
    'paypal', 'apple', 'microsoft', 'amazon', 'google',
    'facebook', 'instagram', 'netflix', 'steam', 'dropbox',
    'linkedin', 'twitter', 'youtube', 'github'
  ];
  const matchedBrands = brands.filter((b) => {
    const inHostname = hostname.includes(b);
    const inBase = baseDomain.includes(b);
    return inHostname && !inBase;
  });
  return { detected: matchedBrands.length > 0, brands: matchedBrands };
}

/**
 * Simulated WHOIS risk: use URL entropy as pseudo-age signal
 * (Real WHOIS would require a backend; this simulates it deterministically)
 */
function simulateWhoisRisk(hostname) {
  // Use entropy and character patterns as a proxy for domain age
  const entropy = calculateEntropy(hostname);
  const tld = extractTLD(hostname);
  const isHighRiskTLD = domainRiskDB.highRisk.includes(tld);

  // Simulate: high entropy + risky TLD → likely new/throwaway domain
  if (entropy > 3.5 && isHighRiskTLD) {
    return { estimatedAgeDays: 12, riskScore: 35, confidence: 'simulated' };
  } else if (entropy > 3.0 || isHighRiskTLD) {
    return { estimatedAgeDays: 90, riskScore: 15, confidence: 'simulated' };
  } else {
    return { estimatedAgeDays: 730, riskScore: 0, confidence: 'simulated' };
  }
}

/**
 * Main extraction function — extracts all features from a URL string
 */
export async function analyzeUrl(rawUrl) {
  const trimmed = rawUrl.trim();
  const parsed = parseUrlSafe(trimmed);

  if (!parsed) {
    throw new Error('Invalid URL format. Please enter a valid URL (e.g. https://example.com).');
  }

  const hostname = parsed.hostname.toLowerCase();
  const baseDomain = getBaseDomain(hostname);
  const tld = extractTLD(hostname);
  const fullUrl = parsed.href;
  const pathAndQuery = parsed.pathname + parsed.search;

  // --- Structural Features ---
  const urlLength = fullUrl.length;
  const subdomainCount = countSubdomains(hostname);
  const hasIPAddress = IP_REGEX.test(hostname);
  const specialCharCount = countSpecialChars(pathAndQuery);
  const foundKeywords = detectSuspiciousKeywords(fullUrl);
  const hasHTTPS = parsed.protocol === 'https:';
  const hasAtSymbolFlag = hasAtSymbol(fullUrl);
  const hasDoubleSlash = hasDoubleSlashRedirect(fullUrl);
  const pathDepth = parsed.pathname.split('/').filter(Boolean).length;
  const queryParamCount = [...parsed.searchParams].length;
  const domainEntropy = calculateEntropy(hostname);
  const homoglyphs = detectHomoglyphs(hostname);
  const brandImpersonation = detectBrandImpersonation(hostname, baseDomain);
  const knownBenign = isKnownBenign(hostname, baseDomain);
  const knownMalicious = isKnownMalicious(hostname);

  // --- Domain Risk ---
  const tldRiskScore = getTLDRisk(tld);
  const whoisRisk = simulateWhoisRisk(hostname);

  // --- Fetch-based HTML Analysis (best-effort, CORS-limited) ---
  let htmlSignals = {
    attempted: false,
    success: false,
    passwordInputCount: 0,
    externalLinkCount: 0,
    formCount: 0,
    titleSuspicious: false,
    titleText: null,
    error: null
  };

  // Only attempt fetch for same-origin or CORS-permissive pages
  // In production (GitHub Pages), this will typically fail due to CORS
  try {
    htmlSignals.attempted = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const response = await fetch(fullUrl, {
      signal: controller.signal,
      mode: 'no-cors'
    });
    clearTimeout(timeout);

    // With no-cors we can't read the body, so we mark success as opaque
    htmlSignals.success = false;
    htmlSignals.error = 'CORS restricted — HTML analysis unavailable for external URLs';
  } catch (err) {
    htmlSignals.error = err.name === 'AbortError'
      ? 'Request timed out'
      : 'Network error — HTML analysis skipped';
  }

  return {
    // Metadata
    rawUrl: trimmed,
    parsedUrl: fullUrl,
    hostname,
    baseDomain,
    tld,
    protocol: parsed.protocol,
    timestamp: new Date().toISOString(),

    // Structural
    urlLength,
    subdomainCount,
    hasIPAddress,
    specialCharCount,
    pathDepth,
    queryParamCount,
    hasHTTPS,
    hasAtSymbol: hasAtSymbolFlag,
    hasDoubleSlash,

    // Keyword & Pattern
    foundKeywords,
    keywordCount: foundKeywords.length,
    homoglyphs,
    brandImpersonation,

    // Domain Risk
    domainEntropy,
    tldRiskScore,
    tld,
    knownBenign,
    knownMalicious,

    // WHOIS (simulated)
    whoisRisk,

    // HTML Signals
    htmlSignals
  };
}
