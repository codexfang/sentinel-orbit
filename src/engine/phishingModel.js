/**
 * Sentinel Orbit — Phishing Detection Model
 *
 * Simulates a Random Forest ensemble classifier.
 * Each "tree" is a weighted rule that votes on phishing probability.
 * Final score is a weighted ensemble average with confidence estimation.
 */

// ─── Feature Weights (importance scores from simulated training) ─────────────
const FEATURE_WEIGHTS = {
  hasIPAddress:         { weight: 0.92, label: 'IP-Based Hostname',        category: 'structural' },
  knownMalicious:       { weight: 0.95, label: 'Known Malicious Pattern',  category: 'threat_intel' },
  brandImpersonation:   { weight: 0.88, label: 'Brand Impersonation',      category: 'deception' },
  missingHTTPS:         { weight: 0.72, label: 'Missing HTTPS',            category: 'structural' },
  highTLDRisk:          { weight: 0.78, label: 'High-Risk TLD',            category: 'domain' },
  highEntropy:          { weight: 0.65, label: 'High Domain Entropy',      category: 'domain' },
  excessiveKeywords:    { weight: 0.70, label: 'Suspicious Keywords',      category: 'content' },
  longUrl:              { weight: 0.45, label: 'Abnormal URL Length',      category: 'structural' },
  manySubdomains:       { weight: 0.68, label: 'Excessive Subdomains',     category: 'structural' },
  specialCharAbuse:     { weight: 0.55, label: 'Special Character Abuse',  category: 'structural' },
  atSymbol:             { weight: 0.82, label: '@ Symbol in URL',          category: 'deception' },
  doubleSlash:          { weight: 0.75, label: 'Double-Slash Redirect',    category: 'deception' },
  deepPath:             { weight: 0.38, label: 'Deep URL Path',            category: 'structural' },
  manyQueryParams:      { weight: 0.42, label: 'Excessive Query Params',   category: 'structural' },
  homoglyphs:           { weight: 0.80, label: 'Homoglyph Characters',     category: 'deception' },
  newDomainRisk:        { weight: 0.60, label: 'New/Throwaway Domain',     category: 'domain' },
  knownBenign:          { weight: -0.90, label: 'Trusted Domain',          category: 'threat_intel' },
};

// ─── Decision Tree Ensemble (15 simulated trees) ────────────────────────────
// Each tree evaluates a subset of features and returns [phishingVote, confidence]

function tree1_structuralCheck(f) {
  let score = 0;
  if (f.hasIPAddress) score += 0.85;
  if (f.urlLength > 100) score += 0.35;
  if (f.urlLength > 150) score += 0.25;
  if (f.specialCharCount > 8) score += 0.30;
  if (f.pathDepth > 5) score += 0.20;
  return Math.min(score, 1.0);
}

function tree2_domainEntropy(f) {
  const e = f.domainEntropy;
  if (e > 4.2) return 0.88;
  if (e > 3.8) return 0.72;
  if (e > 3.4) return 0.52;
  if (e > 3.0) return 0.35;
  if (e > 2.5) return 0.18;
  return 0.05;
}

function tree3_tldRisk(f) {
  if (f.tldRiskScore >= 70) return 0.82;
  if (f.tldRiskScore >= 40) return 0.48;
  if (f.tldRiskScore >= 25) return 0.22;
  return 0.05;
}

function tree4_keywordDensity(f) {
  const k = f.keywordCount;
  if (k >= 5) return 0.90;
  if (k >= 3) return 0.70;
  if (k >= 2) return 0.50;
  if (k >= 1) return 0.28;
  return 0.04;
}

function tree5_deceptionPatterns(f) {
  let score = 0;
  if (f.hasAtSymbol) score += 0.72;
  if (f.hasDoubleSlash) score += 0.60;
  if (f.homoglyphs?.detected) score += 0.65;
  return Math.min(score, 1.0);
}

function tree6_brandImpersonation(f) {
  if (!f.brandImpersonation?.detected) return 0.05;
  const brands = f.brandImpersonation.brands || [];
  if (brands.length >= 2) return 0.95;
  return 0.85;
}

function tree7_httpsAndIP(f) {
  let score = 0;
  if (f.hasIPAddress) score += 0.80;
  if (!f.hasHTTPS) score += 0.45;
  if (f.hasIPAddress && !f.hasHTTPS) score += 0.15; // compound penalty
  return Math.min(score, 1.0);
}

function tree8_subdomainAbuse(f) {
  const s = f.subdomainCount;
  if (s >= 4) return 0.85;
  if (s >= 3) return 0.65;
  if (s >= 2) return 0.40;
  if (s >= 1) return 0.18;
  return 0.05;
}

function tree9_threatIntel(f) {
  if (f.knownMalicious) return 0.97;
  if (f.knownBenign) return 0.02;
  return 0.30;
}

function tree10_whoisAge(f) {
  const risk = f.whoisRisk?.riskScore || 0;
  if (risk >= 35) return 0.75;
  if (risk >= 15) return 0.40;
  return 0.08;
}

function tree11_queryComplexity(f) {
  let score = 0;
  if (f.queryParamCount > 6) score += 0.45;
  if (f.queryParamCount > 3) score += 0.20;
  if (f.specialCharCount > 5 && f.queryParamCount > 2) score += 0.25;
  return Math.min(score, 1.0);
}

function tree12_compoundSignals(f) {
  // Detects combinations that individually seem minor but together are alarming
  let flags = 0;
  if (!f.hasHTTPS) flags++;
  if (f.keywordCount >= 2) flags++;
  if (f.subdomainCount >= 2) flags++;
  if (f.domainEntropy > 3.0) flags++;
  if (f.tldRiskScore >= 40) flags++;
  if (f.urlLength > 75) flags++;
  if (flags >= 5) return 0.92;
  if (flags >= 4) return 0.78;
  if (flags >= 3) return 0.58;
  if (flags >= 2) return 0.32;
  return 0.08;
}

function tree13_protocolAnomaly(f) {
  if (f.hasIPAddress && !f.hasHTTPS) return 0.90;
  if (f.hasAtSymbol && !f.hasHTTPS) return 0.85;
  if (!f.hasHTTPS && f.keywordCount >= 2) return 0.65;
  if (!f.hasHTTPS) return 0.30;
  return 0.05;
}

function tree14_pathAnalysis(f) {
  let score = 0;
  if (f.pathDepth > 7) score += 0.40;
  if (f.pathDepth > 4) score += 0.20;
  // Simulate checking for redirect-style paths
  const suspiciousPaths = ['verify', 'confirm', 'update', 'secure', 'login', 'signin', 'reset'];
  const rawLower = (f.rawUrl || '').toLowerCase();
  const pathHits = suspiciousPaths.filter(p => rawLower.includes('/' + p)).length;
  score += pathHits * 0.12;
  return Math.min(score, 1.0);
}

function tree15_benignOverride(f) {
  // Strong benign override — if known trusted domain, strongly pull score down
  if (f.knownBenign) return 0.01;
  if (!f.hasIPAddress && !f.brandImpersonation?.detected && f.keywordCount === 0
      && f.tldRiskScore <= 5 && f.hasHTTPS && f.domainEntropy < 2.8) {
    return 0.04;
  }
  return 0.50; // neutral
}

// ─── Ensemble Voting ─────────────────────────────────────────────────────────

const TREES = [
  { fn: tree1_structuralCheck,    weight: 1.2 },
  { fn: tree2_domainEntropy,      weight: 1.4 },
  { fn: tree3_tldRisk,            weight: 1.3 },
  { fn: tree4_keywordDensity,     weight: 1.1 },
  { fn: tree5_deceptionPatterns,  weight: 1.5 },
  { fn: tree6_brandImpersonation, weight: 1.6 },
  { fn: tree7_httpsAndIP,         weight: 1.3 },
  { fn: tree8_subdomainAbuse,     weight: 1.0 },
  { fn: tree9_threatIntel,        weight: 1.8 },
  { fn: tree10_whoisAge,          weight: 0.9 },
  { fn: tree11_queryComplexity,   weight: 0.8 },
  { fn: tree12_compoundSignals,   weight: 1.4 },
  { fn: tree13_protocolAnomaly,   weight: 1.2 },
  { fn: tree14_pathAnalysis,      weight: 0.9 },
  { fn: tree15_benignOverride,    weight: 1.7 },
];

const TOTAL_WEIGHT = TREES.reduce((s, t) => s + t.weight, 0);

// ─── Feature Signal Scoring (for per-feature breakdown bar chart) ────────────

function computeFeatureSignals(features) {
  return [
    {
      name: 'IP Hostname',
      score: features.hasIPAddress ? 95 : 2,
      active: features.hasIPAddress,
      weight: FEATURE_WEIGHTS.hasIPAddress.weight,
      category: 'structural',
    },
    {
      name: 'HTTPS Missing',
      score: features.hasHTTPS ? 2 : 65,
      active: !features.hasHTTPS,
      weight: FEATURE_WEIGHTS.missingHTTPS.weight,
      category: 'structural',
    },
    {
      name: 'Domain Entropy',
      score: Math.min(100, Math.round((features.domainEntropy / 5.0) * 100)),
      active: features.domainEntropy > 3.0,
      weight: FEATURE_WEIGHTS.highEntropy.weight,
      category: 'domain',
    },
    {
      name: 'TLD Risk',
      score: features.tldRiskScore,
      active: features.tldRiskScore >= 40,
      weight: FEATURE_WEIGHTS.highTLDRisk.weight,
      category: 'domain',
    },
    {
      name: 'Suspicious Keywords',
      score: Math.min(100, features.keywordCount * 18),
      active: features.keywordCount > 0,
      weight: FEATURE_WEIGHTS.excessiveKeywords.weight,
      category: 'content',
    },
    {
      name: 'Brand Impersonation',
      score: features.brandImpersonation?.detected ? 90 : 3,
      active: features.brandImpersonation?.detected,
      weight: FEATURE_WEIGHTS.brandImpersonation.weight,
      category: 'deception',
    },
    {
      name: 'Subdomain Depth',
      score: Math.min(100, features.subdomainCount * 22),
      active: features.subdomainCount >= 2,
      weight: FEATURE_WEIGHTS.manySubdomains.weight,
      category: 'structural',
    },
    {
      name: 'URL Length',
      score: Math.min(100, Math.round((features.urlLength / 200) * 100)),
      active: features.urlLength > 75,
      weight: FEATURE_WEIGHTS.longUrl.weight,
      category: 'structural',
    },
    {
      name: 'Deception Chars',
      score: features.hasAtSymbol || features.hasDoubleSlash ? 80 : Math.min(40, features.specialCharCount * 5),
      active: features.hasAtSymbol || features.hasDoubleSlash || features.specialCharCount > 6,
      weight: FEATURE_WEIGHTS.atSymbol.weight,
      category: 'deception',
    },
    {
      name: 'Homoglyphs',
      score: features.homoglyphs?.detected ? 82 : 2,
      active: features.homoglyphs?.detected,
      weight: FEATURE_WEIGHTS.homoglyphs.weight,
      category: 'deception',
    },
  ];
}

// ─── Risk Category Classification ────────────────────────────────────────────

function classifyRisk(probability) {
  if (probability >= 80) return { level: 'Critical', color: '#ef4444', glow: '#ef444460' };
  if (probability >= 60) return { level: 'High',     color: '#f97316', glow: '#f9731660' };
  if (probability >= 35) return { level: 'Medium',   color: '#eab308', glow: '#eab30860' };
  return                        { level: 'Low',       color: '#22c55e', glow: '#22c55e60' };
}

// ─── Analyst Explanation Generator ───────────────────────────────────────────

function generateExplanation(features, signals, probability, risk) {
  const topSignals = signals.filter(s => s.active).sort((a, b) => b.score - a.score);
  const lines = [];

  if (features.knownBenign) {
    lines.push(`The domain "${features.hostname}" matches a known trusted provider in Sentinel Orbit's intelligence database. Risk indicators are minimal.`);
  } else if (features.knownMalicious) {
    lines.push(`⚠ This hostname contains patterns matching known malicious domains in our threat intelligence database. Treat with extreme caution.`);
  }

  if (features.hasIPAddress) {
    lines.push(`The URL uses a raw IP address (${features.hostname}) as its hostname — a hallmark of phishing infrastructure designed to bypass domain reputation checks.`);
  }

  if (features.brandImpersonation?.detected) {
    const brands = features.brandImpersonation.brands.join(', ');
    lines.push(`Brand impersonation detected: references to "${brands}" appear in the subdomain structure while the base domain differs — a classic credential-harvesting technique.`);
  }

  if (!features.hasHTTPS) {
    lines.push(`The URL uses plain HTTP, meaning any submitted credentials would be transmitted unencrypted. Legitimate services requiring authentication always use HTTPS.`);
  }

  if (features.keywordCount > 0) {
    lines.push(`Found ${features.keywordCount} suspicious keyword(s) in the URL: [${features.foundKeywords.slice(0, 5).join(', ')}]. These terms are commonly used to lure victims into social engineering attacks.`);
  }

  if (features.domainEntropy > 3.4) {
    lines.push(`Domain entropy of ${features.domainEntropy.toFixed(2)} bits indicates a high degree of character randomness — consistent with algorithmically-generated (DGA) or throwaway domains used in phishing campaigns.`);
  }

  if (features.tldRiskScore >= 70) {
    lines.push(`The ".${features.tld}" TLD carries an elevated risk rating. This top-level domain is frequently registered for malicious purposes due to low cost and minimal verification requirements.`);
  }

  if (features.subdomainCount >= 2) {
    lines.push(`${features.subdomainCount} nested subdomains were detected. Attackers use deep subdomain structures to visually bury the true base domain and confuse victims.`);
  }

  if (features.hasAtSymbol) {
    lines.push(`An "@" symbol was found in the URL path. Browsers historically interpret everything before "@" as credentials, allowing attackers to disguise the true destination URL.`);
  }

  if (features.homoglyphs?.detected) {
    lines.push(`Homoglyph substitution detected — characters designed to visually resemble legitimate domains. This typosquatting technique exploits visual similarity to deceive users.`);
  }

  if (lines.length === 0) {
    lines.push(`No significant threat indicators were found in this URL. The domain appears to use standard structure, HTTPS encryption, and contains no known suspicious patterns.`);
  }

  // Closing verdict
  if (probability >= 80) {
    lines.push(`VERDICT: This URL exhibits multiple hallmarks of an active phishing attack. Do not enter credentials or personal information. Report to your security team immediately.`);
  } else if (probability >= 60) {
    lines.push(`VERDICT: Several high-confidence threat signals detected. Exercise extreme caution. Verify the domain via official channels before proceeding.`);
  } else if (probability >= 35) {
    lines.push(`VERDICT: This URL contains ambiguous signals warranting caution. Not definitively malicious, but proceed with awareness and avoid submitting sensitive data.`);
  } else {
    lines.push(`VERDICT: URL appears legitimate based on available signals. Standard security hygiene still applies — verify the domain if in doubt.`);
  }

  return lines;
}

// ─── Timeline Reasoning Steps ─────────────────────────────────────────────────

function generateTimeline(features, signals) {
  const steps = [
    {
      step: 'URL Parsing',
      detail: `Protocol: ${features.protocol} · Hostname: ${features.hostname} · Path depth: ${features.pathDepth}`,
      status: 'complete',
    },
    {
      step: 'Domain Intelligence Lookup',
      detail: features.knownBenign
        ? `✓ Matched trusted domain registry`
        : features.knownMalicious
        ? `✗ Matched known malicious pattern`
        : `Domain not in reputation database — applying heuristic scoring`,
      status: features.knownMalicious ? 'alert' : 'complete',
    },
    {
      step: 'TLD Risk Assessment',
      detail: `TLD ".${features.tld}" scored ${features.tldRiskScore}/100 risk`,
      status: features.tldRiskScore >= 60 ? 'alert' : 'complete',
    },
    {
      step: 'Entropy Analysis',
      detail: `Shannon entropy: ${features.domainEntropy.toFixed(3)} bits — ${features.domainEntropy > 3.5 ? 'HIGH (possible DGA domain)' : features.domainEntropy > 2.8 ? 'MODERATE' : 'NORMAL'}`,
      status: features.domainEntropy > 3.5 ? 'alert' : 'complete',
    },
    {
      step: 'Keyword & Pattern Scan',
      detail: features.keywordCount > 0
        ? `Detected ${features.keywordCount} suspicious term(s): ${features.foundKeywords.slice(0, 4).join(', ')}`
        : 'No suspicious keywords found',
      status: features.keywordCount >= 2 ? 'alert' : 'complete',
    },
    {
      step: 'Structural Anomaly Check',
      detail: [
        features.hasIPAddress && 'IP address hostname',
        features.hasAtSymbol && '@ symbol in path',
        features.hasDoubleSlash && 'double-slash redirect',
        features.homoglyphs?.detected && 'homoglyph substitution',
        features.subdomainCount >= 2 && `${features.subdomainCount} subdomain levels`,
      ].filter(Boolean).join(' · ') || 'No structural anomalies',
      status: (features.hasIPAddress || features.hasAtSymbol || features.homoglyphs?.detected) ? 'alert' : 'complete',
    },
    {
      step: 'Brand Impersonation Analysis',
      detail: features.brandImpersonation?.detected
        ? `⚠ Impersonating: ${features.brandImpersonation.brands.join(', ')}`
        : 'No brand impersonation detected',
      status: features.brandImpersonation?.detected ? 'alert' : 'complete',
    },
    {
      step: 'Ensemble Model Inference',
      detail: 'Aggregating 15-tree weighted vote across all feature signals',
      status: 'complete',
    },
  ];
  return steps;
}

// ─── Main Model Export ────────────────────────────────────────────────────────

export function runPhishingModel(features) {
  // Run all trees and compute weighted ensemble score
  const votes = TREES.map(({ fn, weight }) => ({
    vote: fn(features),
    weight,
  }));

  const weightedSum = votes.reduce((acc, { vote, weight }) => acc + vote * weight, 0);
  const rawProbability = weightedSum / TOTAL_WEIGHT;

  // Apply benign override clamp: if known benign, cap at 15%
  let probability = rawProbability * 100;
  if (features.knownBenign && probability > 15) probability = Math.min(probability, 12);

  // Apply malicious boost: if known malicious, floor at 85%
  if (features.knownMalicious && probability < 85) probability = Math.max(probability, 88);

  // Clamp to 0–100
  probability = Math.round(Math.max(0, Math.min(100, probability)));

  // Confidence: based on vote agreement (lower variance = higher confidence)
  const meanVote = votes.reduce((s, v) => s + v.vote, 0) / votes.length;
  const variance = votes.reduce((s, v) => s + Math.pow(v.vote - meanVote, 2), 0) / votes.length;
  const confidence = Math.round(Math.max(55, Math.min(99, (1 - variance) * 100)));

  const risk = classifyRisk(probability);
  const featureSignals = computeFeatureSignals(features);
  const explanationLines = generateExplanation(features, featureSignals, probability, risk);
  const timeline = generateTimeline(features, featureSignals);

  return {
    probability,
    confidence,
    risk,
    featureSignals,
    explanationLines,
    timeline,
    activeSignals: featureSignals.filter(s => s.active),
    treeVotes: votes.map((v, i) => ({ tree: i + 1, vote: Math.round(v.vote * 100) })),
  };
}
