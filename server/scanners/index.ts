/**
 * Main Security Scanner Orchestrator
 * Coordinates all scanning modules and generates final report
 *
 * Enhanced with:
 * - Active vulnerability scanning (SQLi, XSS, sensitive files)
 * - Cookie security analysis
 * - Certificate Transparency subdomain enumeration
 * - Subdomain takeover detection
 */
import { scanSSL, SSLInfo } from './ssl-scanner';
import { scanHeaders, HeaderAnalysis, analyzeCookies, cookiesToVulnerabilities, CookieAnalysis } from './header-scanner';
import { getDNSInfo, scanSubdomains, scanSubdomainsEnhanced, checkSubdomainsTakeover, takeoverToVulnerabilities, DNSInfo, SubdomainInfo } from './dns-scanner';
import { scanPorts, getPortDetails, PortScanResult } from './port-scanner';
import { detectTechStack, TechStackItem } from './tech-detector';
import { detectVulnerabilities, Vulnerability } from './vulnerability-detector';
import { calculateSecurityScore, ScoreBreakdown } from './scoring-engine';
import { generateActionPlan, ActionPlanItem } from './action-plan-generator';
import { analyzePageContent, ContentAnalysisResult } from './content-analyzer';
import { checkCompliance } from './compliance-checker';
import { performActiveScan, convertToVulnerabilities as activeToVulns, ActiveScanResult } from './active-scanner';
import { getGeoIP, formatLocation } from '../services/geoip.service';
import { getWhoisInfo, getDaysUntilExpiration } from '../services/whois.service';

export interface SecurityReport {
  targetUrl: string;
  scanTimestamp: string;
  overallScore: number;
  vulnerabilities: Vulnerability[];
  summary: string;
  techStackDetected: TechStackItem[];
  compliance: Array<{
    standard: string;
    status: 'PASS' | 'FAIL' | 'WARNING';
    details: string;
  }>;
  networkInfo: {
    ip: string;
    location: string;
    isp: string;
    asn: string;
    organization: string;
    serverType: string;
    ports: number[];
  };
  headers: HeaderAnalysis[];
  cookies: CookieAnalysis[];
  ssl: SSLInfo;
  subdomains: SubdomainInfo[];
  sensitiveFiles: Array<{
    path: string;
    type: string;
    risk: string;
  }>;
  darkWebLeaks: Array<{
    source: string;
    date: string;
    type: string;
    severity: 'HIGH' | 'MEDIUM';
  }>;
  actionPlan: ActionPlanItem[];
  isPremium?: boolean;
  scanPhases?: {
    activeScanning: boolean;
    enhancedSubdomains: boolean;
    takeoverCheck: boolean;
  };
}

/**
 * Perform comprehensive security scan
 * @param url - Target URL to scan
 * @param isPremium - Whether user has premium access
 * @param lang - Language for report (tr/en)
 */
export async function performSecurityScan(
  url: string,
  isPremium: boolean,
  lang: 'tr' | 'en'
): Promise<SecurityReport> {
  console.log(`[SecurityScan] Starting scan for ${url} (Premium: ${isPremium}, Lang: ${lang})`);

  const parsedUrl = new URL(url);
  const hostname = parsedUrl.hostname;
  const port = parsedUrl.port ? parseInt(parsedUrl.port) : (parsedUrl.protocol === 'https:' ? 443 : 80);

  // Phase 1: Parallel basic scans (SSL, Headers, DNS, Cookies)
  console.log('[SecurityScan] Phase 1: Basic scans (SSL, Headers, DNS, Cookies)');
  const [sslResult, headersResult, dnsResult, cookiesResult] = await Promise.allSettled([
    scanSSL(hostname, port),
    scanHeaders(url),
    getDNSInfo(hostname),
    analyzeCookies(url),
  ]);

  const ssl: SSLInfo = sslResult.status === 'fulfilled'
    ? sslResult.value
    : getDefaultSSL();

  const headers: HeaderAnalysis[] = headersResult.status === 'fulfilled'
    ? headersResult.value
    : [];

  const cookies: CookieAnalysis[] = cookiesResult.status === 'fulfilled'
    ? cookiesResult.value
    : [];

  const network: DNSInfo = dnsResult.status === 'fulfilled'
    ? dnsResult.value
    : { ip: 'Unknown' };

  console.log(`[SecurityScan] Phase 1 complete - SSL: ${ssl.grade}, Headers: ${headers.length}, Cookies: ${cookies.length}, IP: ${network.ip}`);

  // Phase 2: Port scanning (use IP from DNS)
  console.log('[SecurityScan] Phase 2: Port scanning');
  let openPorts: number[] = [];
  if (network.ip !== 'Unknown') {
    try {
      openPorts = await scanPorts(network.ip);
      console.log(`[SecurityScan] Phase 2 complete - Open ports: ${openPorts.length}`);
    } catch (error) {
      console.error('[SecurityScan] Port scan failed:', error);
    }
  }

  // Phase 3: Technology detection
  console.log('[SecurityScan] Phase 3: Technology detection');
  const headersRecord: Record<string, string> = {};
  headers.forEach(h => {
    headersRecord[h.key.toLowerCase()] = h.value;
  });

  let techStack: TechStackItem[] = [];
  try {
    techStack = await detectTechStack(url, headersRecord);
    console.log(`[SecurityScan] Phase 3 complete - Technologies: ${techStack.length}`);
  } catch (error) {
    console.error('[SecurityScan] Tech detection failed:', error);
  }

  // Phase 4: Enhanced Subdomain scanning with crt.sh (premium only)
  console.log('[SecurityScan] Phase 4: Enhanced Subdomain scanning with crt.sh (Premium only)');
  let subdomains: SubdomainInfo[] = [];
  let takeoverVulns: Vulnerability[] = [];
  if (isPremium) {
    try {
      // Use enhanced subdomain scanning with Certificate Transparency
      subdomains = await scanSubdomainsEnhanced(hostname);
      console.log(`[SecurityScan] Phase 4 complete - Subdomains: ${subdomains.length}`);

      // Check for subdomain takeover vulnerabilities
      console.log('[SecurityScan] Phase 4b: Checking subdomain takeover...');
      const takeoverResults = await checkSubdomainsTakeover(subdomains.slice(0, 20)); // Limit to first 20
      takeoverVulns = takeoverToVulnerabilities(takeoverResults, lang);
      console.log(`[SecurityScan] Phase 4b complete - Takeover risks: ${takeoverVulns.length}`);
    } catch (error) {
      console.error('[SecurityScan] Subdomain scan failed:', error);
    }
  } else {
    // Basic subdomain scan for free users
    try {
      subdomains = await scanSubdomains(hostname);
      console.log(`[SecurityScan] Phase 4 complete (basic) - Subdomains: ${subdomains.length}`);
    } catch (error) {
      console.error('[SecurityScan] Subdomain scan failed:', error);
    }
  }

  // Phase 5: Content security analysis
  console.log('[SecurityScan] Phase 5: Content security analysis');
  let contentVulns: Vulnerability[] = [];
  try {
    const { vulnerabilities: contentSecurityVulns } = await analyzePageContent(url, lang);
    contentVulns = contentSecurityVulns;
    console.log(`[SecurityScan] Phase 5 complete - Content vulnerabilities: ${contentVulns.length}`);
  } catch (error) {
    console.error('[SecurityScan] Content analysis failed:', error);
  }

  // Phase 5b: Active security scanning (SQLi, XSS, sensitive files)
  console.log('[SecurityScan] Phase 5b: Active vulnerability scanning');
  let activeVulns: Vulnerability[] = [];
  let sensitiveFiles: Array<{ path: string; type: string; risk: string }> = [];
  try {
    const activeResults = await performActiveScan(url, lang);
    activeVulns = activeToVulns(activeResults, lang);

    // Extract accessible sensitive files for report
    sensitiveFiles = activeResults.sensitiveFiles
      .filter(f => f.accessible)
      .map(f => ({ path: f.path, type: f.type, risk: f.risk }));

    console.log(`[SecurityScan] Phase 5b complete - Active vulns: ${activeVulns.length}, Sensitive files: ${sensitiveFiles.length}`);
  } catch (error) {
    console.error('[SecurityScan] Active scanning failed:', error);
  }

  // Phase 5c: Cookie security analysis
  console.log('[SecurityScan] Phase 5c: Cookie security analysis');
  let cookieVulns: Vulnerability[] = [];
  try {
    cookieVulns = cookiesToVulnerabilities(cookies, lang);
    console.log(`[SecurityScan] Phase 5c complete - Cookie vulns: ${cookieVulns.length}`);
  } catch (error) {
    console.error('[SecurityScan] Cookie analysis failed:', error);
  }

  // Phase 6: GeoIP lookup
  console.log('[SecurityScan] Phase 6: GeoIP lookup');
  let geoipInfo = null;
  if (network.ip !== 'Unknown') {
    try {
      geoipInfo = await getGeoIP(network.ip);
      console.log(`[SecurityScan] Phase 6 complete - Location: ${geoipInfo?.city || 'Unknown'}`);
    } catch (error) {
      console.error('[SecurityScan] GeoIP lookup failed:', error);
    }
  }

  // Phase 7: WHOIS lookup (Premium only)
  console.log('[SecurityScan] Phase 7: WHOIS lookup (Premium only)');
  let whoisInfo = null;
  if (isPremium) {
    try {
      whoisInfo = await getWhoisInfo(hostname);
      console.log(`[SecurityScan] Phase 7 complete - Domain registrar: ${whoisInfo?.registrar || 'Unknown'}`);
    } catch (error) {
      console.error('[SecurityScan] WHOIS lookup failed:', error);
    }
  } else {
    console.log('[SecurityScan] Phase 7 skipped - Not premium');
  }

  // Phase 8: Vulnerability detection and aggregation
  console.log('[SecurityScan] Phase 8: Vulnerability detection and aggregation');
  const headerVulns = await detectVulnerabilities(headers, ssl, techStack, openPorts, lang);

  // Combine all vulnerability sources
  const vulnerabilities = [
    ...headerVulns,      // Header-based vulnerabilities
    ...contentVulns,     // Content analysis vulnerabilities
    ...activeVulns,      // Active scanning (SQLi, XSS, sensitive files)
    ...cookieVulns,      // Cookie security issues
    ...takeoverVulns,    // Subdomain takeover risks (premium)
  ];

  // Remove duplicates based on ID
  const uniqueVulns = vulnerabilities.filter((v, index, self) =>
    index === self.findIndex(t => t.id === v.id)
  );

  console.log(`[SecurityScan] Phase 8 complete - Total unique vulnerabilities: ${uniqueVulns.length}`);

  // Phase 9: Score calculation
  console.log('[SecurityScan] Phase 9: Security score calculation');
  const scoreBreakdown: ScoreBreakdown = calculateSecurityScore(uniqueVulns, ssl, headers);
  console.log(`[SecurityScan] Phase 9 complete - Score: ${scoreBreakdown.total}/100 (${scoreBreakdown.grade})`);

  // Phase 10: Compliance checks
  console.log('[SecurityScan] Phase 10: Compliance checks');
  const compliance = checkCompliance(headers, ssl, uniqueVulns, url.startsWith('https://'), lang);
  console.log(`[SecurityScan] Phase 10 complete - Compliance standards checked: ${compliance.length}`);

  // Phase 11: Action plan generation
  console.log('[SecurityScan] Phase 11: Action plan generation');
  const fullActionPlan = generateActionPlan(uniqueVulns, ssl, lang);
  const actionPlan = isPremium ? fullActionPlan : fullActionPlan.slice(0, 3); // Free users get only 3 items
  console.log(`[SecurityScan] Phase 11 complete - Action items: ${actionPlan.length}`);

  // Generate summary
  const summary = generateSummary(scoreBreakdown.total, uniqueVulns.length, lang);

  // Assemble final report
  const report: SecurityReport = {
    targetUrl: url,
    scanTimestamp: new Date().toISOString(),
    overallScore: scoreBreakdown.total,
    summary,
    vulnerabilities: uniqueVulns,
    techStackDetected: techStack,
    headers,
    cookies,
    ssl,
    networkInfo: {
      ip: network.ip,
      location: formatLocation(geoipInfo, lang),
      isp: geoipInfo?.isp || 'Unknown',
      asn: geoipInfo?.as || 'Unknown',
      organization: geoipInfo?.org || whoisInfo?.registrar || 'Unknown',
      serverType: headersRecord['server'] || 'Unknown',
      ports: openPorts,
    },
    subdomains,
    sensitiveFiles,
    darkWebLeaks: [], // TODO: Integrate Have I Been Pwned API
    actionPlan,
    compliance,
    isPremium,
    scanPhases: {
      activeScanning: activeVulns.length > 0 || sensitiveFiles.length > 0,
      enhancedSubdomains: isPremium,
      takeoverCheck: isPremium && takeoverVulns.length >= 0,
    },
  };

  console.log(`[SecurityScan] Scan complete for ${url}`);
  return report;
}

/**
 * Get default SSL info when scan fails
 */
function getDefaultSSL(): SSLInfo {
  return {
    issuer: 'Unknown',
    validFrom: new Date().toISOString(),
    validTo: new Date().toISOString(),
    daysRemaining: 0,
    protocol: 'Unknown',
    grade: 'F',
  };
}

/**
 * Generate human-readable summary
 */
function generateSummary(score: number, vulnCount: number, lang: 'tr' | 'en'): string {
  if (lang === 'tr') {
    if (score >= 80) {
      return `Güvenlik skoru: ${score}/100 - İyi güvenlik seviyesi. ${vulnCount} zafiyet tespit edildi.`;
    } else if (score >= 60) {
      return `Güvenlik skoru: ${score}/100 - Orta güvenlik seviyesi. ${vulnCount} zafiyet tespit edildi ve iyileştirme gerekiyor.`;
    } else if (score >= 40) {
      return `Güvenlik skoru: ${score}/100 - Düşük güvenlik seviyesi. ${vulnCount} zafiyet tespit edildi. Acil müdahale gerekli.`;
    } else {
      return `Güvenlik skoru: ${score}/100 - Kritik durum! ${vulnCount} ciddi zafiyet tespit edildi. Derhal aksiyon alınmalı!`;
    }
  } else {
    if (score >= 80) {
      return `Security score: ${score}/100 - Good security level. ${vulnCount} vulnerabilities detected.`;
    } else if (score >= 60) {
      return `Security score: ${score}/100 - Medium security level. ${vulnCount} vulnerabilities detected and improvement needed.`;
    } else if (score >= 40) {
      return `Security score: ${score}/100 - Low security level. ${vulnCount} vulnerabilities detected. Urgent action required.`;
    } else {
      return `Security score: ${score}/100 - Critical condition! ${vulnCount} serious vulnerabilities detected. Take immediate action!`;
    }
  }
}
