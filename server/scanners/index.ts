/**
 * Main Security Scanner Orchestrator
 * Coordinates all scanning modules and generates final report
 *
 * Enhanced with:
 * - Active vulnerability scanning (SQLi, XSS, sensitive files)
 * - Cookie security analysis
 * - Certificate Transparency subdomain enumeration
 * - Subdomain takeover detection
 * - HTTP Methods scanning
 * - Robots.txt & Security.txt analysis
 * - CVE correlation for detected technologies
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
import { scanHttpMethods, httpMethodsToVulnerabilities, HttpMethodsResult } from './http-methods-scanner';
import { scanRobots, robotsToVulnerabilities, RobotsScanResult } from './robots-scanner';
import { correlateCVEs, cveCorrelationsToVulnerabilities, CVECorrelationResult } from './cve-correlator';
import { getGeoIP, formatLocation } from '../services/geoip.service';
import { getWhoisInfo, getDaysUntilExpiration } from '../services/whois.service';
import { ScanProgressEmitter } from '../services/scan-progress.service';

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
  // New fields for enhanced scanning
  httpMethods?: {
    allowed: string[];
    dangerous: string[];
  };
  robotsAnalysis?: {
    sensitivePaths: string[];
    hasSecurityTxt: boolean;
  };
  cveCorrelations?: CVECorrelationResult[];
  // Warnings for inconsistencies detected during scan
  warnings?: Array<{
    type: 'infrastructure' | 'configuration' | 'data';
    message: string;
    details?: string;
  }>;
}

/**
 * Perform comprehensive security scan
 * @param url - Target URL to scan
 * @param isPremium - Whether user has premium access
 * @param lang - Language for report (tr/en)
 * @param progressEmitter - Optional progress emitter for real-time updates
 */
export async function performSecurityScan(
  url: string,
  isPremium: boolean,
  lang: 'tr' | 'en',
  progressEmitter?: ScanProgressEmitter
): Promise<SecurityReport> {
  const emit = (phase: string, progress: number, type: 'info' | 'success' | 'warning' | 'error' | 'neutral' = 'info', details?: string) => {
    if (progressEmitter) {
      progressEmitter.emitProgress(phase as any, progress, type, details);
    }
  };

  console.log(`[SecurityScan] Starting scan for ${url} (Premium: ${isPremium}, Lang: ${lang})`);
  emit('connecting', 0, 'info');

  const parsedUrl = new URL(url);
  const hostname = parsedUrl.hostname;
  const port = parsedUrl.port ? parseInt(parsedUrl.port) : (parsedUrl.protocol === 'https:' ? 443 : 80);

  // Phase 1: Parallel basic scans (SSL, Headers, DNS, Cookies)
  console.log('[SecurityScan] Phase 1: Basic scans (SSL, Headers, DNS, Cookies)');
  emit('dns', 5, 'info');
  emit('ssl', 6, 'info');
  emit('headers', 7, 'info');
  emit('cookies', 8, 'info');
  
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
  emit('dns_complete', 10, 'success', `IP: ${network.ip}`);
  emit('ssl_complete', 12, 'success', `Grade: ${ssl.grade}`);
  emit('headers_complete', 14, 'success', `${headers.length} header`);

  // Phase 2: Port scanning (use IP from DNS)
  console.log('[SecurityScan] Phase 2: Port scanning');
  emit('ports', 15, 'info');
  
  let openPorts: number[] = [];
  if (network.ip !== 'Unknown') {
    try {
      openPorts = await scanPorts(network.ip);
      console.log(`[SecurityScan] Phase 2 complete - Open ports: ${openPorts.length}`);
      emit('ports_complete', 25, 'success', `${openPorts.length} açık port`);
    } catch (error) {
      console.error('[SecurityScan] Port scan failed:', error);
      emit('ports_complete', 25, 'warning', 'Port taraması başarısız');
    }
  } else {
    emit('ports_complete', 25, 'neutral', 'IP çözümlenemedi');
  }

  // Phase 3: Technology detection
  console.log('[SecurityScan] Phase 3: Technology detection');
  emit('tech', 26, 'info');
  
  const headersRecord: Record<string, string> = {};
  headers.forEach(h => {
    headersRecord[h.key.toLowerCase()] = h.value;
  });

  let techStack: TechStackItem[] = [];
  try {
    techStack = await detectTechStack(url, headersRecord);
    console.log(`[SecurityScan] Phase 3 complete - Technologies: ${techStack.length}`);
    emit('tech_complete', 30, 'success', `${techStack.length} teknoloji`);
  } catch (error) {
    console.error('[SecurityScan] Tech detection failed:', error);
    emit('tech_complete', 30, 'warning', 'Teknoloji tespiti başarısız');
  }

  // Phase 3b: CVE Correlation for detected technologies
  console.log('[SecurityScan] Phase 3b: CVE Correlation');
  emit('cve', 31, 'info');
  
  let cveCorrelations: CVECorrelationResult[] = [];
  let cveVulns: Vulnerability[] = [];
  try {
    cveCorrelations = await correlateCVEs(techStack, lang);
    const cveVulnResults = cveCorrelationsToVulnerabilities(cveCorrelations, lang);
    // Convert to Vulnerability format
    cveVulns = cveVulnResults.map(cve => ({
      id: cve.id,
      title: cve.title,
      description: cve.description,
      severity: cve.severity as any,
      location: cve.technology,
      remediation: lang === 'tr' 
        ? `${cve.technology} sürümünü güncelleyin. Detaylar: ${cve.nvdUrl}`
        : `Update ${cve.technology} version. Details: ${cve.nvdUrl}`,
      cvssScore: cve.cvssScore,
      exploitExample: cve.hasExploit 
        ? (lang === 'tr' ? 'Bilinen exploit mevcut' : 'Known exploit available')
        : '',
      exploitablePaths: cve.hasExploit ? [{
        description: lang === 'tr' ? 'Bilinen Exploit' : 'Known Exploit',
        scenario: lang === 'tr' 
          ? 'Bu güvenlik açığı için bilinen bir exploit mevcut'
          : 'A known exploit exists for this vulnerability',
        impact: lang === 'tr' ? 'Yüksek risk - acil güncelleme gerekli' : 'High risk - immediate update required'
      }] : [],
      relatedCves: [{ name: cve.cveId, url: cve.nvdUrl }],
    }));
    console.log(`[SecurityScan] Phase 3b complete - CVE correlations: ${cveCorrelations.length}, CVE vulns: ${cveVulns.length}`);
    emit('cve_complete', 35, cveVulns.length > 0 ? 'warning' : 'success', `${cveVulns.length} CVE`);
  } catch (error) {
    console.error('[SecurityScan] CVE correlation failed:', error);
    emit('cve_complete', 35, 'neutral', 'CVE korelasyonu tamamlandı');
  }

  // Phase 4: Enhanced Subdomain scanning with crt.sh (premium only)
  console.log('[SecurityScan] Phase 4: Enhanced Subdomain scanning with crt.sh (Premium only)');
  emit('subdomains', 36, 'info');
  
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
      emit('subdomains_complete', 42, 'success', `${subdomains.length} alt alan adı`);
    } catch (error) {
      console.error('[SecurityScan] Subdomain scan failed:', error);
      emit('subdomains_complete', 42, 'warning', 'Alt alan adı taraması başarısız');
    }
  } else {
    // Basic subdomain scan for free users
    try {
      subdomains = await scanSubdomains(hostname);
      console.log(`[SecurityScan] Phase 4 complete (basic) - Subdomains: ${subdomains.length}`);
      emit('subdomains_complete', 42, 'success', `${subdomains.length} alt alan adı`);
    } catch (error) {
      console.error('[SecurityScan] Subdomain scan failed:', error);
      emit('subdomains_complete', 42, 'neutral', 'Alt alan adı taraması tamamlandı');
    }
  }

  // Phase 5: Content security analysis
  console.log('[SecurityScan] Phase 5: Content security analysis');
  emit('content', 43, 'info');
  
  let contentVulns: Vulnerability[] = [];
  try {
    const { vulnerabilities: contentSecurityVulns } = await analyzePageContent(url, lang);
    contentVulns = contentSecurityVulns;
    console.log(`[SecurityScan] Phase 5 complete - Content vulnerabilities: ${contentVulns.length}`);
    emit('content_complete', 48, contentVulns.length > 0 ? 'warning' : 'success', `${contentVulns.length} içerik açığı`);
  } catch (error) {
    console.error('[SecurityScan] Content analysis failed:', error);
    emit('content_complete', 48, 'neutral', 'İçerik analizi tamamlandı');
  }

  // Phase 5b: Active security scanning (SQLi, XSS, sensitive files)
  console.log('[SecurityScan] Phase 5b: Active vulnerability scanning');
  emit('active', 49, 'info');
  emit('active_files', 52, 'info');
  emit('active_sqli', 55, 'warning');
  emit('active_xss', 58, 'warning');
  
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
    emit('active_complete', 65, activeVulns.length > 0 ? 'warning' : 'success', `${activeVulns.length} aktif açık`);
  } catch (error) {
    console.error('[SecurityScan] Active scanning failed:', error);
    emit('active_complete', 65, 'neutral', 'Aktif tarama tamamlandı');
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

  // Phase 5d: HTTP Methods scanning
  console.log('[SecurityScan] Phase 5d: HTTP Methods scanning');
  emit('http_methods', 70, 'info');
  
  let httpMethodsResult: HttpMethodsResult = { allowedMethods: [], dangerousMethods: [], vulnerabilities: [] };
  let httpMethodsVulns: Vulnerability[] = [];
  try {
    httpMethodsResult = await scanHttpMethods(url, lang);
    httpMethodsVulns = httpMethodsToVulnerabilities(httpMethodsResult, lang);
    console.log(`[SecurityScan] Phase 5d complete - HTTP Methods vulns: ${httpMethodsVulns.length}`);
    emit('http_methods_complete', 75, httpMethodsVulns.length > 0 ? 'warning' : 'success', `${httpMethodsResult.allowedMethods.length} metod`);
  } catch (error) {
    console.error('[SecurityScan] HTTP Methods scanning failed:', error);
    emit('http_methods_complete', 75, 'neutral', 'HTTP metod taraması tamamlandı');
  }

  // Phase 5e: Robots.txt & Security.txt analysis
  console.log('[SecurityScan] Phase 5e: Robots.txt & Security.txt analysis');
  emit('robots', 76, 'info');
  
  let robotsResult: RobotsScanResult = {
    robotsTxt: { exists: false, disallowedPaths: [], sensitivePaths: [], sitemapUrls: [] },
    securityTxt: { exists: false },
    findings: [],
  };
  let robotsVulns: Vulnerability[] = [];
  try {
    robotsResult = await scanRobots(url, lang);
    robotsVulns = robotsToVulnerabilities(robotsResult, lang);
    console.log(`[SecurityScan] Phase 5e complete - Robots vulns: ${robotsVulns.length}`);
    emit('robots_complete', 80, robotsVulns.length > 0 ? 'warning' : 'success', `${robotsResult.robotsTxt.sensitivePaths.length} hassas yol`);
  } catch (error) {
    console.error('[SecurityScan] Robots.txt analysis failed:', error);
    emit('robots_complete', 80, 'neutral', 'Robots analizi tamamlandı');
  }

  // Phase 6: GeoIP lookup
  console.log('[SecurityScan] Phase 6: GeoIP lookup');
  emit('geoip', 81, 'info');
  
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
    emit('whois', 83, 'info');
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
  emit('scoring', 85, 'info');
  const headerVulns = await detectVulnerabilities(headers, ssl, techStack, openPorts, lang);

  // Combine all vulnerability sources
  const vulnerabilities = [
    ...headerVulns,      // Header-based vulnerabilities
    ...contentVulns,     // Content analysis vulnerabilities
    ...activeVulns,      // Active scanning (SQLi, XSS, sensitive files)
    ...cookieVulns,      // Cookie security issues
    ...takeoverVulns,    // Subdomain takeover risks (premium)
    ...httpMethodsVulns, // HTTP Methods vulnerabilities
    ...robotsVulns,      // Robots.txt sensitive paths
    ...cveVulns,         // CVE correlations for detected technologies
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
  emit('compliance', 90, 'info');
  
  const compliance = checkCompliance(headers, ssl, uniqueVulns, url.startsWith('https://'), lang);
  console.log(`[SecurityScan] Phase 10 complete - Compliance standards checked: ${compliance.length}`);

  // Phase 11: Action plan generation
  console.log('[SecurityScan] Phase 11: Action plan generation');
  emit('report', 95, 'info');
  const fullActionPlan = generateActionPlan(uniqueVulns, ssl, lang);
  const actionPlan = isPremium ? fullActionPlan : fullActionPlan.slice(0, 3); // Free users get only 3 items
  console.log(`[SecurityScan] Phase 11 complete - Action items: ${actionPlan.length}`);

  // Generate summary
  const summary = generateSummary(scoreBreakdown.total, uniqueVulns.length, lang);

  // Check for infrastructure inconsistencies
  const warnings: Array<{ type: 'infrastructure' | 'configuration' | 'data'; message: string; details?: string }> = [];
  
  // Check server type vs ISP/port inconsistency
  const serverType = headersRecord['server'] || '';
  const serverTypeLower = serverType.toLowerCase();
  const isp = geoipInfo?.isp || '';
  const ispLower = isp.toLowerCase();
  
  // Known serverless/CDN providers that shouldn't have database ports open
  const serverlessProviders = ['vercel', 'netlify', 'cloudflare', 'aws lambda', 'azure functions', 'firebase'];
  const isServerless = serverlessProviders.some(p => serverTypeLower.includes(p));
  
  // Database and dangerous ports that shouldn't be open on serverless
  const databasePorts = [3306, 5432, 27017, 6379, 1433, 11211];
  const dangerousPorts = [21, 22, 23, 3389, 5900];
  const openDatabasePorts = openPorts.filter(p => databasePorts.includes(p));
  const openDangerousPorts = openPorts.filter(p => dangerousPorts.includes(p));
  
  if (isServerless && (openDatabasePorts.length > 0 || openDangerousPorts.length > 0)) {
    warnings.push({
      type: 'infrastructure',
      message: lang === 'tr' 
        ? `Altyapı Tutarsızlığı: HTTP başlıklarında "${serverType}" tespit edildi ancak IP adresinde (${network.ip}) veritabanı/servis portları açık.`
        : `Infrastructure Inconsistency: "${serverType}" detected in HTTP headers but database/service ports are open on IP (${network.ip}).`,
      details: lang === 'tr'
        ? `Bu durum DNS yanlış yapılandırması, proxy/CDN kullanımı veya farklı bir sunucuya yönlendirme olduğunu gösterebilir. Açık portlar: ${[...openDatabasePorts, ...openDangerousPorts].join(', ')}`
        : `This may indicate DNS misconfiguration, proxy/CDN usage, or redirection to a different server. Open ports: ${[...openDatabasePorts, ...openDangerousPorts].join(', ')}`
    });
  }
  
  // Check if ISP doesn't match expected cloud provider
  const cloudProviders: Record<string, string[]> = {
    'vercel': ['amazon', 'aws', 'google', 'gcp', 'cloudflare'],
    'netlify': ['amazon', 'aws', 'google', 'gcp', 'cloudflare'],
    'cloudflare': ['cloudflare'],
  };
  
  for (const [provider, expectedIsps] of Object.entries(cloudProviders)) {
    if (serverTypeLower.includes(provider)) {
      const matchesExpected = expectedIsps.some(exp => ispLower.includes(exp));
      if (!matchesExpected && isp && isp !== 'Unknown') {
        warnings.push({
          type: 'infrastructure',
          message: lang === 'tr'
            ? `ISP Uyuşmazlığı: Sunucu "${serverType}" olarak tespit edildi ancak ISP "${isp}" beklenenden farklı.`
            : `ISP Mismatch: Server detected as "${serverType}" but ISP "${isp}" differs from expected.`,
          details: lang === 'tr'
            ? 'Bu durum DNS yapılandırma hatası veya proxy kullanımı olabilir.'
            : 'This may indicate DNS misconfiguration or proxy usage.'
        });
        break;
      }
    }
  }

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
    // New fields for enhanced scanning
    httpMethods: {
      allowed: httpMethodsResult.allowedMethods,
      dangerous: httpMethodsResult.dangerousMethods,
    },
    robotsAnalysis: {
      sensitivePaths: robotsResult.robotsTxt.sensitivePaths,
      hasSecurityTxt: robotsResult.securityTxt.exists,
    },
    cveCorrelations,
    warnings: warnings.length > 0 ? warnings : undefined,
  };

  console.log(`[SecurityScan] Scan complete for ${url}`);
  emit('complete', 100, 'success', `Skor: ${scoreBreakdown.total}/100`);
  
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
