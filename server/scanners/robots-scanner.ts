/**
 * Robots.txt & Security.txt Scanner
 * Analyzes robots.txt and security.txt files for security insights
 * 
 * Features:
 * - Parse robots.txt Disallow entries
 * - Identify sensitive paths (admin, backup, config patterns)
 * - Check for security.txt presence
 * - Extract security contact information
 */

import axios from 'axios';

// ==================== INTERFACES ====================

export interface RobotsScanResult {
  robotsTxt: {
    exists: boolean;
    disallowedPaths: string[];
    sensitivePaths: string[];
    sitemapUrls: string[];
  };
  securityTxt: {
    exists: boolean;
    contact?: string;
    encryption?: string;
    policy?: string;
    acknowledgments?: string;
    preferredLanguages?: string;
    canonical?: string;
    expires?: string;
  };
  findings: RobotsFinding[];
}

export interface RobotsFinding {
  type: 'sensitive_path' | 'admin_panel' | 'backup_dir' | 'config_file' | 'missing_security_txt';
  path?: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM';
  description: string;
}

// ==================== CONSTANTS ====================

/**
 * Patterns that indicate sensitive paths in robots.txt
 */
export const SENSITIVE_PATH_PATTERNS: Array<{
  pattern: RegExp;
  type: RobotsFinding['type'];
  severity: 'INFO' | 'LOW' | 'MEDIUM';
  descriptionKey: string;
}> = [
  // Admin panels
  { pattern: /admin/i, type: 'admin_panel', severity: 'MEDIUM', descriptionKey: 'admin' },
  { pattern: /administrator/i, type: 'admin_panel', severity: 'MEDIUM', descriptionKey: 'admin' },
  { pattern: /wp-admin/i, type: 'admin_panel', severity: 'MEDIUM', descriptionKey: 'admin' },
  { pattern: /cpanel/i, type: 'admin_panel', severity: 'MEDIUM', descriptionKey: 'admin' },
  { pattern: /phpmyadmin/i, type: 'admin_panel', severity: 'MEDIUM', descriptionKey: 'admin' },
  { pattern: /manager/i, type: 'admin_panel', severity: 'LOW', descriptionKey: 'admin' },
  { pattern: /dashboard/i, type: 'admin_panel', severity: 'LOW', descriptionKey: 'admin' },
  
  // Backup directories
  { pattern: /backup/i, type: 'backup_dir', severity: 'MEDIUM', descriptionKey: 'backup' },
  { pattern: /backups/i, type: 'backup_dir', severity: 'MEDIUM', descriptionKey: 'backup' },
  { pattern: /\.bak/i, type: 'backup_dir', severity: 'MEDIUM', descriptionKey: 'backup' },
  { pattern: /\.old/i, type: 'backup_dir', severity: 'LOW', descriptionKey: 'backup' },
  { pattern: /archive/i, type: 'backup_dir', severity: 'LOW', descriptionKey: 'backup' },
  { pattern: /dump/i, type: 'backup_dir', severity: 'MEDIUM', descriptionKey: 'backup' },
  
  // Config files
  { pattern: /config/i, type: 'config_file', severity: 'MEDIUM', descriptionKey: 'config' },
  { pattern: /\.env/i, type: 'config_file', severity: 'MEDIUM', descriptionKey: 'config' },
  { pattern: /\.git/i, type: 'config_file', severity: 'MEDIUM', descriptionKey: 'config' },
  { pattern: /\.svn/i, type: 'config_file', severity: 'MEDIUM', descriptionKey: 'config' },
  { pattern: /\.htaccess/i, type: 'config_file', severity: 'LOW', descriptionKey: 'config' },
  { pattern: /web\.config/i, type: 'config_file', severity: 'MEDIUM', descriptionKey: 'config' },
  
  // Sensitive directories
  { pattern: /private/i, type: 'sensitive_path', severity: 'LOW', descriptionKey: 'sensitive' },
  { pattern: /secret/i, type: 'sensitive_path', severity: 'MEDIUM', descriptionKey: 'sensitive' },
  { pattern: /internal/i, type: 'sensitive_path', severity: 'LOW', descriptionKey: 'sensitive' },
  { pattern: /api\/v\d+\/internal/i, type: 'sensitive_path', severity: 'MEDIUM', descriptionKey: 'sensitive' },
  { pattern: /debug/i, type: 'sensitive_path', severity: 'MEDIUM', descriptionKey: 'sensitive' },
  { pattern: /test/i, type: 'sensitive_path', severity: 'LOW', descriptionKey: 'sensitive' },
  { pattern: /staging/i, type: 'sensitive_path', severity: 'LOW', descriptionKey: 'sensitive' },
  { pattern: /dev/i, type: 'sensitive_path', severity: 'LOW', descriptionKey: 'sensitive' },
  { pattern: /tmp/i, type: 'sensitive_path', severity: 'LOW', descriptionKey: 'sensitive' },
  { pattern: /temp/i, type: 'sensitive_path', severity: 'LOW', descriptionKey: 'sensitive' },
  { pattern: /upload/i, type: 'sensitive_path', severity: 'LOW', descriptionKey: 'sensitive' },
  { pattern: /uploads/i, type: 'sensitive_path', severity: 'LOW', descriptionKey: 'sensitive' },
  { pattern: /log/i, type: 'sensitive_path', severity: 'MEDIUM', descriptionKey: 'sensitive' },
  { pattern: /logs/i, type: 'sensitive_path', severity: 'MEDIUM', descriptionKey: 'sensitive' },
];

// ==================== TRANSLATIONS ====================

const TRANSLATIONS = {
  tr: {
    admin: 'Admin paneli yolu tespit edildi - yetkisiz erişim riski',
    backup: 'Yedekleme dizini tespit edildi - veri sızıntısı riski',
    config: 'Yapılandırma dosyası yolu tespit edildi - hassas bilgi sızıntısı riski',
    sensitive: 'Hassas dizin yolu tespit edildi',
    missingSecurityTxt: 'security.txt dosyası bulunamadı - güvenlik iletişim bilgileri eksik',
    vulnTitle: 'Robots.txt\'de Hassas Yollar Tespit Edildi',
    vulnDescription: 'robots.txt dosyasında {count} hassas yol tespit edildi',
    securityTxtMissingTitle: 'Security.txt Dosyası Eksik',
    securityTxtMissingDesc: 'RFC 9116 standardına uygun security.txt dosyası bulunamadı',
    remediation: 'Hassas dizinleri robots.txt\'den kaldırın ve erişim kontrolü uygulayın',
    securityTxtRemediation: '/.well-known/security.txt dosyası oluşturun ve güvenlik iletişim bilgilerini ekleyin',
  },
  en: {
    admin: 'Admin panel path detected - unauthorized access risk',
    backup: 'Backup directory detected - data leakage risk',
    config: 'Configuration file path detected - sensitive information leakage risk',
    sensitive: 'Sensitive directory path detected',
    missingSecurityTxt: 'security.txt file not found - security contact information missing',
    vulnTitle: 'Sensitive Paths Found in Robots.txt',
    vulnDescription: '{count} sensitive paths detected in robots.txt',
    securityTxtMissingTitle: 'Security.txt File Missing',
    securityTxtMissingDesc: 'No security.txt file found per RFC 9116 standard',
    remediation: 'Remove sensitive directories from robots.txt and implement access controls',
    securityTxtRemediation: 'Create /.well-known/security.txt file and add security contact information',
  },
};

// ==================== PARSING FUNCTIONS ====================

/**
 * Parse robots.txt content and extract Disallow entries
 * @param content - Raw robots.txt content
 * @returns Array of disallowed paths
 */
export function parseRobotsTxt(content: string): { disallowedPaths: string[]; sitemapUrls: string[] } {
  const disallowedPaths: string[] = [];
  const sitemapUrls: string[] = [];
  
  if (!content || typeof content !== 'string') {
    return { disallowedPaths, sitemapUrls };
  }
  
  const lines = content.split('\n');
  
  for (const line of lines) {
    const trimmedLine = line.trim();
    
    // Skip comments and empty lines
    if (trimmedLine.startsWith('#') || trimmedLine === '') {
      continue;
    }
    
    // Parse Disallow entries
    const disallowMatch = trimmedLine.match(/^Disallow:\s*(.+)$/i);
    if (disallowMatch) {
      const path = disallowMatch[1].trim();
      if (path && path !== '' && !disallowedPaths.includes(path)) {
        disallowedPaths.push(path);
      }
    }
    
    // Parse Sitemap entries
    const sitemapMatch = trimmedLine.match(/^Sitemap:\s*(.+)$/i);
    if (sitemapMatch) {
      const url = sitemapMatch[1].trim();
      if (url && !sitemapUrls.includes(url)) {
        sitemapUrls.push(url);
      }
    }
  }
  
  return { disallowedPaths, sitemapUrls };
}

/**
 * Parse security.txt content and extract fields
 * @param content - Raw security.txt content
 * @returns Parsed security.txt fields
 */
export function parseSecurityTxt(content: string): RobotsScanResult['securityTxt'] {
  const result: RobotsScanResult['securityTxt'] = {
    exists: false,
  };
  
  if (!content || typeof content !== 'string') {
    return { exists: false };
  }
  
  const lines = content.split('\n');
  let hasValidField = false;
  
  for (const line of lines) {
    const trimmedLine = line.trim();
    
    // Skip comments and empty lines
    if (trimmedLine.startsWith('#') || trimmedLine === '') {
      continue;
    }
    
    // Parse Contact field
    const contactMatch = trimmedLine.match(/^Contact:\s*(.+)$/i);
    if (contactMatch) {
      result.contact = contactMatch[1].trim();
      hasValidField = true;
    }
    
    // Parse Encryption field
    const encryptionMatch = trimmedLine.match(/^Encryption:\s*(.+)$/i);
    if (encryptionMatch) {
      result.encryption = encryptionMatch[1].trim();
      hasValidField = true;
    }
    
    // Parse Policy field
    const policyMatch = trimmedLine.match(/^Policy:\s*(.+)$/i);
    if (policyMatch) {
      result.policy = policyMatch[1].trim();
      hasValidField = true;
    }
    
    // Parse Acknowledgments field
    const ackMatch = trimmedLine.match(/^Acknowledgments:\s*(.+)$/i);
    if (ackMatch) {
      result.acknowledgments = ackMatch[1].trim();
      hasValidField = true;
    }
    
    // Parse Preferred-Languages field
    const langMatch = trimmedLine.match(/^Preferred-Languages:\s*(.+)$/i);
    if (langMatch) {
      result.preferredLanguages = langMatch[1].trim();
      hasValidField = true;
    }
    
    // Parse Canonical field
    const canonicalMatch = trimmedLine.match(/^Canonical:\s*(.+)$/i);
    if (canonicalMatch) {
      result.canonical = canonicalMatch[1].trim();
      hasValidField = true;
    }
    
    // Parse Expires field
    const expiresMatch = trimmedLine.match(/^Expires:\s*(.+)$/i);
    if (expiresMatch) {
      result.expires = expiresMatch[1].trim();
      hasValidField = true;
    }
  }
  
  // Only mark as exists if we found at least one valid field
  result.exists = hasValidField;
  
  return result;
}

/**
 * Identify sensitive paths from disallowed paths
 * @param disallowedPaths - Array of paths from robots.txt
 * @param lang - Language for descriptions
 * @returns Array of findings for sensitive paths
 */
export function identifySensitivePaths(
  disallowedPaths: string[],
  lang: 'tr' | 'en'
): { sensitivePaths: string[]; findings: RobotsFinding[] } {
  const sensitivePaths: string[] = [];
  const findings: RobotsFinding[] = [];
  const t = TRANSLATIONS[lang];
  
  for (const path of disallowedPaths) {
    for (const patternDef of SENSITIVE_PATH_PATTERNS) {
      if (patternDef.pattern.test(path)) {
        if (!sensitivePaths.includes(path)) {
          sensitivePaths.push(path);
          
          findings.push({
            type: patternDef.type,
            path,
            severity: patternDef.severity,
            description: `${t[patternDef.descriptionKey as keyof typeof t]}: ${path}`,
          });
        }
        break; // Only match first pattern per path
      }
    }
  }
  
  return { sensitivePaths, findings };
}

// ==================== MAIN SCANNER ====================

/**
 * Scan robots.txt and security.txt files
 * @param baseUrl - Target base URL to scan
 * @param lang - Language for descriptions
 * @returns Robots scan result
 */
export async function scanRobots(
  baseUrl: string,
  lang: 'tr' | 'en' = 'en'
): Promise<RobotsScanResult> {
  console.log(`[RobotsScanner] Scanning robots.txt and security.txt for ${baseUrl}`);
  
  const t = TRANSLATIONS[lang];
  const result: RobotsScanResult = {
    robotsTxt: {
      exists: false,
      disallowedPaths: [],
      sensitivePaths: [],
      sitemapUrls: [],
    },
    securityTxt: {
      exists: false,
    },
    findings: [],
  };
  
  // Normalize base URL
  const parsedUrl = new URL(baseUrl);
  const origin = parsedUrl.origin;
  
  // Fetch robots.txt
  try {
    const robotsResponse = await axios.get(`${origin}/robots.txt`, {
      timeout: 5000,
      validateStatus: (status) => status < 500,
      maxRedirects: 3,
      headers: {
        'User-Agent': 'SecuriScan Security Scanner',
      },
    });
    
    if (robotsResponse.status === 200 && robotsResponse.data) {
      const content = typeof robotsResponse.data === 'string' 
        ? robotsResponse.data 
        : String(robotsResponse.data);
      
      // Check if it's actually robots.txt content (not HTML error page)
      if (!content.toLowerCase().includes('<!doctype') && !content.toLowerCase().includes('<html')) {
        result.robotsTxt.exists = true;
        
        const { disallowedPaths, sitemapUrls } = parseRobotsTxt(content);
        result.robotsTxt.disallowedPaths = disallowedPaths;
        result.robotsTxt.sitemapUrls = sitemapUrls;
        
        // Identify sensitive paths
        const { sensitivePaths, findings } = identifySensitivePaths(disallowedPaths, lang);
        result.robotsTxt.sensitivePaths = sensitivePaths;
        result.findings.push(...findings);
        
        console.log(`[RobotsScanner] robots.txt found - ${disallowedPaths.length} disallowed paths, ${sensitivePaths.length} sensitive`);
      }
    }
  } catch (error: any) {
    console.log(`[RobotsScanner] robots.txt not accessible: ${error.message}`);
  }
  
  // Fetch security.txt (try both locations)
  const securityTxtPaths = ['/.well-known/security.txt', '/security.txt'];
  
  for (const secPath of securityTxtPaths) {
    try {
      const securityResponse = await axios.get(`${origin}${secPath}`, {
        timeout: 5000,
        validateStatus: (status) => status < 500,
        maxRedirects: 3,
        headers: {
          'User-Agent': 'SecuriScan Security Scanner',
        },
      });
      
      if (securityResponse.status === 200 && securityResponse.data) {
        const content = typeof securityResponse.data === 'string'
          ? securityResponse.data
          : String(securityResponse.data);
        
        // Check if it's actually security.txt content (not HTML error page)
        if (!content.toLowerCase().includes('<!doctype') && !content.toLowerCase().includes('<html')) {
          result.securityTxt = parseSecurityTxt(content);
          console.log(`[RobotsScanner] security.txt found at ${secPath}`);
          break;
        }
      }
    } catch (error: any) {
      // Continue to next path
    }
  }
  
  // Add finding if security.txt is missing
  if (!result.securityTxt.exists) {
    result.findings.push({
      type: 'missing_security_txt',
      severity: 'INFO',
      description: t.missingSecurityTxt,
    });
    console.log('[RobotsScanner] security.txt not found');
  }
  
  console.log(`[RobotsScanner] Scan complete - ${result.findings.length} findings`);
  
  return result;
}

/**
 * Convert robots scan result to vulnerabilities for the report
 * @param result - Robots scan result
 * @param lang - Language for descriptions
 * @returns Array of vulnerabilities
 */
export function robotsToVulnerabilities(
  result: RobotsScanResult,
  lang: 'tr' | 'en'
): any[] {
  const t = TRANSLATIONS[lang];
  const vulnerabilities: any[] = [];
  
  // Group sensitive path findings
  const sensitiveFindings = result.findings.filter(f => f.type !== 'missing_security_txt');
  
  if (sensitiveFindings.length > 0) {
    // Group by severity
    const mediumFindings = sensitiveFindings.filter(f => f.severity === 'MEDIUM');
    const lowFindings = sensitiveFindings.filter(f => f.severity === 'LOW');
    
    if (mediumFindings.length > 0) {
      vulnerabilities.push({
        id: 'VULN-ROBOTS-SENSITIVE-MEDIUM',
        title: t.vulnTitle,
        description: t.vulnDescription.replace('{count}', String(mediumFindings.length)),
        severity: lang === 'tr' ? 'Orta' : 'Medium',
        location: 'robots.txt',
        remediation: t.remediation,
        cvssScore: 5.3,
        exploitExample: `curl ${result.robotsTxt.sensitivePaths[0] || '/admin'}`,
        exploitablePaths: mediumFindings.map(f => ({
          description: f.path || f.type,
          scenario: f.description,
          impact: lang === 'tr' ? 'Hassas bilgi sızıntısı' : 'Sensitive information disclosure',
        })),
        relatedCves: ['CWE-200', 'CWE-538'],
        sensitivePaths: result.robotsTxt.sensitivePaths,
      });
    }
    
    if (lowFindings.length > 0) {
      vulnerabilities.push({
        id: 'VULN-ROBOTS-SENSITIVE-LOW',
        title: lang === 'tr' ? 'Robots.txt\'de Potansiyel Hassas Yollar' : 'Potential Sensitive Paths in Robots.txt',
        description: lang === 'tr' 
          ? `robots.txt dosyasında ${lowFindings.length} potansiyel hassas yol tespit edildi`
          : `${lowFindings.length} potential sensitive paths detected in robots.txt`,
        severity: lang === 'tr' ? 'Düşük' : 'Low',
        location: 'robots.txt',
        remediation: t.remediation,
        cvssScore: 3.1,
        exploitablePaths: lowFindings.map(f => ({
          description: f.path || f.type,
          scenario: f.description,
          impact: lang === 'tr' ? 'Bilgi ifşası' : 'Information disclosure',
        })),
        relatedCves: ['CWE-200'],
      });
    }
  }
  
  // Add security.txt missing finding
  const securityTxtMissing = result.findings.find(f => f.type === 'missing_security_txt');
  if (securityTxtMissing) {
    vulnerabilities.push({
      id: 'VULN-SECURITY-TXT-MISSING',
      title: t.securityTxtMissingTitle,
      description: t.securityTxtMissingDesc,
      severity: lang === 'tr' ? 'Bilgi' : 'Info',
      location: '/.well-known/security.txt',
      remediation: t.securityTxtRemediation,
      cvssScore: 0,
      exploitExample: 'N/A',
      exploitablePaths: [{
        description: 'security.txt',
        scenario: lang === 'tr' 
          ? 'Güvenlik araştırmacıları iletişim bilgisi bulamıyor'
          : 'Security researchers cannot find contact information',
        impact: lang === 'tr' 
          ? 'Güvenlik açıkları raporlanamayabilir'
          : 'Security vulnerabilities may not be reported',
      }],
      relatedCves: ['RFC-9116'],
    });
  }
  
  return vulnerabilities;
}
