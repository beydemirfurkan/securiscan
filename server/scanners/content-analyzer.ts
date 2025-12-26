/**
 * Content Security Analyzer
 * Analyzes page content for security vulnerabilities:
 * - XSS vulnerabilities
 * - Form security
 * - Hardcoded secrets/API keys
 * - Outdated JavaScript libraries
 * - Insecure cookies
 * - CORS misconfigurations
 */

import axios from 'axios';
import { Vulnerability, Severity } from './vulnerability-detector';

export interface ContentAnalysisResult {
  hasXSSRisk: boolean;
  insecureForms: number;
  hardcodedSecrets: string[];
  outdatedLibraries: Array<{ name: string; version: string; latestVersion: string }>;
  insecureCookies: string[];
  corsMisconfig: boolean;
  mixedContent: boolean;
}

/**
 * Analyze page HTML content for security issues
 */
export async function analyzePageContent(url: string, lang: 'tr' | 'en'): Promise<{
  vulnerabilities: Vulnerability[];
  analysis: ContentAnalysisResult;
}> {
  const vulnerabilities: Vulnerability[] = [];
  const analysis: ContentAnalysisResult = {
    hasXSSRisk: false,
    insecureForms: 0,
    hardcodedSecrets: [],
    outdatedLibraries: [],
    insecureCookies: [],
    corsMisconfig: false,
    mixedContent: false,
  };

  try {
    // Fetch page HTML
    const response = await axios.get(url, {
      timeout: 15000,
      maxRedirects: 3,
      headers: {
        'User-Agent': 'SecuriScan-Bot/1.0',
      },
    });

    const html = response.data;
    const headers = response.headers;

    // 1. Check for XSS vulnerabilities
    const xssRisk = checkXSSRisk(html);
    if (xssRisk) {
      analysis.hasXSSRisk = true;
      vulnerabilities.push({
        id: 'VULN-CONTENT-XSS',
        title: lang === 'tr' ? 'Potansiyel XSS Riski Tespit Edildi' : 'Potential XSS Risk Detected',
        description: lang === 'tr'
          ? 'Sayfada kullanıcı girdilerinin yeterince sanitize edilmediğine dair işaretler bulundu. Bu XSS (Cross-Site Scripting) saldırılarına yol açabilir.'
          : 'Found indicators that user inputs are not properly sanitized on the page. This can lead to XSS (Cross-Site Scripting) attacks.',
        severity: Severity.HIGH,
        location: 'Page Content / JavaScript',
        remediation: lang === 'tr'
          ? 'Tüm kullanıcı girdilerini sanitize edin, innerHTML yerine textContent kullanın, CSP header ekleyin'
          : 'Sanitize all user inputs, use textContent instead of innerHTML, add CSP header',
        cvssScore: 7.5,
        exploitExample: '<script>alert(document.cookie)</script>',
        exploitablePaths: [
          {
            description: lang === 'tr' ? 'DOM-based XSS' : 'DOM-based XSS',
            scenario: lang === 'tr'
              ? 'Saldırgan URL parametreleri veya form girdileri aracılığıyla kötü amaçlı kod çalıştırabilir'
              : 'Attacker can execute malicious code via URL parameters or form inputs',
            impact: lang === 'tr' ? 'Kullanıcı oturumlarının çalınması, phishing' : 'User session theft, phishing',
          },
        ],
        relatedCves: [{ name: 'CWE-79' }],
      });
    }

    // 2. Check for insecure forms
    const insecureForms = checkInsecureForms(html, url);
    if (insecureForms > 0) {
      analysis.insecureForms = insecureForms;
      vulnerabilities.push({
        id: 'VULN-CONTENT-INSECURE-FORMS',
        title: lang === 'tr' ? `${insecureForms} Güvensiz Form Tespit Edildi` : `${insecureForms} Insecure Forms Detected`,
        description: lang === 'tr'
          ? `Sayfada ${insecureForms} adet HTTP üzerinden veri gönderen veya HTTPS olmayan action URL'li form bulundu.`
          : `Found ${insecureForms} forms sending data over HTTP or with non-HTTPS action URLs.`,
        severity: Severity.CRITICAL,
        location: 'HTML Forms',
        remediation: lang === 'tr'
          ? 'Tüm formları HTTPS üzerinden gönderin, hassas veriler için CSRF token kullanın'
          : 'Submit all forms over HTTPS, use CSRF tokens for sensitive data',
        cvssScore: 9.0,
        exploitExample: 'MITM attack on form submission',
        exploitablePaths: [
          {
            description: lang === 'tr' ? 'Form Verisi Ele Geçirme' : 'Form Data Interception',
            scenario: lang === 'tr'
              ? 'HTTP üzerinden gönderilen form verileri düz metin olarak ele geçirilebilir'
              : 'Form data sent over HTTP can be intercepted in plaintext',
            impact: lang === 'tr' ? 'Kullanıcı kimlik bilgileri, kredi kartı bilgileri çalınabilir' : 'User credentials, credit card info can be stolen',
          },
        ],
        relatedCves: [{ name: 'CWE-319' }],
      });
    }

    // 3. Check for hardcoded secrets
    const secrets = findHardcodedSecrets(html);
    if (secrets.length > 0) {
      analysis.hardcodedSecrets = secrets;
      vulnerabilities.push({
        id: 'VULN-CONTENT-HARDCODED-SECRETS',
        title: lang === 'tr' ? 'Hardcode Edilmiş API Anahtarları/Şifreler' : 'Hardcoded API Keys/Secrets',
        description: lang === 'tr'
          ? `Sayfa kaynak kodunda ${secrets.length} adet potansiyel API anahtarı veya şifre tespit edildi.`
          : `Found ${secrets.length} potential API keys or secrets in page source code.`,
        severity: Severity.CRITICAL,
        location: 'JavaScript / HTML Source',
        remediation: lang === 'tr'
          ? 'API anahtarlarını sunucu tarafında saklayın, environment variables kullanın, asla client-side kodda hardcode etmeyin'
          : 'Store API keys on server-side, use environment variables, never hardcode in client-side code',
        cvssScore: 9.5,
        exploitExample: 'View page source -> extract API key',
        exploitablePaths: [
          {
            description: lang === 'tr' ? 'API Anahtarı Çalınması' : 'API Key Theft',
            scenario: lang === 'tr'
              ? 'Herkes sayfa kaynağını görüntüleyerek API anahtarlarını çalabilir'
              : 'Anyone can view page source and steal API keys',
            impact: lang === 'tr' ? 'Yetkisiz API kullanımı, veri sızıntısı, maliyet artışı' : 'Unauthorized API usage, data breach, cost increase',
          },
        ],
        relatedCves: [{ name: 'CWE-798' }],
      });
    }

    // 4. Check for outdated JavaScript libraries
    const outdatedLibs = detectOutdatedLibraries(html);
    if (outdatedLibs.length > 0) {
      analysis.outdatedLibraries = outdatedLibs;
      vulnerabilities.push({
        id: 'VULN-CONTENT-OUTDATED-LIBS',
        title: lang === 'tr' ? 'Güncel Olmayan JavaScript Kütüphaneleri' : 'Outdated JavaScript Libraries',
        description: lang === 'tr'
          ? `${outdatedLibs.length} adet güncel olmayan veya güvenlik açığı içeren JavaScript kütüphanesi tespit edildi: ${outdatedLibs.map(l => l.name).join(', ')}`
          : `Found ${outdatedLibs.length} outdated or vulnerable JavaScript libraries: ${outdatedLibs.map(l => l.name).join(', ')}`,
        severity: Severity.MEDIUM,
        location: 'JavaScript Libraries',
        remediation: lang === 'tr'
          ? 'Tüm JavaScript kütüphanelerini en son güvenli versiyonlara güncelleyin'
          : 'Update all JavaScript libraries to latest secure versions',
        cvssScore: 6.0,
        exploitExample: 'Exploit known CVEs in outdated libraries',
        exploitablePaths: [],
        relatedCves: outdatedLibs.map(lib => ({ name: `${lib.name}@${lib.version} vulnerable` })),
      });
    }

    // 5. Check for mixed content
    const mixedContent = checkMixedContent(html, url);
    if (mixedContent) {
      analysis.mixedContent = true;
      vulnerabilities.push({
        id: 'VULN-CONTENT-MIXED',
        title: lang === 'tr' ? 'Mixed Content (Karışık İçerik)' : 'Mixed Content',
        description: lang === 'tr'
          ? 'HTTPS sayfası HTTP üzerinden kaynaklar (resim, script, stylesheet) yüklüyor. Bu MITM saldırılarına yol açabilir.'
          : 'HTTPS page loads resources (images, scripts, stylesheets) over HTTP. This can lead to MITM attacks.',
        severity: Severity.MEDIUM,
        location: 'Page Resources',
        remediation: lang === 'tr'
          ? 'Tüm kaynakları HTTPS üzerinden yükleyin veya protocol-relative URL kullanın (//example.com/...)'
          : 'Load all resources over HTTPS or use protocol-relative URLs (//example.com/...)',
        cvssScore: 5.5,
        exploitExample: 'Inject malicious code via HTTP resources',
        exploitablePaths: [],
        relatedCves: [{ name: 'CWE-311' }],
      });
    }

    // 6. Check for CORS misconfigurations
    const corsMisconfig = checkCORSMisconfig(headers);
    if (corsMisconfig) {
      analysis.corsMisconfig = true;
      vulnerabilities.push({
        id: 'VULN-CONTENT-CORS',
        title: lang === 'tr' ? 'CORS Yanlış Yapılandırması' : 'CORS Misconfiguration',
        description: lang === 'tr'
          ? 'Access-Control-Allow-Origin: * kullanılıyor. Bu, herhangi bir origin\'den isteklere izin verir ve güvenlik riski oluşturur.'
          : 'Using Access-Control-Allow-Origin: *. This allows requests from any origin and creates security risk.',
        severity: Severity.MEDIUM,
        location: 'HTTP Headers / CORS',
        remediation: lang === 'tr'
          ? 'Specific origin listesi kullanın, wildcard (*) yerine güvenilir domainleri belirtin'
          : 'Use specific origin list, specify trusted domains instead of wildcard (*)',
        cvssScore: 5.0,
        exploitExample: 'Cross-origin data theft',
        exploitablePaths: [],
        relatedCves: [{ name: 'CWE-942' }],
      });
    }
  } catch (error: any) {
    console.error('[ContentAnalyzer] Error:', error.message);
  }

  return { vulnerabilities, analysis };
}

/**
 * Check for potential XSS vulnerabilities
 */
function checkXSSRisk(html: string): boolean {
  // Check for dangerous patterns
  const xssPatterns = [
    /innerHTML\s*=/gi,
    /document\.write\(/gi,
    /eval\(/gi,
    /dangerouslySetInnerHTML/gi,
    /<script[^>]*>.*?document\.location/gi,
    /<script[^>]*>.*?window\.location/gi,
  ];

  return xssPatterns.some(pattern => pattern.test(html));
}

/**
 * Check for insecure forms (HTTP forms)
 */
function checkInsecureForms(html: string, pageUrl: string): number {
  const isHTTPS = pageUrl.startsWith('https://');
  let count = 0;

  // Find all forms
  const formRegex = /<form[^>]*>/gi;
  const forms = html.match(formRegex) || [];

  forms.forEach(formTag => {
    // Check if form action is HTTP (when page is HTTPS)
    if (isHTTPS && /action\s*=\s*["']http:\/\//i.test(formTag)) {
      count++;
    }
    // Check if form has no action and page is HTTP
    if (!isHTTPS && !/action\s*=/i.test(formTag)) {
      count++;
    }
  });

  return count;
}

/**
 * Find hardcoded secrets (API keys, tokens, passwords)
 */
function findHardcodedSecrets(html: string): string[] {
  const secrets: string[] = [];

  // Common secret patterns
  const secretPatterns = [
    { name: 'API Key', regex: /api[_-]?key['"]?\s*[:=]\s*['"]\w{20,}['"]/gi },
    { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
    { name: 'Google API Key', regex: /AIza[0-9A-Za-z\\-_]{35}/g },
    { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g },
    { name: 'Slack Token', regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}/g },
    { name: 'Private Key', regex: /-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----/g },
    { name: 'Authorization Header', regex: /authorization['"]?\s*:\s*['"]Bearer\s+\w{20,}['"]/gi },
  ];

  secretPatterns.forEach(({ name, regex }) => {
    const matches = html.match(regex);
    if (matches) {
      secrets.push(`${name} (${matches.length} occurrence${matches.length > 1 ? 's' : ''})`);
    }
  });

  return secrets;
}

/**
 * Detect outdated JavaScript libraries
 */
function detectOutdatedLibraries(html: string): Array<{ name: string; version: string; latestVersion: string }> {
  const outdated: Array<{ name: string; version: string; latestVersion: string }> = [];

  // Common library patterns and their known vulnerable versions
  const libraries = [
    { name: 'jQuery', pattern: /jquery[.-](\d+\.\d+\.\d+)/i, vulnerable: ['1.', '2.', '3.0', '3.1', '3.2', '3.3'], latest: '3.7.1' },
    { name: 'Angular', pattern: /angular[.-](\d+\.\d+\.\d+)/i, vulnerable: ['1.'], latest: '17.0.0' },
    { name: 'Bootstrap', pattern: /bootstrap[.-](\d+\.\d+\.\d+)/i, vulnerable: ['3.', '4.0', '4.1', '4.2', '4.3'], latest: '5.3.0' },
    { name: 'Lodash', pattern: /lodash[.-](\d+\.\d+\.\d+)/i, vulnerable: ['4.0', '4.1', '4.2', '4.3', '4.4', '4.5', '4.6', '4.7', '4.8', '4.9', '4.10', '4.11', '4.12', '4.13', '4.14', '4.15', '4.16'], latest: '4.17.21' },
  ];

  libraries.forEach(lib => {
    const match = html.match(lib.pattern);
    if (match && match[1]) {
      const version = match[1];
      const isVulnerable = lib.vulnerable.some(v => version.startsWith(v));
      if (isVulnerable) {
        outdated.push({
          name: lib.name,
          version,
          latestVersion: lib.latest,
        });
      }
    }
  });

  return outdated;
}

/**
 * Check for mixed content (HTTP resources on HTTPS page)
 */
function checkMixedContent(html: string, url: string): boolean {
  if (!url.startsWith('https://')) {
    return false; // Only applicable to HTTPS pages
  }

  // Check for HTTP resources
  const httpResourcePatterns = [
    /src\s*=\s*["']http:\/\//i,
    /href\s*=\s*["']http:\/\//i,
    /url\s*\(\s*["']?http:\/\//i,
  ];

  return httpResourcePatterns.some(pattern => pattern.test(html));
}

/**
 * Check for CORS misconfigurations
 */
function checkCORSMisconfig(headers: Record<string, any>): boolean {
  const corsHeader = headers['access-control-allow-origin'];
  return corsHeader === '*';
}
