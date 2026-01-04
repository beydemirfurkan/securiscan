/**
 * Active Security Scanner
 * Performs active security tests including:
 * - Sensitive file/directory discovery
 * - SQL Injection detection (error-based)
 * - XSS detection (reflected)
 * - Open redirect detection
 * - CORS misconfiguration
 */

import axios, { AxiosError } from 'axios';

// ==================== INTERFACES ====================

export interface ActiveScanResult {
  sensitiveFiles: SensitiveFileResult[];
  sqlInjection: SqlInjectionResult[];
  xss: XssResult[];
  openRedirect: OpenRedirectResult[];
  cors: CorsResult | null;
}

export interface SensitiveFileResult {
  path: string;
  type: 'config' | 'backup' | 'admin' | 'vcs' | 'debug' | 'api';
  status: number;
  accessible: boolean;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
}

export interface SqlInjectionResult {
  parameter: string;
  payload: string;
  detected: boolean;
  evidence: string;
  type: 'error-based' | 'boolean-based' | 'time-based';
}

export interface XssResult {
  parameter: string;
  payload: string;
  reflected: boolean;
  context: string;
}

export interface OpenRedirectResult {
  parameter: string;
  vulnerable: boolean;
  redirectedTo: string;
}

export interface CorsResult {
  allowOrigin: string | null;
  allowCredentials: boolean;
  vulnerable: boolean;
  issue: string;
}

// ==================== CONSTANTS ====================

// Sensitive files and directories to check
const SENSITIVE_PATHS = [
  // Version Control
  { path: '/.git/config', type: 'vcs' as const, risk: 'CRITICAL' as const, desc: 'Git repository exposed - source code leak' },
  { path: '/.git/HEAD', type: 'vcs' as const, risk: 'CRITICAL' as const, desc: 'Git repository exposed' },
  { path: '/.svn/entries', type: 'vcs' as const, risk: 'CRITICAL' as const, desc: 'SVN repository exposed' },
  { path: '/.hg/hgrc', type: 'vcs' as const, risk: 'HIGH' as const, desc: 'Mercurial repository exposed' },

  // Environment & Config
  { path: '/.env', type: 'config' as const, risk: 'CRITICAL' as const, desc: 'Environment file exposed - may contain secrets' },
  { path: '/.env.local', type: 'config' as const, risk: 'CRITICAL' as const, desc: 'Local environment file exposed' },
  { path: '/.env.production', type: 'config' as const, risk: 'CRITICAL' as const, desc: 'Production environment file exposed' },
  { path: '/config.php', type: 'config' as const, risk: 'HIGH' as const, desc: 'PHP configuration file exposed' },
  { path: '/config.json', type: 'config' as const, risk: 'HIGH' as const, desc: 'JSON configuration file exposed' },
  { path: '/settings.py', type: 'config' as const, risk: 'HIGH' as const, desc: 'Python settings file exposed' },
  { path: '/web.config', type: 'config' as const, risk: 'HIGH' as const, desc: 'IIS configuration file exposed' },
  { path: '/wp-config.php', type: 'config' as const, risk: 'CRITICAL' as const, desc: 'WordPress config with DB credentials' },
  { path: '/configuration.php', type: 'config' as const, risk: 'CRITICAL' as const, desc: 'Joomla configuration exposed' },

  // Backup Files
  { path: '/backup.sql', type: 'backup' as const, risk: 'CRITICAL' as const, desc: 'SQL backup file exposed' },
  { path: '/database.sql', type: 'backup' as const, risk: 'CRITICAL' as const, desc: 'Database dump exposed' },
  { path: '/db.sql', type: 'backup' as const, risk: 'CRITICAL' as const, desc: 'Database file exposed' },
  { path: '/backup.zip', type: 'backup' as const, risk: 'HIGH' as const, desc: 'Backup archive exposed' },
  { path: '/backup.tar.gz', type: 'backup' as const, risk: 'HIGH' as const, desc: 'Backup archive exposed' },
  { path: '/site.tar.gz', type: 'backup' as const, risk: 'HIGH' as const, desc: 'Site backup exposed' },

  // Admin Panels
  { path: '/admin', type: 'admin' as const, risk: 'MEDIUM' as const, desc: 'Admin panel found' },
  { path: '/admin/', type: 'admin' as const, risk: 'MEDIUM' as const, desc: 'Admin panel found' },
  { path: '/administrator', type: 'admin' as const, risk: 'MEDIUM' as const, desc: 'Administrator panel found' },
  { path: '/wp-admin/', type: 'admin' as const, risk: 'MEDIUM' as const, desc: 'WordPress admin panel' },
  { path: '/wp-login.php', type: 'admin' as const, risk: 'LOW' as const, desc: 'WordPress login page' },
  { path: '/phpmyadmin/', type: 'admin' as const, risk: 'HIGH' as const, desc: 'phpMyAdmin exposed' },
  { path: '/adminer.php', type: 'admin' as const, risk: 'HIGH' as const, desc: 'Adminer database tool exposed' },
  { path: '/cpanel', type: 'admin' as const, risk: 'HIGH' as const, desc: 'cPanel access found' },
  { path: '/manager/', type: 'admin' as const, risk: 'HIGH' as const, desc: 'Tomcat Manager exposed' },

  // Debug & Development
  { path: '/phpinfo.php', type: 'debug' as const, risk: 'MEDIUM' as const, desc: 'PHP info page exposed' },
  { path: '/info.php', type: 'debug' as const, risk: 'MEDIUM' as const, desc: 'PHP info page exposed' },
  { path: '/test.php', type: 'debug' as const, risk: 'LOW' as const, desc: 'Test file found' },
  { path: '/debug', type: 'debug' as const, risk: 'MEDIUM' as const, desc: 'Debug endpoint found' },
  { path: '/.DS_Store', type: 'debug' as const, risk: 'LOW' as const, desc: 'macOS metadata file' },
  { path: '/Thumbs.db', type: 'debug' as const, risk: 'LOW' as const, desc: 'Windows thumbnail cache' },
  { path: '/server-status', type: 'debug' as const, risk: 'MEDIUM' as const, desc: 'Apache server status exposed' },
  { path: '/nginx_status', type: 'debug' as const, risk: 'MEDIUM' as const, desc: 'Nginx status exposed' },

  // API & Documentation
  { path: '/api', type: 'api' as const, risk: 'LOW' as const, desc: 'API endpoint found' },
  { path: '/api/v1', type: 'api' as const, risk: 'LOW' as const, desc: 'API v1 endpoint' },
  { path: '/swagger.json', type: 'api' as const, risk: 'MEDIUM' as const, desc: 'Swagger API docs exposed' },
  { path: '/openapi.json', type: 'api' as const, risk: 'MEDIUM' as const, desc: 'OpenAPI spec exposed' },
  { path: '/graphql', type: 'api' as const, risk: 'MEDIUM' as const, desc: 'GraphQL endpoint found' },
  { path: '/.well-known/security.txt', type: 'api' as const, risk: 'LOW' as const, desc: 'Security contact info' },
  { path: '/robots.txt', type: 'api' as const, risk: 'LOW' as const, desc: 'Robots file (may reveal paths)' },
  { path: '/sitemap.xml', type: 'api' as const, risk: 'LOW' as const, desc: 'Sitemap found' },

  // Source Maps
  { path: '/main.js.map', type: 'debug' as const, risk: 'MEDIUM' as const, desc: 'JavaScript source map exposed' },
  { path: '/bundle.js.map', type: 'debug' as const, risk: 'MEDIUM' as const, desc: 'Bundle source map exposed' },
  { path: '/app.js.map', type: 'debug' as const, risk: 'MEDIUM' as const, desc: 'App source map exposed' },
];

// SQL Injection error patterns
const SQL_ERROR_PATTERNS = [
  /SQL syntax.*MySQL/i,
  /Warning.*mysql_/i,
  /MySqlException/i,
  /valid MySQL result/i,
  /PostgreSQL.*ERROR/i,
  /Warning.*pg_/i,
  /ORA-\d{5}/i,
  /Oracle.*Driver/i,
  /SQLite.*error/i,
  /SQLite3::/i,
  /ODBC.*Driver/i,
  /SQL Server.*Driver/i,
  /Microsoft OLE DB Provider/i,
  /Unclosed quotation mark/i,
  /quoted string not properly terminated/i,
  /syntax error at or near/i,
  /unexpected end of SQL command/i,
];

// SQL Injection payloads (safe, error-based)
const SQL_PAYLOADS = [
  "'",
  "\"",
  "' OR '1'='1",
  "1' OR '1'='1' --",
  "' OR 1=1 --",
  "\" OR 1=1 --",
  "1; SELECT 1",
  "1' AND '1'='1",
];

// XSS payloads (harmless, detection only)
const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>',
  '"><script>alert(1)</script>',
  "'-alert(1)-'",
  '<body onload=alert(1)>',
];

// ==================== MAIN SCANNER ====================

/**
 * Perform active security scan
 * @param url - Target URL to scan
 * @param lang - Language for descriptions
 * @returns Active scan results
 */
export async function performActiveScan(
  url: string,
  lang: 'tr' | 'en' = 'tr'
): Promise<ActiveScanResult> {
  console.log(`[ActiveScanner] Starting active scan for ${url}`);

  const baseUrl = new URL(url).origin;

  // Run all scans in parallel for speed
  const [sensitiveFiles, sqlInjection, xss, openRedirect, cors] = await Promise.all([
    scanSensitiveFiles(baseUrl),
    scanForSqlInjection(url),
    scanForXss(url),
    scanForOpenRedirect(url),
    scanForCorsMisconfiguration(url),
  ]);

  console.log(`[ActiveScanner] Scan complete - Found ${sensitiveFiles.filter(f => f.accessible).length} accessible files, ${sqlInjection.filter(s => s.detected).length} SQLi, ${xss.filter(x => x.reflected).length} XSS`);

  return {
    sensitiveFiles,
    sqlInjection,
    xss,
    openRedirect,
    cors,
  };
}

// ==================== SENSITIVE FILE SCANNER ====================

/**
 * Scan for sensitive files and directories
 */
async function scanSensitiveFiles(baseUrl: string): Promise<SensitiveFileResult[]> {
  const results: SensitiveFileResult[] = [];
  const batchSize = 10;

  // Process in batches to avoid overwhelming the server
  for (let i = 0; i < SENSITIVE_PATHS.length; i += batchSize) {
    const batch = SENSITIVE_PATHS.slice(i, i + batchSize);

    const batchResults = await Promise.all(
      batch.map(async (item) => {
        try {
          const fullUrl = `${baseUrl}${item.path}`;
          const response = await axios.head(fullUrl, {
            timeout: 5000,
            validateStatus: () => true,
            maxRedirects: 0,
          });

          const accessible = response.status === 200 || response.status === 403;

          return {
            path: item.path,
            type: item.type,
            status: response.status,
            accessible,
            risk: accessible ? item.risk : 'LOW' as const,
            description: accessible ? item.desc : `${item.desc} (not accessible)`,
          };
        } catch (error) {
          return {
            path: item.path,
            type: item.type,
            status: 0,
            accessible: false,
            risk: 'LOW' as const,
            description: 'Connection failed',
          };
        }
      })
    );

    // Only include accessible files or interesting status codes
    results.push(...batchResults.filter(r => r.accessible || r.status === 403));

    // Small delay between batches
    if (i + batchSize < SENSITIVE_PATHS.length) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  return results;
}

// ==================== SQL INJECTION SCANNER ====================

/**
 * Scan for SQL Injection vulnerabilities (error-based)
 */
async function scanForSqlInjection(url: string): Promise<SqlInjectionResult[]> {
  const results: SqlInjectionResult[] = [];
  const parsedUrl = new URL(url);

  // Check each query parameter
  const params = new URLSearchParams(parsedUrl.search);

  if (params.toString() === '') {
    // No parameters to test, try common parameter names
    const commonParams = ['id', 'page', 'user', 'search', 'q', 'query', 'cat', 'category'];

    for (const param of commonParams.slice(0, 3)) {
      for (const payload of SQL_PAYLOADS.slice(0, 3)) {
        const testUrl = new URL(url);
        testUrl.searchParams.set(param, payload);

        const result = await testSqlInjection(testUrl.toString(), param, payload);
        if (result.detected) {
          results.push(result);
          break; // Found vulnerability, no need to test more payloads
        }
      }
    }
  } else {
    // Test existing parameters
    for (const [param, originalValue] of params.entries()) {
      for (const payload of SQL_PAYLOADS) {
        const testUrl = new URL(url);
        testUrl.searchParams.set(param, payload);

        const result = await testSqlInjection(testUrl.toString(), param, payload);
        if (result.detected) {
          results.push(result);
          break; // Found vulnerability, no need to test more payloads
        }
      }
    }
  }

  return results;
}

/**
 * Test a single SQL injection payload
 */
async function testSqlInjection(
  testUrl: string,
  parameter: string,
  payload: string
): Promise<SqlInjectionResult> {
  try {
    const response = await axios.get(testUrl, {
      timeout: 10000,
      validateStatus: () => true,
      maxRedirects: 3,
    });

    const body = String(response.data);

    // Check for SQL error patterns
    for (const pattern of SQL_ERROR_PATTERNS) {
      const match = body.match(pattern);
      if (match) {
        return {
          parameter,
          payload,
          detected: true,
          evidence: match[0].substring(0, 100),
          type: 'error-based',
        };
      }
    }

    return {
      parameter,
      payload,
      detected: false,
      evidence: '',
      type: 'error-based',
    };
  } catch (error) {
    return {
      parameter,
      payload,
      detected: false,
      evidence: '',
      type: 'error-based',
    };
  }
}

// ==================== XSS SCANNER ====================

/**
 * Scan for reflected XSS vulnerabilities
 */
async function scanForXss(url: string): Promise<XssResult[]> {
  const results: XssResult[] = [];
  const parsedUrl = new URL(url);

  // Check each query parameter
  const params = new URLSearchParams(parsedUrl.search);

  const paramsToTest = params.toString() !== ''
    ? Array.from(params.keys())
    : ['q', 'search', 'query', 'name', 'input'];

  for (const param of paramsToTest.slice(0, 5)) {
    for (const payload of XSS_PAYLOADS.slice(0, 3)) {
      const testUrl = new URL(url);
      testUrl.searchParams.set(param, payload);

      try {
        const response = await axios.get(testUrl.toString(), {
          timeout: 10000,
          validateStatus: () => true,
          maxRedirects: 3,
        });

        const body = String(response.data);

        // Check if payload is reflected in response
        if (body.includes(payload)) {
          // Determine context
          let context = 'unknown';
          if (body.includes(`"${payload}"`) || body.includes(`'${payload}'`)) {
            context = 'attribute';
          } else if (body.includes(`>${payload}<`)) {
            context = 'html';
          } else if (body.includes(`<script>${payload}`)) {
            context = 'script';
          }

          results.push({
            parameter: param,
            payload,
            reflected: true,
            context,
          });
          break; // Found vulnerability, no need to test more payloads
        }
      } catch (error) {
        // Ignore errors
      }
    }
  }

  return results;
}

// ==================== OPEN REDIRECT SCANNER ====================

/**
 * Scan for open redirect vulnerabilities
 */
async function scanForOpenRedirect(url: string): Promise<OpenRedirectResult[]> {
  const results: OpenRedirectResult[] = [];
  const redirectParams = ['url', 'redirect', 'next', 'return', 'returnUrl', 'goto', 'dest', 'destination', 'redir', 'redirect_uri'];
  const evilUrl = 'https://evil.com/phishing';

  const parsedUrl = new URL(url);

  for (const param of redirectParams) {
    const testUrl = new URL(url);
    testUrl.searchParams.set(param, evilUrl);

    try {
      const response = await axios.get(testUrl.toString(), {
        timeout: 10000,
        validateStatus: () => true,
        maxRedirects: 0, // Don't follow redirects
      });

      const locationHeader = response.headers['location'];

      if (locationHeader && locationHeader.includes('evil.com')) {
        results.push({
          parameter: param,
          vulnerable: true,
          redirectedTo: locationHeader,
        });
      }
    } catch (error) {
      // Ignore errors
    }
  }

  return results;
}

// ==================== CORS SCANNER ====================

/**
 * Scan for CORS misconfiguration
 */
async function scanForCorsMisconfiguration(url: string): Promise<CorsResult | null> {
  try {
    // Test with evil origin
    const response = await axios.get(url, {
      timeout: 10000,
      validateStatus: () => true,
      headers: {
        'Origin': 'https://evil.com',
      },
    });

    const allowOrigin = response.headers['access-control-allow-origin'];
    const allowCredentials = response.headers['access-control-allow-credentials'] === 'true';

    if (!allowOrigin) {
      return null; // No CORS headers
    }

    let vulnerable = false;
    let issue = '';

    if (allowOrigin === '*') {
      vulnerable = true;
      issue = 'Wildcard origin allows any website to access resources';
    } else if (allowOrigin === 'https://evil.com') {
      vulnerable = true;
      issue = 'Origin is reflected without validation - any origin is accepted';

      if (allowCredentials) {
        issue += ' (with credentials - CRITICAL)';
      }
    } else if (allowOrigin === 'null') {
      vulnerable = true;
      issue = 'Null origin allowed - can be exploited via sandboxed iframes';
    }

    return {
      allowOrigin,
      allowCredentials,
      vulnerable,
      issue,
    };
  } catch (error) {
    return null;
  }
}

// ==================== HELPER FUNCTIONS ====================

/**
 * Convert active scan results to vulnerabilities
 */
export function convertToVulnerabilities(
  results: ActiveScanResult,
  lang: 'tr' | 'en'
): any[] {
  const vulnerabilities: any[] = [];

  // Sensitive files
  results.sensitiveFiles
    .filter(f => f.accessible && f.risk !== 'LOW')
    .forEach((file, index) => {
      vulnerabilities.push({
        id: `VULN-FILE-${index + 1}`,
        title: lang === 'tr' ? `Hassas Dosya Tespit Edildi: ${file.path}` : `Sensitive File Found: ${file.path}`,
        description: lang === 'tr'
          ? `${file.path} dosyası erişilebilir durumda. ${file.description}`
          : `${file.path} is accessible. ${file.description}`,
        severity: file.risk === 'CRITICAL' ? 'Kritik' : file.risk === 'HIGH' ? 'Yüksek' : 'Orta',
        location: file.path,
        remediation: lang === 'tr'
          ? 'Bu dosyayı web sunucusu yapılandırmasından engelleyin veya silin.'
          : 'Block this file in web server configuration or remove it.',
        cvssScore: file.risk === 'CRITICAL' ? 9.0 : file.risk === 'HIGH' ? 7.5 : 5.0,
        exploitExample: `curl -I ${file.path}`,
        exploitablePaths: [{
          description: lang === 'tr' ? 'Doğrudan Erişim' : 'Direct Access',
          scenario: lang === 'tr' ? 'Saldırgan bu dosyaya doğrudan erişebilir' : 'Attacker can directly access this file',
          impact: file.description,
        }],
        relatedCves: [],
      });
    });

  // SQL Injection
  results.sqlInjection
    .filter(s => s.detected)
    .forEach((sqli, index) => {
      vulnerabilities.push({
        id: `VULN-SQLI-${index + 1}`,
        title: lang === 'tr' ? 'SQL Injection Tespit Edildi' : 'SQL Injection Detected',
        description: lang === 'tr'
          ? `${sqli.parameter} parametresi SQL injection'a açık. Kanıt: ${sqli.evidence}`
          : `${sqli.parameter} parameter is vulnerable to SQL injection. Evidence: ${sqli.evidence}`,
        severity: 'Kritik',
        location: `Parameter: ${sqli.parameter}`,
        remediation: lang === 'tr'
          ? 'Parametreli sorgular (prepared statements) kullanın. Kullanıcı girdilerini asla doğrudan SQL sorgularına eklemeyin.'
          : 'Use parameterized queries (prepared statements). Never concatenate user input directly into SQL queries.',
        cvssScore: 9.8,
        exploitExample: `?${sqli.parameter}=${encodeURIComponent(sqli.payload)}`,
        exploitablePaths: [{
          description: lang === 'tr' ? 'Veritabanı Erişimi' : 'Database Access',
          scenario: lang === 'tr' ? 'Saldırgan veritabanını okuyabilir/değiştirebilir' : 'Attacker can read/modify database',
          impact: lang === 'tr' ? 'Tam veritabanı ele geçirme' : 'Full database compromise',
        }],
        relatedCves: ['CWE-89'],
      });
    });

  // XSS
  results.xss
    .filter(x => x.reflected)
    .forEach((xss, index) => {
      vulnerabilities.push({
        id: `VULN-XSS-${index + 1}`,
        title: lang === 'tr' ? 'Reflected XSS Tespit Edildi' : 'Reflected XSS Detected',
        description: lang === 'tr'
          ? `${xss.parameter} parametresi XSS'e açık. Payload ${xss.context} bağlamında yansıtılıyor.`
          : `${xss.parameter} parameter is vulnerable to XSS. Payload reflected in ${xss.context} context.`,
        severity: 'Yüksek',
        location: `Parameter: ${xss.parameter}`,
        remediation: lang === 'tr'
          ? 'Tüm kullanıcı girdilerini çıktı bağlamına göre encode edin. Content-Security-Policy başlığı kullanın.'
          : 'Encode all user input according to output context. Use Content-Security-Policy header.',
        cvssScore: 7.5,
        exploitExample: `?${xss.parameter}=${encodeURIComponent(xss.payload)}`,
        exploitablePaths: [{
          description: lang === 'tr' ? 'Session Hijacking' : 'Session Hijacking',
          scenario: lang === 'tr' ? 'Saldırgan kullanıcı oturumunu çalabilir' : 'Attacker can steal user sessions',
          impact: lang === 'tr' ? 'Hesap ele geçirme' : 'Account takeover',
        }],
        relatedCves: ['CWE-79'],
      });
    });

  // Open Redirect
  results.openRedirect
    .filter(r => r.vulnerable)
    .forEach((redirect, index) => {
      vulnerabilities.push({
        id: `VULN-REDIRECT-${index + 1}`,
        title: lang === 'tr' ? 'Open Redirect Tespit Edildi' : 'Open Redirect Detected',
        description: lang === 'tr'
          ? `${redirect.parameter} parametresi open redirect'e açık.`
          : `${redirect.parameter} parameter is vulnerable to open redirect.`,
        severity: 'Orta',
        location: `Parameter: ${redirect.parameter}`,
        remediation: lang === 'tr'
          ? 'Yönlendirme URL\'lerini whitelist ile doğrulayın. Harici URL\'lere yönlendirmeye izin vermeyin.'
          : 'Validate redirect URLs against a whitelist. Do not allow redirects to external URLs.',
        cvssScore: 5.5,
        exploitExample: `?${redirect.parameter}=https://evil.com`,
        exploitablePaths: [{
          description: lang === 'tr' ? 'Phishing' : 'Phishing',
          scenario: lang === 'tr' ? 'Saldırgan kullanıcıları sahte sitelere yönlendirebilir' : 'Attacker can redirect users to fake sites',
          impact: lang === 'tr' ? 'Kimlik bilgisi hırsızlığı' : 'Credential theft',
        }],
        relatedCves: ['CWE-601'],
      });
    });

  // CORS
  if (results.cors?.vulnerable) {
    vulnerabilities.push({
      id: 'VULN-CORS-1',
      title: lang === 'tr' ? 'CORS Yanlış Yapılandırması' : 'CORS Misconfiguration',
      description: lang === 'tr'
        ? `CORS politikası güvensiz. ${results.cors.issue}`
        : `CORS policy is insecure. ${results.cors.issue}`,
      severity: results.cors.allowCredentials ? 'Kritik' : 'Yüksek',
      location: 'Access-Control-Allow-Origin Header',
      remediation: lang === 'tr'
        ? 'Sadece güvenilen origin\'lere izin verin. Wildcard (*) kullanmayın.'
        : 'Only allow trusted origins. Do not use wildcard (*).',
      cvssScore: results.cors.allowCredentials ? 8.5 : 6.5,
      exploitExample: 'curl -H "Origin: https://evil.com" [TARGET]',
      exploitablePaths: [{
        description: lang === 'tr' ? 'Cross-Origin Data Theft' : 'Cross-Origin Data Theft',
        scenario: lang === 'tr' ? 'Kötü amaçlı site kullanıcı verilerini çalabilir' : 'Malicious site can steal user data',
        impact: lang === 'tr' ? 'Hassas veri sızıntısı' : 'Sensitive data leak',
      }],
      relatedCves: ['CWE-942'],
    });
  }

  return vulnerabilities;
}
