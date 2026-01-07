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
  directoryTraversal: DirectoryTraversalResult[];
}

export interface DirectoryTraversalResult {
  vulnerable: boolean;
  payload: string;
  evidence: string;
  targetFile: string;
  parameter: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
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
  exploitUrl: string;
  severity: 'MEDIUM';
  payload: string;
}

export interface CorsResult {
  allowOrigin: string | null;
  allowCredentials: boolean;
  vulnerable: boolean;
  issue: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | null;
  testedOrigins: string[];
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

// Directory Traversal patterns
const TRAVERSAL_PATTERNS = [
  // Basic patterns
  '../',
  '..\\',
  // URL encoded
  '..%2f',
  '..%2F',
  '..%5c',
  '..%5C',
  // Double URL encoded
  '..%252f',
  '..%252F',
  '..%255c',
  '..%255C',
  // Unicode/UTF-8 encoded
  '..%c0%af',
  '..%c1%9c',
  // Null byte injection (for older systems)
  '../%00',
  '..\\%00',
  // Mixed encoding
  '....///',
  '....\\\\\\',
  // Overlong UTF-8
  '%2e%2e%2f',
  '%2e%2e/',
  '.%2e/',
];

// Target files for directory traversal detection
const TRAVERSAL_TARGET_FILES = [
  // Unix/Linux files
  {
    path: '/etc/passwd',
    indicators: ['root:x:', 'root:*:', 'daemon:', 'bin:', 'nobody:'],
    os: 'unix',
  },
  {
    path: '/etc/shadow',
    indicators: ['root:', '$1$', '$5$', '$6$', '$y$'],
    os: 'unix',
  },
  {
    path: '/etc/hosts',
    indicators: ['localhost', '127.0.0.1', '::1'],
    os: 'unix',
  },
  // Windows files
  {
    path: 'C:\\Windows\\win.ini',
    indicators: ['[fonts]', '[extensions]', '[mci extensions]', '[files]'],
    os: 'windows',
  },
  {
    path: 'C:\\Windows\\System32\\drivers\\etc\\hosts',
    indicators: ['localhost', '127.0.0.1'],
    os: 'windows',
  },
  {
    path: 'C:\\boot.ini',
    indicators: ['[boot loader]', '[operating systems]', 'multi(0)'],
    os: 'windows',
  },
  // Web config files
  {
    path: 'web.config',
    indicators: ['<configuration>', '<system.web>', '<connectionStrings>', '<?xml'],
    os: 'any',
  },
  {
    path: 'WEB-INF/web.xml',
    indicators: ['<web-app', '<servlet>', '<filter>', '<?xml'],
    os: 'any',
  },
];

// Common parameters that might be vulnerable to directory traversal
const TRAVERSAL_PARAMS = [
  'file', 'path', 'filepath', 'filename', 'doc', 'document', 'page', 'pg',
  'include', 'dir', 'directory', 'folder', 'root', 'template', 'tmpl',
  'load', 'read', 'download', 'content', 'view', 'show', 'display',
  'cat', 'action', 'board', 'date', 'detail', 'name', 'item', 'module',
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
  const [sensitiveFiles, sqlInjection, xss, openRedirect, cors, directoryTraversal] = await Promise.all([
    scanSensitiveFiles(baseUrl),
    scanForSqlInjection(url),
    scanForXss(url),
    scanForOpenRedirect(url),
    scanForCorsMisconfiguration(url),
    scanForDirectoryTraversal(url),
  ]);

  console.log(`[ActiveScanner] Scan complete - Found ${sensitiveFiles.filter(f => f.accessible).length} accessible files, ${sqlInjection.filter(s => s.detected).length} SQLi, ${xss.filter(x => x.reflected).length} XSS, ${directoryTraversal.filter(d => d.vulnerable).length} Dir Traversal`);

  return {
    sensitiveFiles,
    sqlInjection,
    xss,
    openRedirect,
    cors,
    directoryTraversal,
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

// Extended list of redirect parameters
const REDIRECT_PARAMS = [
  // Common redirect parameters
  'url', 'redirect', 'next', 'return', 'returnUrl', 'goto', 'dest', 'destination',
  'redir', 'redirect_uri', 'redirect_url', 'return_url', 'returnTo', 'return_to',
  // OAuth/SSO related
  'callback', 'callback_url', 'continue', 'continueTo', 'forward', 'forward_url',
  // Navigation related
  'target', 'to', 'out', 'view', 'link', 'linkurl', 'go', 'jump', 'jump_url',
  // Legacy/CMS related
  'uri', 'u', 'r', 'ref', 'referrer', 'site', 'html', 'page', 'feed',
  // Path-based
  'path', 'path_info', 'data', 'domain', 'host', 'location', 'checkout_url',
  // Action related
  'action', 'service', 'image_url', 'img_url', 'file', 'load', 'source',
];

// Test payloads for open redirect detection
const REDIRECT_PAYLOADS = [
  { payload: 'https://evil.com/phishing', type: 'direct' as const },
  { payload: '//evil.com/phishing', type: 'protocol-relative' as const },
  { payload: 'https:evil.com', type: 'malformed' as const },
  { payload: '////evil.com', type: 'multiple-slash' as const },
  { payload: 'https://evil.com%2f%2f', type: 'encoded' as const },
  { payload: 'https://evil.com@legitimate.com', type: 'at-sign' as const },
  { payload: 'https://legitimate.com.evil.com', type: 'subdomain-trick' as const },
];

/**
 * Generate exploit URL example for open redirect
 */
export function generateExploitUrl(baseUrl: string, parameter: string, payload: string): string {
  try {
    const url = new URL(baseUrl);
    url.searchParams.set(parameter, payload);
    return url.toString();
  } catch {
    return `${baseUrl}?${parameter}=${encodeURIComponent(payload)}`;
  }
}

/**
 * Scan for open redirect vulnerabilities with enhanced detection
 */
async function scanForOpenRedirect(url: string): Promise<OpenRedirectResult[]> {
  const results: OpenRedirectResult[] = [];
  const parsedUrl = new URL(url);
  const existingParams = Array.from(new URLSearchParams(parsedUrl.search).keys());
  
  // Test existing parameters first, then common redirect parameters
  const paramsToTest = [
    ...existingParams.filter(p => REDIRECT_PARAMS.includes(p.toLowerCase())),
    ...REDIRECT_PARAMS.slice(0, 20), // Limit to avoid too many requests
  ];
  
  // Remove duplicates
  const uniqueParams = [...new Set(paramsToTest)];

  for (const param of uniqueParams.slice(0, 15)) {
    for (const { payload, type } of REDIRECT_PAYLOADS) {
      const testUrl = new URL(url);
      testUrl.searchParams.set(param, payload);

      try {
        const response = await axios.get(testUrl.toString(), {
          timeout: 10000,
          validateStatus: () => true,
          maxRedirects: 0, // Don't follow redirects
        });

        const locationHeader = response.headers['location'];
        const statusCode = response.status;

        // Check for redirect status codes (3xx)
        if (statusCode >= 300 && statusCode < 400 && locationHeader) {
          // Check if the redirect goes to an external domain
          if (isExternalRedirect(locationHeader, parsedUrl.hostname)) {
            const exploitUrl = generateExploitUrl(url, param, payload);
            
            results.push({
              parameter: param,
              vulnerable: true,
              redirectedTo: locationHeader,
              exploitUrl,
              severity: 'MEDIUM',
              payload,
            });
            
            // Found vulnerability for this param, move to next param
            break;
          }
        }
      } catch (error) {
        // Ignore errors
      }
    }
  }

  return results;
}

/**
 * Check if a redirect URL points to an external domain
 */
function isExternalRedirect(redirectUrl: string, originalHostname: string): boolean {
  try {
    // Handle protocol-relative URLs
    const normalizedUrl = redirectUrl.startsWith('//') 
      ? `https:${redirectUrl}` 
      : redirectUrl;
    
    const redirectHostname = new URL(normalizedUrl).hostname;
    
    // Check if it's a different domain
    return redirectHostname !== originalHostname && 
           !redirectHostname.endsWith(`.${originalHostname}`);
  } catch {
    // If URL parsing fails, check for common external indicators
    return redirectUrl.includes('evil.com') || 
           redirectUrl.includes('attacker') ||
           redirectUrl.startsWith('//') ||
           redirectUrl.match(/^https?:\/\/[^/]*\.[^/]+/) !== null;
  }
}

// ==================== CORS SCANNER ====================

// CORS test origins for comprehensive testing
const CORS_TEST_ORIGINS = [
  { origin: 'https://evil.com', type: 'external' as const },
  { origin: 'null', type: 'null' as const },
  { origin: 'http://evil.com', type: 'scheme-variation' as const },
];

/**
 * Generate subdomain test origins based on target URL
 */
function generateSubdomainOrigins(targetUrl: string): { origin: string; type: 'subdomain' }[] {
  try {
    const url = new URL(targetUrl);
    const hostname = url.hostname;
    
    return [
      { origin: `https://evil.${hostname}`, type: 'subdomain' as const },
      { origin: `https://${hostname}.evil.com`, type: 'subdomain' as const },
      { origin: `https://sub.${hostname}`, type: 'subdomain' as const },
    ];
  } catch {
    return [];
  }
}

/**
 * Map CORS vulnerability to severity based on design requirements
 * - Wildcard origin (*) → HIGH severity
 * - Reflected origin with credentials → CRITICAL severity
 * - Reflected origin without credentials → HIGH severity
 * - Null origin allowed → MEDIUM severity
 */
export function mapCorsSeverity(
  allowOrigin: string | null,
  allowCredentials: boolean,
  originType: 'external' | 'null' | 'subdomain' | 'scheme-variation'
): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | null {
  if (!allowOrigin) return null;
  
  // Wildcard origin
  if (allowOrigin === '*') {
    return 'HIGH';
  }
  
  // Null origin
  if (allowOrigin === 'null' || originType === 'null') {
    return 'MEDIUM';
  }
  
  // Reflected origin (external, subdomain, or scheme variation)
  if (originType === 'external' || originType === 'subdomain' || originType === 'scheme-variation') {
    if (allowCredentials) {
      return 'CRITICAL';
    }
    return 'HIGH';
  }
  
  return null;
}

/**
 * Scan for CORS misconfiguration with enhanced testing
 */
async function scanForCorsMisconfiguration(url: string): Promise<CorsResult | null> {
  const testedOrigins: string[] = [];
  const subdomainOrigins = generateSubdomainOrigins(url);
  const allOrigins = [...CORS_TEST_ORIGINS, ...subdomainOrigins];
  
  let worstResult: CorsResult | null = null;
  let worstSeverityRank = 0;
  
  const severityRank: Record<string, number> = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
  };
  
  for (const testOrigin of allOrigins) {
    testedOrigins.push(testOrigin.origin);
    
    try {
      const response = await axios.get(url, {
        timeout: 10000,
        validateStatus: () => true,
        headers: {
          'Origin': testOrigin.origin,
        },
      });

      const allowOrigin = response.headers['access-control-allow-origin'];
      const allowCredentials = response.headers['access-control-allow-credentials'] === 'true';

      if (!allowOrigin) {
        continue; // No CORS headers for this origin
      }

      let vulnerable = false;
      let issue = '';
      let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | null = null;

      if (allowOrigin === '*') {
        vulnerable = true;
        issue = 'Wildcard origin (*) allows any website to access resources';
        severity = 'HIGH';
      } else if (allowOrigin === testOrigin.origin) {
        vulnerable = true;
        
        if (testOrigin.type === 'null') {
          issue = 'Null origin allowed - can be exploited via sandboxed iframes';
          severity = 'MEDIUM';
        } else if (testOrigin.type === 'subdomain') {
          issue = `Subdomain origin (${testOrigin.origin}) is accepted - potential subdomain takeover risk`;
          severity = allowCredentials ? 'CRITICAL' : 'HIGH';
        } else if (testOrigin.type === 'scheme-variation') {
          issue = `HTTP scheme variation accepted - downgrade attack possible`;
          severity = allowCredentials ? 'CRITICAL' : 'HIGH';
        } else {
          issue = 'Origin is reflected without validation - any origin is accepted';
          severity = allowCredentials ? 'CRITICAL' : 'HIGH';
        }

        if (allowCredentials) {
          issue += ' (with credentials - CRITICAL)';
        }
      } else if (allowOrigin === 'null') {
        vulnerable = true;
        issue = 'Null origin allowed - can be exploited via sandboxed iframes';
        severity = 'MEDIUM';
      }

      if (vulnerable && severity) {
        const currentRank = severityRank[severity] || 0;
        
        if (currentRank > worstSeverityRank) {
          worstSeverityRank = currentRank;
          worstResult = {
            allowOrigin,
            allowCredentials,
            vulnerable,
            issue,
            severity,
            testedOrigins: [...testedOrigins],
          };
        }
      }
    } catch (error) {
      // Ignore errors for individual origin tests
    }
  }

  // Return the worst result found, or null if no vulnerabilities
  if (worstResult) {
    worstResult.testedOrigins = testedOrigins;
    return worstResult;
  }
  
  return null;
}

// ==================== DIRECTORY TRAVERSAL SCANNER ====================

/**
 * Scan for directory traversal vulnerabilities
 * Tests various encoding patterns against common sensitive files
 */
async function scanForDirectoryTraversal(url: string): Promise<DirectoryTraversalResult[]> {
  const results: DirectoryTraversalResult[] = [];
  const parsedUrl = new URL(url);
  const params = new URLSearchParams(parsedUrl.search);

  // Determine which parameters to test
  const paramsToTest = params.toString() !== ''
    ? Array.from(params.keys())
    : TRAVERSAL_PARAMS.slice(0, 5); // Test common params if none exist

  // Test each parameter with traversal patterns
  for (const param of paramsToTest.slice(0, 5)) {
    for (const targetFile of TRAVERSAL_TARGET_FILES) {
      for (const pattern of TRAVERSAL_PATTERNS.slice(0, 8)) {
        // Build traversal payload with multiple depth levels
        const depths = [3, 5, 7, 10];
        
        for (const depth of depths) {
          const traversalPath = pattern.repeat(depth) + targetFile.path.replace(/^[A-Z]:\\/, '').replace(/\\/g, '/');
          const testUrl = new URL(url);
          testUrl.searchParams.set(param, traversalPath);

          const result = await testDirectoryTraversal(
            testUrl.toString(),
            param,
            traversalPath,
            targetFile
          );

          if (result.vulnerable) {
            results.push(result);
            // Found vulnerability for this param, move to next param
            break;
          }
        }

        // If we found a vulnerability, stop testing this param
        if (results.some(r => r.parameter === param && r.vulnerable)) {
          break;
        }
      }

      // If we found a vulnerability, stop testing this param
      if (results.some(r => r.parameter === param && r.vulnerable)) {
        break;
      }
    }
  }

  return results;
}

/**
 * Test a single directory traversal payload
 */
async function testDirectoryTraversal(
  testUrl: string,
  parameter: string,
  payload: string,
  targetFile: { path: string; indicators: string[]; os: string }
): Promise<DirectoryTraversalResult> {
  try {
    const response = await axios.get(testUrl, {
      timeout: 10000,
      validateStatus: () => true,
      maxRedirects: 3,
    });

    const body = String(response.data);

    // Check for sensitive file content indicators
    for (const indicator of targetFile.indicators) {
      if (body.includes(indicator)) {
        return {
          vulnerable: true,
          payload,
          evidence: extractEvidence(body, indicator),
          targetFile: targetFile.path,
          parameter,
          severity: 'CRITICAL',
        };
      }
    }

    return {
      vulnerable: false,
      payload,
      evidence: '',
      targetFile: targetFile.path,
      parameter,
      severity: 'LOW',
    };
  } catch (error) {
    return {
      vulnerable: false,
      payload,
      evidence: '',
      targetFile: targetFile.path,
      parameter,
      severity: 'LOW',
    };
  }
}

/**
 * Extract evidence snippet around the indicator
 */
function extractEvidence(body: string, indicator: string): string {
  const index = body.indexOf(indicator);
  if (index === -1) return '';
  
  const start = Math.max(0, index - 20);
  const end = Math.min(body.length, index + indicator.length + 50);
  return body.substring(start, end).replace(/\n/g, ' ').trim();
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
          ? `${redirect.parameter} parametresi open redirect'e açık. Yönlendirme hedefi: ${redirect.redirectedTo}`
          : `${redirect.parameter} parameter is vulnerable to open redirect. Redirect target: ${redirect.redirectedTo}`,
        severity: lang === 'tr' ? 'Orta' : 'Medium',
        location: `Parameter: ${redirect.parameter}`,
        remediation: lang === 'tr'
          ? 'Yönlendirme URL\'lerini whitelist ile doğrulayın. Harici URL\'lere yönlendirmeye izin vermeyin. Relative URL\'ler kullanın.'
          : 'Validate redirect URLs against a whitelist. Do not allow redirects to external URLs. Use relative URLs.',
        cvssScore: 5.5,
        exploitExample: redirect.exploitUrl,
        exploitablePaths: [{
          description: lang === 'tr' ? 'Phishing' : 'Phishing',
          scenario: lang === 'tr' ? 'Saldırgan kullanıcıları sahte sitelere yönlendirebilir' : 'Attacker can redirect users to fake sites',
          impact: lang === 'tr' ? 'Kimlik bilgisi hırsızlığı' : 'Credential theft',
        }],
        relatedCves: ['CWE-601'],
        payload: redirect.payload,
      });
    });

  // CORS
  if (results.cors?.vulnerable) {
    const corsSeverity = results.cors.severity || (results.cors.allowCredentials ? 'CRITICAL' : 'HIGH');
    const severityText = corsSeverity === 'CRITICAL' ? (lang === 'tr' ? 'Kritik' : 'Critical') :
                         corsSeverity === 'HIGH' ? (lang === 'tr' ? 'Yüksek' : 'High') :
                         corsSeverity === 'MEDIUM' ? (lang === 'tr' ? 'Orta' : 'Medium') :
                         (lang === 'tr' ? 'Düşük' : 'Low');
    
    const cvssScore = corsSeverity === 'CRITICAL' ? 9.1 :
                      corsSeverity === 'HIGH' ? 7.5 :
                      corsSeverity === 'MEDIUM' ? 5.3 : 3.1;
    
    vulnerabilities.push({
      id: 'VULN-CORS-1',
      title: lang === 'tr' ? 'CORS Yanlış Yapılandırması' : 'CORS Misconfiguration',
      description: lang === 'tr'
        ? `CORS politikası güvensiz. ${results.cors.issue}`
        : `CORS policy is insecure. ${results.cors.issue}`,
      severity: severityText,
      location: 'Access-Control-Allow-Origin Header',
      remediation: lang === 'tr'
        ? 'Sadece güvenilen origin\'lere izin verin. Wildcard (*) kullanmayın. Credentials ile birlikte wildcard kullanmayın.'
        : 'Only allow trusted origins. Do not use wildcard (*). Never use wildcard with credentials.',
      cvssScore,
      exploitExample: 'curl -H "Origin: https://evil.com" [TARGET]',
      exploitablePaths: [{
        description: lang === 'tr' ? 'Cross-Origin Data Theft' : 'Cross-Origin Data Theft',
        scenario: lang === 'tr' ? 'Kötü amaçlı site kullanıcı verilerini çalabilir' : 'Malicious site can steal user data',
        impact: lang === 'tr' ? 'Hassas veri sızıntısı' : 'Sensitive data leak',
      }],
      relatedCves: ['CWE-942'],
      testedOrigins: results.cors.testedOrigins,
    });
  }

  // Directory Traversal
  results.directoryTraversal
    .filter(d => d.vulnerable)
    .forEach((traversal, index) => {
      vulnerabilities.push({
        id: `VULN-TRAVERSAL-${index + 1}`,
        title: lang === 'tr' ? 'Directory Traversal Tespit Edildi' : 'Directory Traversal Detected',
        description: lang === 'tr'
          ? `${traversal.parameter} parametresi directory traversal'a açık. Hedef dosya: ${traversal.targetFile}. Kanıt: ${traversal.evidence}`
          : `${traversal.parameter} parameter is vulnerable to directory traversal. Target file: ${traversal.targetFile}. Evidence: ${traversal.evidence}`,
        severity: 'Kritik',
        location: `Parameter: ${traversal.parameter}`,
        remediation: lang === 'tr'
          ? 'Kullanıcı girdilerini dosya yollarında kullanmayın. Whitelist yaklaşımı kullanın. Dosya erişimini chroot veya sandbox ile sınırlayın.'
          : 'Do not use user input in file paths. Use whitelist approach. Restrict file access with chroot or sandbox.',
        cvssScore: 9.1,
        exploitExample: `?${traversal.parameter}=${encodeURIComponent(traversal.payload)}`,
        exploitablePaths: [{
          description: lang === 'tr' ? 'Hassas Dosya Okuma' : 'Sensitive File Read',
          scenario: lang === 'tr' ? 'Saldırgan sunucudaki hassas dosyaları okuyabilir' : 'Attacker can read sensitive files on the server',
          impact: lang === 'tr' ? 'Sistem bilgisi sızıntısı, kimlik bilgisi hırsızlığı' : 'System information leak, credential theft',
        }],
        relatedCves: ['CWE-22', 'CWE-23'],
      });
    });

  return vulnerabilities;
}

// ==================== EXPORTS FOR TESTING ====================

export {
  TRAVERSAL_PATTERNS,
  TRAVERSAL_TARGET_FILES,
  TRAVERSAL_PARAMS,
  extractEvidence,
  CORS_TEST_ORIGINS,
  generateSubdomainOrigins,
  REDIRECT_PARAMS,
  REDIRECT_PAYLOADS,
};
