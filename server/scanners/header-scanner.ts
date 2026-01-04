/**
 * HTTP Headers Scanner
 * Analyzes security headers and server information
 */

import axios from 'axios';
import { SECURITY_HEADERS_RULES } from '../utils/security-constants';

export interface HeaderAnalysis {
  key: string;
  value: string;
  status: 'SECURE' | 'MISSING' | 'WARNING' | 'INFO';
  description: string;
}

export interface CookieAnalysis {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  issues: string[];
  risk: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
}

/**
 * Scan HTTP headers for security configuration
 * @param url - The URL to analyze
 * @returns Array of header analysis results
 */
export async function scanHeaders(url: string): Promise<HeaderAnalysis[]> {
  const analysis: HeaderAnalysis[] = [];

  try {
    // Make HEAD request to get headers without downloading body
    const response = await axios.head(url, {
      timeout: 10000,
      validateStatus: () => true, // Accept any status code
      maxRedirects: 3,
    });

    const headers = response.headers;

    // Check security headers
    Object.entries(SECURITY_HEADERS_RULES).forEach(([headerKey, rule]) => {
      const value = headers[headerKey.toLowerCase()];

      if (!value) {
        analysis.push({
          key: headerKey,
          value: 'Missing',
          status: 'WARNING',
          description: rule.description,
        });
      } else {
        // Header exists - validate its value
        const isValid = validateHeaderValue(headerKey, value);

        analysis.push({
          key: headerKey,
          value: String(value),
          status: isValid ? 'SECURE' : 'WARNING',
          description: rule.description,
        });
      }
    });

    // Check for information disclosure headers
    const infoHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator'];

    infoHeaders.forEach((headerKey) => {
      const value = headers[headerKey];
      if (value) {
        analysis.push({
          key: headerKey.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('-'),
          value: String(value),
          status: 'INFO',
          description: 'Server information disclosure - reveals technology stack',
        });
      }
    });

    // Check cache-control
    const cacheControl = headers['cache-control'];
    if (cacheControl) {
      analysis.push({
        key: 'Cache-Control',
        value: String(cacheControl),
        status: 'INFO',
        description: 'Caching policy configuration',
      });
    }

  } catch (error: any) {
    // If HEAD fails, try GET with minimal data
    try {
      const response = await axios.get(url, {
        timeout: 10000,
        validateStatus: () => true,
        maxRedirects: 3,
        maxContentLength: 1024, // Only download first 1KB
      });

      const headers = response.headers;

      // Repeat security headers check
      Object.entries(SECURITY_HEADERS_RULES).forEach(([headerKey, rule]) => {
        const value = headers[headerKey.toLowerCase()];

        analysis.push({
          key: headerKey,
          value: value ? String(value) : 'Missing',
          status: value ? 'SECURE' : 'WARNING',
          description: rule.description,
        });
      });

    } catch (fallbackError: any) {
      throw new Error(`Headers scan failed: ${error.message}`);
    }
  }

  return analysis;
}

/**
 * Validate header value for common misconfigurations
 * @param headerKey - The header name
 * @param value - The header value
 * @returns true if valid, false otherwise
 */
function validateHeaderValue(headerKey: string, value: string): boolean {
  const lowerKey = headerKey.toLowerCase();
  const lowerValue = String(value).toLowerCase();

  switch (lowerKey) {
    case 'strict-transport-security':
      // Should have max-age
      return lowerValue.includes('max-age');

    case 'content-security-policy':
      // Should not be "none" or empty
      return lowerValue.length > 10 && !lowerValue.includes('unsafe-inline');

    case 'x-frame-options':
      // Should be DENY or SAMEORIGIN
      return lowerValue === 'deny' || lowerValue === 'sameorigin';

    case 'x-content-type-options':
      // Should be nosniff
      return lowerValue === 'nosniff';

    case 'referrer-policy':
      // Should have a policy set
      return lowerValue.length > 0;

    default:
      // For other headers, just check if they exist
      return true;
  }
}

/**
 * Analyze cookies for security flags
 * @param url - The URL to analyze
 * @returns Array of cookie analysis results
 */
export async function analyzeCookies(url: string): Promise<CookieAnalysis[]> {
  const results: CookieAnalysis[] = [];

  try {
    const response = await axios.get(url, {
      timeout: 10000,
      validateStatus: () => true,
      maxRedirects: 3,
    });

    // Get Set-Cookie headers
    const setCookieHeaders = response.headers['set-cookie'];

    if (!setCookieHeaders || !Array.isArray(setCookieHeaders)) {
      return results;
    }

    for (const cookieHeader of setCookieHeaders) {
      const analysis = parseCookie(cookieHeader);
      results.push(analysis);
    }
  } catch (error) {
    // Ignore errors
  }

  return results;
}

/**
 * Parse a single Set-Cookie header and analyze security
 */
function parseCookie(cookieHeader: string): CookieAnalysis {
  const parts = cookieHeader.split(';').map(p => p.trim());
  const [nameValue] = parts;
  const [name] = nameValue.split('=');

  const lowerHeader = cookieHeader.toLowerCase();

  const secure = lowerHeader.includes('secure');
  const httpOnly = lowerHeader.includes('httponly');

  let sameSite: string | null = null;
  const sameSiteMatch = lowerHeader.match(/samesite\s*=\s*(strict|lax|none)/i);
  if (sameSiteMatch) {
    sameSite = sameSiteMatch[1].toLowerCase();
  }

  const issues: string[] = [];

  // Check for session-like cookie names
  const isSessionCookie = /session|token|auth|jwt|sid|id$/i.test(name);

  if (!secure) {
    issues.push('Missing Secure flag - cookie can be sent over HTTP');
  }

  if (!httpOnly && isSessionCookie) {
    issues.push('Missing HttpOnly flag - cookie accessible via JavaScript (XSS risk)');
  }

  if (!sameSite) {
    issues.push('Missing SameSite attribute - vulnerable to CSRF');
  } else if (sameSite === 'none' && !secure) {
    issues.push('SameSite=None requires Secure flag');
  }

  // Determine risk level
  let risk: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' = 'NONE';

  if (isSessionCookie) {
    if (!secure && !httpOnly) {
      risk = 'HIGH';
    } else if (!secure || !httpOnly) {
      risk = 'MEDIUM';
    } else if (!sameSite) {
      risk = 'LOW';
    }
  } else {
    if (!secure) {
      risk = 'LOW';
    }
  }

  return {
    name,
    secure,
    httpOnly,
    sameSite,
    issues,
    risk,
  };
}

/**
 * Convert cookie analysis to vulnerabilities
 */
export function cookiesToVulnerabilities(
  cookies: CookieAnalysis[],
  lang: 'tr' | 'en'
): any[] {
  const vulnerabilities: any[] = [];

  const riskySessionCookies = cookies.filter(
    c => c.risk === 'HIGH' || c.risk === 'MEDIUM'
  );

  if (riskySessionCookies.length > 0) {
    const cookieNames = riskySessionCookies.map(c => c.name).join(', ');
    const allIssues = riskySessionCookies.flatMap(c => c.issues);

    vulnerabilities.push({
      id: 'VULN-COOKIE-1',
      title: lang === 'tr' ? 'Güvensiz Oturum Çerezleri' : 'Insecure Session Cookies',
      description: lang === 'tr'
        ? `Şu çerezlerde güvenlik sorunları tespit edildi: ${cookieNames}. Sorunlar: ${allIssues.join('; ')}`
        : `Security issues found in cookies: ${cookieNames}. Issues: ${allIssues.join('; ')}`,
      severity: riskySessionCookies.some(c => c.risk === 'HIGH') ? 'Yüksek' : 'Orta',
      location: 'Set-Cookie Headers',
      remediation: lang === 'tr'
        ? 'Tüm oturum çerezlerine Secure, HttpOnly ve SameSite=Strict flaglerini ekleyin.'
        : 'Add Secure, HttpOnly, and SameSite=Strict flags to all session cookies.',
      cvssScore: riskySessionCookies.some(c => c.risk === 'HIGH') ? 7.0 : 5.0,
      exploitExample: 'document.cookie // XSS ile çerez çalma',
      exploitablePaths: [{
        description: lang === 'tr' ? 'Session Hijacking' : 'Session Hijacking',
        scenario: lang === 'tr'
          ? 'XSS saldırısı ile oturum çerezi çalınabilir'
          : 'Session cookie can be stolen via XSS attack',
        impact: lang === 'tr' ? 'Hesap ele geçirme' : 'Account takeover',
      }],
      relatedCves: ['CWE-614', 'CWE-1004'],
    });
  }

  return vulnerabilities;
}
