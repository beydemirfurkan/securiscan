/**
 * HTTP Methods Scanner
 * Detects enabled HTTP methods and identifies dangerous ones
 * 
 * Dangerous methods:
 * - PUT: Can upload files to server (HIGH severity)
 * - DELETE: Can delete resources (HIGH severity)
 * - TRACE: Can enable XST attacks (MEDIUM severity)
 */

import axios from 'axios';

// ==================== INTERFACES ====================

export interface HttpMethodsResult {
  allowedMethods: string[];
  dangerousMethods: string[];
  vulnerabilities: MethodVulnerability[];
}

export interface MethodVulnerability {
  method: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  risk: string;
}

// ==================== CONSTANTS ====================

/**
 * Dangerous HTTP methods and their severity mappings
 */
export const DANGEROUS_METHODS: Record<string, { severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'; risk: string }> = {
  PUT: {
    severity: 'HIGH',
    risk: 'Allows uploading files to the server, potentially enabling code execution',
  },
  DELETE: {
    severity: 'HIGH',
    risk: 'Allows deleting resources on the server, potentially causing data loss',
  },
  TRACE: {
    severity: 'MEDIUM',
    risk: 'Enables Cross-Site Tracing (XST) attacks, can steal cookies and credentials',
  },
};

/**
 * All HTTP methods to check
 */
const ALL_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT'];

// ==================== TRANSLATIONS ====================

const TRANSLATIONS = {
  tr: {
    PUT: {
      description: 'PUT metodu aktif - Sunucuya dosya yükleme riski',
      risk: 'Sunucuya dosya yüklenebilir, potansiyel kod çalıştırma riski',
    },
    DELETE: {
      description: 'DELETE metodu aktif - Kaynak silme riski',
      risk: 'Sunucudaki kaynaklar silinebilir, veri kaybı riski',
    },
    TRACE: {
      description: 'TRACE metodu aktif - XST saldırı riski',
      risk: 'Cross-Site Tracing (XST) saldırıları ile çerez ve kimlik bilgileri çalınabilir',
    },
    vulnTitle: 'Tehlikeli HTTP Metodu Tespit Edildi',
    vulnDescription: 'Sunucuda tehlikeli HTTP metodları aktif: {methods}',
    remediation: 'Web sunucu yapılandırmasında tehlikeli HTTP metodlarını devre dışı bırakın',
  },
  en: {
    PUT: {
      description: 'PUT method enabled - File upload risk',
      risk: 'Allows uploading files to the server, potentially enabling code execution',
    },
    DELETE: {
      description: 'DELETE method enabled - Resource deletion risk',
      risk: 'Allows deleting resources on the server, potentially causing data loss',
    },
    TRACE: {
      description: 'TRACE method enabled - XST attack risk',
      risk: 'Enables Cross-Site Tracing (XST) attacks, can steal cookies and credentials',
    },
    vulnTitle: 'Dangerous HTTP Method Detected',
    vulnDescription: 'Dangerous HTTP methods enabled on server: {methods}',
    remediation: 'Disable dangerous HTTP methods in web server configuration',
  },
};

// ==================== MAIN SCANNER ====================

/**
 * Scan for enabled HTTP methods using OPTIONS request
 * @param url - Target URL to scan
 * @param lang - Language for descriptions
 * @returns HTTP methods scan result
 */
export async function scanHttpMethods(
  url: string,
  lang: 'tr' | 'en' = 'en'
): Promise<HttpMethodsResult> {
  console.log(`[HttpMethodsScanner] Scanning HTTP methods for ${url}`);

  const allowedMethods: string[] = [];
  const dangerousMethods: string[] = [];
  const vulnerabilities: MethodVulnerability[] = [];

  try {
    // First, try OPTIONS request to get allowed methods
    const optionsResponse = await axios.options(url, {
      timeout: 5000,
      validateStatus: () => true,
      maxRedirects: 3,
    });

    // Check Allow header
    const allowHeader = optionsResponse.headers['allow'];
    if (allowHeader) {
      const methods = parseAllowHeader(allowHeader);
      allowedMethods.push(...methods);
    }

    // Check Access-Control-Allow-Methods header (for CORS)
    const corsAllowMethods = optionsResponse.headers['access-control-allow-methods'];
    if (corsAllowMethods) {
      const methods = parseAllowHeader(corsAllowMethods);
      methods.forEach(m => {
        if (!allowedMethods.includes(m)) {
          allowedMethods.push(m);
        }
      });
    }

    // If no Allow header, probe individual methods
    if (allowedMethods.length === 0) {
      const probedMethods = await probeHttpMethods(url);
      allowedMethods.push(...probedMethods);
    }

    // Identify dangerous methods
    for (const method of allowedMethods) {
      const upperMethod = method.toUpperCase();
      if (DANGEROUS_METHODS[upperMethod]) {
        dangerousMethods.push(upperMethod);
        
        const t = TRANSLATIONS[lang][upperMethod as keyof typeof TRANSLATIONS['en']];
        const methodInfo = DANGEROUS_METHODS[upperMethod];
        
        vulnerabilities.push({
          method: upperMethod,
          severity: methodInfo.severity,
          description: typeof t === 'object' && 'description' in t ? t.description : methodInfo.risk,
          risk: typeof t === 'object' && 'risk' in t ? t.risk : methodInfo.risk,
        });
      }
    }

    console.log(`[HttpMethodsScanner] Found ${allowedMethods.length} methods, ${dangerousMethods.length} dangerous`);

  } catch (error: any) {
    console.error(`[HttpMethodsScanner] Error scanning: ${error.message}`);
    // Try probing as fallback
    try {
      const probedMethods = await probeHttpMethods(url);
      allowedMethods.push(...probedMethods);
      
      for (const method of probedMethods) {
        const upperMethod = method.toUpperCase();
        if (DANGEROUS_METHODS[upperMethod]) {
          dangerousMethods.push(upperMethod);
          
          const t = TRANSLATIONS[lang][upperMethod as keyof typeof TRANSLATIONS['en']];
          const methodInfo = DANGEROUS_METHODS[upperMethod];
          
          vulnerabilities.push({
            method: upperMethod,
            severity: methodInfo.severity,
            description: typeof t === 'object' && 'description' in t ? t.description : methodInfo.risk,
            risk: typeof t === 'object' && 'risk' in t ? t.risk : methodInfo.risk,
          });
        }
      }
    } catch (probeError) {
      console.error(`[HttpMethodsScanner] Probe fallback also failed`);
    }
  }

  return {
    allowedMethods,
    dangerousMethods,
    vulnerabilities,
  };
}

/**
 * Parse Allow header value into array of methods
 */
export function parseAllowHeader(allowHeader: string): string[] {
  return allowHeader
    .split(',')
    .map(m => m.trim().toUpperCase())
    .filter(m => m.length > 0 && ALL_METHODS.includes(m));
}

/**
 * Probe individual HTTP methods when OPTIONS doesn't return Allow header
 */
async function probeHttpMethods(url: string): Promise<string[]> {
  const enabledMethods: string[] = [];
  const methodsToProbe = ['GET', 'POST', 'PUT', 'DELETE', 'TRACE', 'OPTIONS'];

  for (const method of methodsToProbe) {
    try {
      const response = await axios.request({
        method: method as any,
        url,
        timeout: 5000,
        validateStatus: () => true,
        maxRedirects: 0,
        // Don't send body for methods that don't need it
        data: ['PUT', 'POST', 'PATCH'].includes(method) ? '' : undefined,
      });

      // Method is enabled if we don't get 405 Method Not Allowed
      if (response.status !== 405 && response.status !== 501) {
        enabledMethods.push(method);
      }
    } catch (error) {
      // Ignore errors - method likely not supported
    }
  }

  return enabledMethods;
}

/**
 * Map dangerous methods to severity
 * This is a pure function for property-based testing
 */
export function mapMethodToSeverity(method: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | null {
  const upperMethod = method.toUpperCase();
  if (DANGEROUS_METHODS[upperMethod]) {
    return DANGEROUS_METHODS[upperMethod].severity;
  }
  return null;
}

/**
 * Convert HTTP methods scan result to vulnerabilities for the report
 */
export function httpMethodsToVulnerabilities(
  result: HttpMethodsResult,
  lang: 'tr' | 'en'
): any[] {
  if (result.dangerousMethods.length === 0) {
    return [];
  }

  const t = TRANSLATIONS[lang];
  const vulnerabilities: any[] = [];

  // Group vulnerabilities by severity
  const highSeverityMethods = result.dangerousMethods.filter(
    m => DANGEROUS_METHODS[m]?.severity === 'HIGH'
  );
  const mediumSeverityMethods = result.dangerousMethods.filter(
    m => DANGEROUS_METHODS[m]?.severity === 'MEDIUM'
  );

  // Create vulnerability for HIGH severity methods (PUT, DELETE)
  if (highSeverityMethods.length > 0) {
    vulnerabilities.push({
      id: 'VULN-HTTP-METHODS-HIGH',
      title: lang === 'tr' 
        ? `Tehlikeli HTTP Metodları: ${highSeverityMethods.join(', ')}`
        : `Dangerous HTTP Methods: ${highSeverityMethods.join(', ')}`,
      description: t.vulnDescription.replace('{methods}', highSeverityMethods.join(', ')),
      severity: lang === 'tr' ? 'Yüksek' : 'High',
      location: 'HTTP Methods',
      remediation: t.remediation,
      cvssScore: 7.5,
      exploitExample: `curl -X ${highSeverityMethods[0]} [TARGET_URL]`,
      exploitablePaths: highSeverityMethods.map(method => ({
        description: method,
        scenario: result.vulnerabilities.find(v => v.method === method)?.risk || '',
        impact: lang === 'tr' ? 'Yetkisiz erişim veya veri kaybı' : 'Unauthorized access or data loss',
      })),
      relatedCves: ['CWE-749'],
      enabledMethods: result.allowedMethods,
    });
  }

  // Create vulnerability for MEDIUM severity methods (TRACE)
  if (mediumSeverityMethods.length > 0) {
    vulnerabilities.push({
      id: 'VULN-HTTP-METHODS-MEDIUM',
      title: lang === 'tr'
        ? `XST Saldırı Riski: TRACE Metodu Aktif`
        : `XST Attack Risk: TRACE Method Enabled`,
      description: result.vulnerabilities.find(v => v.method === 'TRACE')?.description || '',
      severity: lang === 'tr' ? 'Orta' : 'Medium',
      location: 'HTTP Methods',
      remediation: lang === 'tr'
        ? 'TRACE metodunu web sunucu yapılandırmasında devre dışı bırakın'
        : 'Disable TRACE method in web server configuration',
      cvssScore: 5.0,
      exploitExample: 'curl -X TRACE [TARGET_URL]',
      exploitablePaths: [{
        description: 'Cross-Site Tracing (XST)',
        scenario: result.vulnerabilities.find(v => v.method === 'TRACE')?.risk || '',
        impact: lang === 'tr' ? 'Çerez ve kimlik bilgisi hırsızlığı' : 'Cookie and credential theft',
      }],
      relatedCves: ['CWE-693'],
      enabledMethods: result.allowedMethods,
    });
  }

  return vulnerabilities;
}
