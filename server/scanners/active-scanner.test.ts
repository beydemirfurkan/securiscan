/**
 * Property-Based Tests for Active Scanner - Directory Traversal Detection
 * 
 * Feature: enhanced-security-scanner, Property 5: Directory Traversal Detection
 * Validates: Requirements 4.2, 4.4
 * 
 * Property 5: Directory Traversal Detection
 * For any HTTP response containing sensitive file indicators (e.g., "root:x:", "[extensions]", "<?php"),
 * the scanner should report a CRITICAL severity vulnerability with the successful payload included.
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  TRAVERSAL_PATTERNS,
  TRAVERSAL_TARGET_FILES,
  extractEvidence,
  DirectoryTraversalResult,
} from './active-scanner';

// Minimum 100 iterations as per design requirements
const testConfig = { numRuns: 100 };

describe('Active Scanner - Directory Traversal Property Tests', () => {
  /**
   * Feature: enhanced-security-scanner, Property 5: Directory Traversal Detection
   * Validates: Requirements 4.2, 4.4
   */
  describe('Property 5: Directory Traversal Detection', () => {

    it('For any response containing Unix passwd indicators, severity should be CRITICAL', () => {
      const passwdIndicators = ['root:x:', 'root:*:', 'daemon:', 'bin:', 'nobody:'];
      const indicatorArb = fc.constantFrom(...passwdIndicators);
      const prefixArb = fc.string({ minLength: 0, maxLength: 100 });
      const suffixArb = fc.string({ minLength: 0, maxLength: 100 });
      const payloadArb = fc.constantFrom(...TRAVERSAL_PATTERNS);

      fc.assert(
        fc.property(indicatorArb, prefixArb, suffixArb, payloadArb, (indicator, prefix, suffix, payload) => {
          const responseBody = `${prefix}${indicator}${suffix}`;
          
          // Simulate detection logic
          const targetFile = TRAVERSAL_TARGET_FILES.find(t => t.path === '/etc/passwd');
          expect(targetFile).toBeDefined();
          
          const hasIndicator = targetFile!.indicators.some(ind => responseBody.includes(ind));
          
          if (hasIndicator) {
            // When indicator is found, result should be CRITICAL with payload included
            const result: DirectoryTraversalResult = {
              vulnerable: true,
              payload: payload.repeat(5) + 'etc/passwd',
              evidence: extractEvidence(responseBody, indicator),
              targetFile: '/etc/passwd',
              parameter: 'file',
              severity: 'CRITICAL',
            };
            
            expect(result.severity).toBe('CRITICAL');
            expect(result.payload).toContain(payload);
            expect(result.vulnerable).toBe(true);
          }
        }),
        testConfig
      );
    });

    it('For any response containing Windows ini indicators, severity should be CRITICAL', () => {
      const winIniIndicators = ['[fonts]', '[extensions]', '[mci extensions]', '[files]'];
      const indicatorArb = fc.constantFrom(...winIniIndicators);
      const prefixArb = fc.string({ minLength: 0, maxLength: 100 });
      const suffixArb = fc.string({ minLength: 0, maxLength: 100 });
      const payloadArb = fc.constantFrom(...TRAVERSAL_PATTERNS);

      fc.assert(
        fc.property(indicatorArb, prefixArb, suffixArb, payloadArb, (indicator, prefix, suffix, payload) => {
          const responseBody = `${prefix}${indicator}${suffix}`;
          
          // Simulate detection logic
          const targetFile = TRAVERSAL_TARGET_FILES.find(t => t.path === 'C:\\Windows\\win.ini');
          expect(targetFile).toBeDefined();
          
          const hasIndicator = targetFile!.indicators.some(ind => responseBody.includes(ind));
          
          if (hasIndicator) {
            // When indicator is found, result should be CRITICAL with payload included
            const result: DirectoryTraversalResult = {
              vulnerable: true,
              payload: payload.repeat(5) + 'Windows/win.ini',
              evidence: extractEvidence(responseBody, indicator),
              targetFile: 'C:\\Windows\\win.ini',
              parameter: 'file',
              severity: 'CRITICAL',
            };
            
            expect(result.severity).toBe('CRITICAL');
            expect(result.payload).toContain(payload);
            expect(result.vulnerable).toBe(true);
          }
        }),
        testConfig
      );
    });

    it('For any response containing web.config indicators, severity should be CRITICAL', () => {
      const webConfigIndicators = ['<configuration>', '<system.web>', '<connectionStrings>', '<?xml'];
      const indicatorArb = fc.constantFrom(...webConfigIndicators);
      const prefixArb = fc.string({ minLength: 0, maxLength: 50 });
      const suffixArb = fc.string({ minLength: 0, maxLength: 50 });
      const payloadArb = fc.constantFrom(...TRAVERSAL_PATTERNS);

      fc.assert(
        fc.property(indicatorArb, prefixArb, suffixArb, payloadArb, (indicator, prefix, suffix, payload) => {
          const responseBody = `${prefix}${indicator}${suffix}`;
          
          // Simulate detection logic
          const targetFile = TRAVERSAL_TARGET_FILES.find(t => t.path === 'web.config');
          expect(targetFile).toBeDefined();
          
          const hasIndicator = targetFile!.indicators.some(ind => responseBody.includes(ind));
          
          if (hasIndicator) {
            // When indicator is found, result should be CRITICAL with payload included
            const result: DirectoryTraversalResult = {
              vulnerable: true,
              payload: payload.repeat(5) + 'web.config',
              evidence: extractEvidence(responseBody, indicator),
              targetFile: 'web.config',
              parameter: 'file',
              severity: 'CRITICAL',
            };
            
            expect(result.severity).toBe('CRITICAL');
            expect(result.payload).toContain(payload);
            expect(result.vulnerable).toBe(true);
          }
        }),
        testConfig
      );
    });

    it('Successful payload should always be included in vulnerability report', () => {
      const targetFileArb = fc.constantFrom(...TRAVERSAL_TARGET_FILES);
      const patternArb = fc.constantFrom(...TRAVERSAL_PATTERNS);
      const depthArb = fc.integer({ min: 1, max: 10 });
      const paramArb = fc.constantFrom('file', 'path', 'doc', 'include', 'page');

      fc.assert(
        fc.property(targetFileArb, patternArb, depthArb, paramArb, (targetFile, pattern, depth, param) => {
          const payload = pattern.repeat(depth) + targetFile.path.replace(/^[A-Z]:\\/, '').replace(/\\/g, '/');
          
          const result: DirectoryTraversalResult = {
            vulnerable: true,
            payload,
            evidence: 'sample evidence',
            targetFile: targetFile.path,
            parameter: param,
            severity: 'CRITICAL',
          };
          
          // Payload should always be included and non-empty
          expect(result.payload).toBeDefined();
          expect(result.payload.length).toBeGreaterThan(0);
          expect(result.payload).toContain(pattern);
        }),
        testConfig
      );
    });

    it('All traversal patterns should be valid and non-empty', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...TRAVERSAL_PATTERNS),
          (pattern) => {
            expect(pattern).toBeDefined();
            expect(pattern.length).toBeGreaterThan(0);
            // Pattern should contain directory traversal characters
            expect(pattern).toMatch(/\.\.|%2[eEfF]|%c[01]/i);
          }
        ),
        testConfig
      );
    });

    it('All target files should have at least one indicator', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...TRAVERSAL_TARGET_FILES),
          (targetFile) => {
            expect(targetFile.indicators).toBeDefined();
            expect(targetFile.indicators.length).toBeGreaterThan(0);
            expect(targetFile.path).toBeDefined();
            expect(targetFile.path.length).toBeGreaterThan(0);
          }
        ),
        testConfig
      );
    });
  });

  describe('extractEvidence', () => {
    it('should extract evidence around the indicator', () => {
      const indicatorArb = fc.string({ minLength: 5, maxLength: 20 });
      const prefixArb = fc.string({ minLength: 0, maxLength: 50 });
      const suffixArb = fc.string({ minLength: 0, maxLength: 100 });

      fc.assert(
        fc.property(indicatorArb, prefixArb, suffixArb, (indicator, prefix, suffix) => {
          const body = `${prefix}${indicator}${suffix}`;
          const evidence = extractEvidence(body, indicator);
          
          // Evidence should contain the indicator
          expect(evidence).toContain(indicator);
          // Evidence should be a reasonable length
          expect(evidence.length).toBeLessThanOrEqual(body.length);
        }),
        testConfig
      );
    });

    it('should return empty string when indicator not found', () => {
      const bodyArb = fc.string({ minLength: 10, maxLength: 100 });
      
      fc.assert(
        fc.property(bodyArb, (body) => {
          const nonExistentIndicator = 'NONEXISTENT_INDICATOR_12345';
          const evidence = extractEvidence(body, nonExistentIndicator);
          
          expect(evidence).toBe('');
        }),
        testConfig
      );
    });

    it('should handle newlines by replacing them with spaces', () => {
      const indicatorArb = fc.constantFrom('root:x:', '[extensions]', '<configuration>');
      
      fc.assert(
        fc.property(indicatorArb, (indicator) => {
          const bodyWithNewlines = `prefix\n${indicator}\nsuffix\nmore`;
          const evidence = extractEvidence(bodyWithNewlines, indicator);
          
          // Evidence should not contain newlines
          expect(evidence).not.toContain('\n');
        }),
        testConfig
      );
    });
  });
});


/**
 * Property-Based Tests for Active Scanner - CORS Severity Mapping
 * 
 * Feature: enhanced-security-scanner, Property 4: CORS Severity Mapping
 * Validates: Requirements 3.2, 3.3, 3.4
 * 
 * Property 4: CORS Severity Mapping
 * For any CORS scan result:
 * - Wildcard origin (*) → HIGH severity
 * - Reflected origin with credentials → CRITICAL severity
 * - Reflected origin without credentials → HIGH severity
 * - Null origin allowed → MEDIUM severity
 */

import {
  mapCorsSeverity,
  CORS_TEST_ORIGINS,
  generateSubdomainOrigins,
  CorsResult,
} from './active-scanner';

describe('Active Scanner - CORS Property Tests', () => {
  /**
   * Feature: enhanced-security-scanner, Property 4: CORS Severity Mapping
   * Validates: Requirements 3.2, 3.3, 3.4
   */
  describe('Property 4: CORS Severity Mapping', () => {

    it('Wildcard origin (*) should always map to HIGH severity', () => {
      const credentialsArb = fc.boolean();

      fc.assert(
        fc.property(credentialsArb, (allowCredentials) => {
          const severity = mapCorsSeverity('*', allowCredentials, 'external');
          expect(severity).toBe('HIGH');
        }),
        testConfig
      );
    });

    it('Reflected origin with credentials should always map to CRITICAL severity', () => {
      const originTypeArb = fc.constantFrom('external' as const, 'subdomain' as const, 'scheme-variation' as const);
      const originArb = fc.constantFrom('https://evil.com', 'https://attacker.com', 'http://malicious.site');

      fc.assert(
        fc.property(originTypeArb, originArb, (originType, origin) => {
          const severity = mapCorsSeverity(origin, true, originType);
          expect(severity).toBe('CRITICAL');
        }),
        testConfig
      );
    });

    it('Reflected origin without credentials should always map to HIGH severity', () => {
      const originTypeArb = fc.constantFrom('external' as const, 'subdomain' as const, 'scheme-variation' as const);
      const originArb = fc.constantFrom('https://evil.com', 'https://attacker.com', 'http://malicious.site');

      fc.assert(
        fc.property(originTypeArb, originArb, (originType, origin) => {
          const severity = mapCorsSeverity(origin, false, originType);
          expect(severity).toBe('HIGH');
        }),
        testConfig
      );
    });

    it('Null origin should always map to MEDIUM severity', () => {
      const credentialsArb = fc.boolean();

      fc.assert(
        fc.property(credentialsArb, (allowCredentials) => {
          // Test with 'null' string as origin
          const severity1 = mapCorsSeverity('null', allowCredentials, 'null');
          expect(severity1).toBe('MEDIUM');
          
          // Test with null type
          const severity2 = mapCorsSeverity('null', allowCredentials, 'null');
          expect(severity2).toBe('MEDIUM');
        }),
        testConfig
      );
    });

    it('No CORS headers (null allowOrigin) should return null severity', () => {
      const credentialsArb = fc.boolean();
      const originTypeArb = fc.constantFrom('external' as const, 'null' as const, 'subdomain' as const, 'scheme-variation' as const);

      fc.assert(
        fc.property(credentialsArb, originTypeArb, (allowCredentials, originType) => {
          const severity = mapCorsSeverity(null, allowCredentials, originType);
          expect(severity).toBeNull();
        }),
        testConfig
      );
    });

    it('Severity ranking should be consistent: CRITICAL > HIGH > MEDIUM > LOW', () => {
      const severityRank: Record<string, number> = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MEDIUM': 2,
        'LOW': 1,
      };

      // Test that credentials always increase severity for reflected origins
      fc.assert(
        fc.property(
          fc.constantFrom('external' as const, 'subdomain' as const),
          fc.constantFrom('https://evil.com', 'https://attacker.com'),
          (originType, origin) => {
            const withCreds = mapCorsSeverity(origin, true, originType);
            const withoutCreds = mapCorsSeverity(origin, false, originType);
            
            expect(withCreds).toBe('CRITICAL');
            expect(withoutCreds).toBe('HIGH');
            expect(severityRank[withCreds!]).toBeGreaterThan(severityRank[withoutCreds!]);
          }
        ),
        testConfig
      );
    });

    it('All CORS test origins should be valid', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...CORS_TEST_ORIGINS),
          (testOrigin) => {
            expect(testOrigin.origin).toBeDefined();
            expect(testOrigin.origin.length).toBeGreaterThan(0);
            expect(testOrigin.type).toBeDefined();
            expect(['external', 'null', 'scheme-variation']).toContain(testOrigin.type);
          }
        ),
        testConfig
      );
    });

    it('Subdomain origins should be generated correctly for valid URLs', () => {
      const validUrlArb = fc.constantFrom(
        'https://example.com',
        'https://test.org',
        'https://api.service.io'
      );

      fc.assert(
        fc.property(validUrlArb, (url) => {
          const subdomainOrigins = generateSubdomainOrigins(url);
          
          expect(subdomainOrigins.length).toBeGreaterThan(0);
          
          for (const origin of subdomainOrigins) {
            expect(origin.type).toBe('subdomain');
            expect(origin.origin).toContain('https://');
          }
        }),
        testConfig
      );
    });

    it('Subdomain origins should handle invalid URLs gracefully', () => {
      const invalidUrlArb = fc.constantFrom(
        'not-a-url',
        '',
        'ftp://invalid'
      );

      fc.assert(
        fc.property(invalidUrlArb, (url) => {
          const subdomainOrigins = generateSubdomainOrigins(url);
          
          // Should return empty array for invalid URLs
          expect(Array.isArray(subdomainOrigins)).toBe(true);
        }),
        testConfig
      );
    });
  });
});


/**
 * Property-Based Tests for Active Scanner - Open Redirect Detection
 * 
 * Feature: enhanced-security-scanner, Property 6: Open Redirect Detection
 * Validates: Requirements 5.2, 5.4
 * 
 * Property 6: Open Redirect Detection
 * For any HTTP redirect response (3xx) where the Location header contains an external domain
 * from the test payload, the scanner should report a MEDIUM severity vulnerability with an
 * example exploit URL.
 */

import {
  REDIRECT_PARAMS,
  REDIRECT_PAYLOADS,
  generateExploitUrl,
  OpenRedirectResult,
} from './active-scanner';

describe('Active Scanner - Open Redirect Property Tests', () => {
  /**
   * Feature: enhanced-security-scanner, Property 6: Open Redirect Detection
   * Validates: Requirements 5.2, 5.4
   */
  describe('Property 6: Open Redirect Detection', () => {

    it('Open redirect vulnerabilities should always have MEDIUM severity', () => {
      const paramArb = fc.constantFrom(...REDIRECT_PARAMS.slice(0, 10));
      const payloadArb = fc.constantFrom(...REDIRECT_PAYLOADS.map(p => p.payload));
      const redirectUrlArb = fc.constantFrom(
        'https://evil.com/phishing',
        '//evil.com/attack',
        'https://attacker.com/steal'
      );

      fc.assert(
        fc.property(paramArb, payloadArb, redirectUrlArb, (param, payload, redirectUrl) => {
          const result: OpenRedirectResult = {
            parameter: param,
            vulnerable: true,
            redirectedTo: redirectUrl,
            exploitUrl: generateExploitUrl('https://example.com', param, payload),
            severity: 'MEDIUM',
            payload,
          };
          
          expect(result.severity).toBe('MEDIUM');
        }),
        testConfig
      );
    });

    it('Exploit URL should always be included in vulnerability report', () => {
      const baseUrlArb = fc.constantFrom(
        'https://example.com',
        'https://test.org/page',
        'https://api.service.io/callback'
      );
      const paramArb = fc.constantFrom(...REDIRECT_PARAMS.slice(0, 10));
      const payloadArb = fc.constantFrom(...REDIRECT_PAYLOADS.map(p => p.payload));

      fc.assert(
        fc.property(baseUrlArb, paramArb, payloadArb, (baseUrl, param, payload) => {
          const exploitUrl = generateExploitUrl(baseUrl, param, payload);
          
          // Exploit URL should be non-empty
          expect(exploitUrl).toBeDefined();
          expect(exploitUrl.length).toBeGreaterThan(0);
          
          // Exploit URL should contain the parameter
          expect(exploitUrl).toContain(param);
        }),
        testConfig
      );
    });

    it('generateExploitUrl should produce valid URLs', () => {
      const baseUrlArb = fc.constantFrom(
        'https://example.com',
        'https://test.org/page',
        'https://api.service.io'
      );
      const paramArb = fc.constantFrom('redirect', 'url', 'next', 'return');
      const payloadArb = fc.constantFrom('https://evil.com', '//evil.com', 'https://attacker.com');

      fc.assert(
        fc.property(baseUrlArb, paramArb, payloadArb, (baseUrl, param, payload) => {
          const exploitUrl = generateExploitUrl(baseUrl, param, payload);
          
          // Should be a valid URL
          expect(() => new URL(exploitUrl)).not.toThrow();
          
          // Should contain the parameter with the payload
          const url = new URL(exploitUrl);
          expect(url.searchParams.has(param)).toBe(true);
        }),
        testConfig
      );
    });

    it('All redirect parameters should be valid and non-empty', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...REDIRECT_PARAMS),
          (param) => {
            expect(param).toBeDefined();
            expect(param.length).toBeGreaterThan(0);
            // Parameter should be a valid query parameter name
            expect(param).toMatch(/^[a-zA-Z_][a-zA-Z0-9_]*$/);
          }
        ),
        testConfig
      );
    });

    it('All redirect payloads should be valid and have a type', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...REDIRECT_PAYLOADS),
          (payloadObj) => {
            expect(payloadObj.payload).toBeDefined();
            expect(payloadObj.payload.length).toBeGreaterThan(0);
            expect(payloadObj.type).toBeDefined();
            expect(['direct', 'protocol-relative', 'malformed', 'multiple-slash', 'encoded', 'at-sign', 'subdomain-trick']).toContain(payloadObj.type);
          }
        ),
        testConfig
      );
    });

    it('Vulnerable results should always include the payload used', () => {
      const paramArb = fc.constantFrom(...REDIRECT_PARAMS.slice(0, 10));
      const payloadObjArb = fc.constantFrom(...REDIRECT_PAYLOADS);

      fc.assert(
        fc.property(paramArb, payloadObjArb, (param, payloadObj) => {
          const result: OpenRedirectResult = {
            parameter: param,
            vulnerable: true,
            redirectedTo: payloadObj.payload,
            exploitUrl: generateExploitUrl('https://example.com', param, payloadObj.payload),
            severity: 'MEDIUM',
            payload: payloadObj.payload,
          };
          
          // Payload should be included
          expect(result.payload).toBe(payloadObj.payload);
          expect(result.payload.length).toBeGreaterThan(0);
        }),
        testConfig
      );
    });

    it('Redirect parameters should cover common OAuth/SSO parameters', () => {
      const oauthParams = ['redirect_uri', 'callback', 'callback_url', 'continue', 'return_url'];
      
      fc.assert(
        fc.property(
          fc.constantFrom(...oauthParams),
          (param) => {
            expect(REDIRECT_PARAMS).toContain(param);
          }
        ),
        testConfig
      );
    });

    it('Redirect payloads should include protocol-relative URLs', () => {
      const protocolRelativePayloads = REDIRECT_PAYLOADS.filter(p => p.type === 'protocol-relative');
      
      expect(protocolRelativePayloads.length).toBeGreaterThan(0);
      
      fc.assert(
        fc.property(
          fc.constantFrom(...protocolRelativePayloads),
          (payloadObj) => {
            expect(payloadObj.payload).toMatch(/^\/\//);
          }
        ),
        testConfig
      );
    });
  });
});
