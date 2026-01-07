/**
 * Property-Based Tests for HTTP Methods Scanner
 * 
 * Feature: enhanced-security-scanner, Property 7: HTTP Methods Vulnerability Mapping
 * Validates: Requirements 6.2, 6.3, 6.4
 * 
 * Property 7: HTTP Methods Vulnerability Mapping
 * For any set of enabled HTTP methods:
 * - PUT enabled → HIGH severity
 * - DELETE enabled → HIGH severity
 * - TRACE enabled → MEDIUM severity (XST risk)
 * - The vulnerability details should include the complete list of enabled methods.
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  mapMethodToSeverity,
  parseAllowHeader,
  httpMethodsToVulnerabilities,
  HttpMethodsResult,
  DANGEROUS_METHODS,
} from './http-methods-scanner';

// Minimum 100 iterations as per design requirements
const testConfig = { numRuns: 100 };

describe('HTTP Methods Scanner - Property Tests', () => {
  /**
   * Feature: enhanced-security-scanner, Property 7: HTTP Methods Vulnerability Mapping
   * Validates: Requirements 6.2, 6.3, 6.4
   * 
   * For any set of enabled HTTP methods:
   * - PUT enabled → HIGH severity
   * - DELETE enabled → HIGH severity
   * - TRACE enabled → MEDIUM severity (XST risk)
   * - The vulnerability details should include the complete list of enabled methods.
   */
  describe('Property 7: HTTP Methods Vulnerability Mapping', () => {

    it('PUT method should always map to HIGH severity', () => {
      fc.assert(
        fc.property(
          fc.constant('PUT'),
          (method) => {
            const severity = mapMethodToSeverity(method);
            expect(severity).toBe('HIGH');
          }
        ),
        testConfig
      );
    });

    it('DELETE method should always map to HIGH severity', () => {
      fc.assert(
        fc.property(
          fc.constant('DELETE'),
          (method) => {
            const severity = mapMethodToSeverity(method);
            expect(severity).toBe('HIGH');
          }
        ),
        testConfig
      );
    });

    it('TRACE method should always map to MEDIUM severity', () => {
      fc.assert(
        fc.property(
          fc.constant('TRACE'),
          (method) => {
            const severity = mapMethodToSeverity(method);
            expect(severity).toBe('MEDIUM');
          }
        ),
        testConfig
      );
    });

    it('For any combination of dangerous methods, severity mapping should be consistent', () => {
      const dangerousMethodsArb = fc.subarray(['PUT', 'DELETE', 'TRACE'], { minLength: 1 });

      fc.assert(
        fc.property(dangerousMethodsArb, (methods) => {
          for (const method of methods) {
            const severity = mapMethodToSeverity(method);
            expect(severity).not.toBeNull();
            
            if (method === 'PUT' || method === 'DELETE') {
              expect(severity).toBe('HIGH');
            } else if (method === 'TRACE') {
              expect(severity).toBe('MEDIUM');
            }
          }
        }),
        testConfig
      );
    });

    it('Safe methods should return null severity', () => {
      const safeMethods = ['GET', 'POST', 'HEAD', 'OPTIONS', 'PATCH'];
      
      fc.assert(
        fc.property(
          fc.constantFrom(...safeMethods),
          (method) => {
            const severity = mapMethodToSeverity(method);
            expect(severity).toBeNull();
          }
        ),
        testConfig
      );
    });

    it('Vulnerability details should include all enabled methods', () => {
      const allMethodsArb = fc.subarray(
        ['GET', 'POST', 'PUT', 'DELETE', 'TRACE', 'OPTIONS', 'HEAD', 'PATCH'],
        { minLength: 1 }
      );
      const langArb = fc.constantFrom('tr' as const, 'en' as const);

      fc.assert(
        fc.property(allMethodsArb, langArb, (methods, lang) => {
          const dangerousMethods = methods.filter(m => DANGEROUS_METHODS[m]);
          
          const result: HttpMethodsResult = {
            allowedMethods: methods,
            dangerousMethods,
            vulnerabilities: dangerousMethods.map(m => ({
              method: m,
              severity: DANGEROUS_METHODS[m].severity,
              description: `${m} method enabled`,
              risk: DANGEROUS_METHODS[m].risk,
            })),
          };

          const vulns = httpMethodsToVulnerabilities(result, lang);

          // If there are dangerous methods, vulnerabilities should be generated
          if (dangerousMethods.length > 0) {
            expect(vulns.length).toBeGreaterThan(0);
            
            // Each vulnerability should include the enabled methods list
            for (const vuln of vulns) {
              expect(vuln.enabledMethods).toBeDefined();
              expect(vuln.enabledMethods).toEqual(methods);
            }
          } else {
            // No dangerous methods = no vulnerabilities
            expect(vulns.length).toBe(0);
          }
        }),
        testConfig
      );
    });

    it('HIGH severity methods should generate HIGH severity vulnerabilities', () => {
      const highSeverityMethodsArb = fc.subarray(['PUT', 'DELETE'], { minLength: 1 });
      const langArb = fc.constantFrom('tr' as const, 'en' as const);

      fc.assert(
        fc.property(highSeverityMethodsArb, langArb, (methods, lang) => {
          const result: HttpMethodsResult = {
            allowedMethods: methods,
            dangerousMethods: methods,
            vulnerabilities: methods.map(m => ({
              method: m,
              severity: DANGEROUS_METHODS[m].severity,
              description: `${m} method enabled`,
              risk: DANGEROUS_METHODS[m].risk,
            })),
          };

          const vulns = httpMethodsToVulnerabilities(result, lang);
          
          // Should have at least one HIGH severity vulnerability
          const highVuln = vulns.find(v => v.id === 'VULN-HTTP-METHODS-HIGH');
          expect(highVuln).toBeDefined();
          expect(highVuln?.severity).toBe(lang === 'tr' ? 'Yüksek' : 'High');
        }),
        testConfig
      );
    });

    it('TRACE method should generate MEDIUM severity vulnerability', () => {
      const langArb = fc.constantFrom('tr' as const, 'en' as const);

      fc.assert(
        fc.property(langArb, (lang) => {
          const result: HttpMethodsResult = {
            allowedMethods: ['GET', 'TRACE'],
            dangerousMethods: ['TRACE'],
            vulnerabilities: [{
              method: 'TRACE',
              severity: 'MEDIUM',
              description: 'TRACE method enabled',
              risk: DANGEROUS_METHODS['TRACE'].risk,
            }],
          };

          const vulns = httpMethodsToVulnerabilities(result, lang);
          
          // Should have MEDIUM severity vulnerability for TRACE
          const mediumVuln = vulns.find(v => v.id === 'VULN-HTTP-METHODS-MEDIUM');
          expect(mediumVuln).toBeDefined();
          expect(mediumVuln?.severity).toBe(lang === 'tr' ? 'Orta' : 'Medium');
        }),
        testConfig
      );
    });
  });

  describe('parseAllowHeader', () => {
    it('should parse comma-separated methods correctly', () => {
      const methodsArb = fc.subarray(
        ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE'],
        { minLength: 1 }
      );

      fc.assert(
        fc.property(methodsArb, (methods) => {
          const headerValue = methods.join(', ');
          const parsed = parseAllowHeader(headerValue);
          
          // All input methods should be in the parsed result
          for (const method of methods) {
            expect(parsed).toContain(method);
          }
        }),
        testConfig
      );
    });

    it('should handle various whitespace formats', () => {
      const methodsArb = fc.subarray(['GET', 'POST', 'PUT'], { minLength: 1 });
      const separatorArb = fc.constantFrom(', ', ',', ' , ', ',  ');

      fc.assert(
        fc.property(methodsArb, separatorArb, (methods, separator) => {
          const headerValue = methods.join(separator);
          const parsed = parseAllowHeader(headerValue);
          
          // Should parse all methods regardless of whitespace
          for (const method of methods) {
            expect(parsed).toContain(method);
          }
        }),
        testConfig
      );
    });

    it('should convert methods to uppercase', () => {
      const methodsArb = fc.subarray(['get', 'post', 'put', 'delete'], { minLength: 1 });

      fc.assert(
        fc.property(methodsArb, (methods) => {
          const headerValue = methods.join(', ');
          const parsed = parseAllowHeader(headerValue);
          
          // All parsed methods should be uppercase
          for (const method of parsed) {
            expect(method).toBe(method.toUpperCase());
          }
        }),
        testConfig
      );
    });
  });
});
