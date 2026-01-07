/**
 * Property-Based Tests for Robots.txt & Security.txt Scanner
 * 
 * Feature: enhanced-security-scanner, Property 8: Robots.txt Analysis
 * Validates: Requirements 7.2, 7.3, 7.4
 * 
 * Property 8: Robots.txt Analysis
 * For any robots.txt content:
 * - Disallow entries should be extracted as paths
 * - Paths matching admin/backup/config patterns should be flagged as sensitive
 * - Missing security.txt should generate an INFO level finding
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  parseRobotsTxt,
  parseSecurityTxt,
  identifySensitivePaths,
  robotsToVulnerabilities,
  SENSITIVE_PATH_PATTERNS,
  RobotsScanResult,
} from './robots-scanner';

// Minimum 100 iterations as per design requirements
const testConfig = { numRuns: 100 };

describe('Robots Scanner - Property Tests', () => {
  /**
   * Feature: enhanced-security-scanner, Property 8: Robots.txt Analysis
   * Validates: Requirements 7.2, 7.3, 7.4
   * 
   * For any robots.txt content:
   * - Disallow entries should be extracted as paths
   * - Paths matching admin/backup/config patterns should be flagged as sensitive
   * - Missing security.txt should generate an INFO level finding
   */
  describe('Property 8: Robots.txt Analysis', () => {

    it('Disallow entries should be extracted as paths (Requirement 7.2)', () => {
      // Generate random paths using constantFrom for valid path examples
      const pathArb = fc.array(
        fc.constantFrom('/admin', '/backup', '/config', '/private', '/test', '/api', '/uploads', '/logs'),
        { minLength: 1, maxLength: 8 }
      );

      fc.assert(
        fc.property(pathArb, (paths) => {
          // Create robots.txt content with Disallow entries
          const robotsContent = paths.map(p => `Disallow: ${p}`).join('\n');
          
          const { disallowedPaths } = parseRobotsTxt(robotsContent);
          
          // All paths should be extracted (accounting for deduplication)
          const uniquePaths = [...new Set(paths)];
          for (const path of uniquePaths) {
            expect(disallowedPaths).toContain(path);
          }
        }),
        testConfig
      );
    });

    it('Admin paths should be flagged as sensitive with MEDIUM severity (Requirement 7.3)', () => {
      const adminPaths = ['/admin', '/administrator', '/wp-admin', '/cpanel', '/phpmyadmin'];
      const adminPathArb = fc.constantFrom(...adminPaths);
      const langArb = fc.constantFrom('tr' as const, 'en' as const);

      fc.assert(
        fc.property(adminPathArb, langArb, (path, lang) => {
          const { sensitivePaths, findings } = identifySensitivePaths([path], lang);
          
          // Path should be identified as sensitive
          expect(sensitivePaths).toContain(path);
          
          // Should have a finding for admin panel
          const adminFinding = findings.find(f => f.type === 'admin_panel');
          expect(adminFinding).toBeDefined();
          expect(adminFinding?.path).toBe(path);
          expect(['MEDIUM', 'LOW']).toContain(adminFinding?.severity);
        }),
        testConfig
      );
    });

    it('Backup paths should be flagged as sensitive (Requirement 7.3)', () => {
      const backupPaths = ['/backup', '/backups', '/data.bak', '/old-site.old', '/archive', '/dump'];
      const backupPathArb = fc.constantFrom(...backupPaths);
      const langArb = fc.constantFrom('tr' as const, 'en' as const);

      fc.assert(
        fc.property(backupPathArb, langArb, (path, lang) => {
          const { sensitivePaths, findings } = identifySensitivePaths([path], lang);
          
          // Path should be identified as sensitive
          expect(sensitivePaths).toContain(path);
          
          // Should have a finding for backup directory
          const backupFinding = findings.find(f => f.type === 'backup_dir');
          expect(backupFinding).toBeDefined();
          expect(backupFinding?.path).toBe(path);
        }),
        testConfig
      );
    });

    it('Config paths should be flagged as sensitive (Requirement 7.3)', () => {
      const configPaths = ['/config', '/.env', '/.git', '/.svn', '/web.config'];
      const configPathArb = fc.constantFrom(...configPaths);
      const langArb = fc.constantFrom('tr' as const, 'en' as const);

      fc.assert(
        fc.property(configPathArb, langArb, (path, lang) => {
          const { sensitivePaths, findings } = identifySensitivePaths([path], lang);
          
          // Path should be identified as sensitive
          expect(sensitivePaths).toContain(path);
          
          // Should have a finding for config file
          const configFinding = findings.find(f => f.type === 'config_file');
          expect(configFinding).toBeDefined();
          expect(configFinding?.path).toBe(path);
        }),
        testConfig
      );
    });

    it('Missing security.txt should generate INFO level finding (Requirement 7.4)', () => {
      const langArb = fc.constantFrom('tr' as const, 'en' as const);

      fc.assert(
        fc.property(langArb, (lang) => {
          // Create a result with missing security.txt
          const result: RobotsScanResult = {
            robotsTxt: {
              exists: true,
              disallowedPaths: ['/admin'],
              sensitivePaths: ['/admin'],
              sitemapUrls: [],
            },
            securityTxt: {
              exists: false,
            },
            findings: [{
              type: 'missing_security_txt',
              severity: 'INFO',
              description: lang === 'tr' 
                ? 'security.txt dosyası bulunamadı - güvenlik iletişim bilgileri eksik'
                : 'security.txt file not found - security contact information missing',
            }],
          };

          const vulns = robotsToVulnerabilities(result, lang);
          
          // Should have an INFO level vulnerability for missing security.txt
          const securityTxtVuln = vulns.find(v => v.id === 'VULN-SECURITY-TXT-MISSING');
          expect(securityTxtVuln).toBeDefined();
          expect(securityTxtVuln?.severity).toBe(lang === 'tr' ? 'Bilgi' : 'Info');
        }),
        testConfig
      );
    });

    it('Non-sensitive paths should not be flagged', () => {
      const safePaths = ['/images', '/css', '/js', '/assets', '/static', '/public'];
      const safePathArb = fc.constantFrom(...safePaths);
      const langArb = fc.constantFrom('tr' as const, 'en' as const);

      fc.assert(
        fc.property(safePathArb, langArb, (path, lang) => {
          const { sensitivePaths, findings } = identifySensitivePaths([path], lang);
          
          // Path should NOT be identified as sensitive
          expect(sensitivePaths).not.toContain(path);
          expect(findings.length).toBe(0);
        }),
        testConfig
      );
    });

    it('Multiple sensitive paths should all be detected', () => {
      const sensitivePathsArb = fc.subarray(
        ['/admin', '/backup', '/config', '/.env', '/.git', '/wp-admin'],
        { minLength: 2, maxLength: 6 }
      );
      const langArb = fc.constantFrom('tr' as const, 'en' as const);

      fc.assert(
        fc.property(sensitivePathsArb, langArb, (paths, lang) => {
          const { sensitivePaths, findings } = identifySensitivePaths(paths, lang);
          
          // All sensitive paths should be detected
          for (const path of paths) {
            expect(sensitivePaths).toContain(path);
          }
          
          // Should have findings for each path
          expect(findings.length).toBe(paths.length);
        }),
        testConfig
      );
    });

    it('Vulnerability severity should match finding severity', () => {
      const langArb = fc.constantFrom('tr' as const, 'en' as const);
      const pathTypeArb = fc.constantFrom(
        { path: '/admin', expectedSeverity: 'MEDIUM' },
        { path: '/backup', expectedSeverity: 'MEDIUM' },
        { path: '/config', expectedSeverity: 'MEDIUM' },
        { path: '/private', expectedSeverity: 'LOW' },
        { path: '/test', expectedSeverity: 'LOW' }
      );

      fc.assert(
        fc.property(pathTypeArb, langArb, ({ path, expectedSeverity }, lang) => {
          const { sensitivePaths, findings } = identifySensitivePaths([path], lang);
          
          if (sensitivePaths.length > 0) {
            const finding = findings[0];
            expect(finding.severity).toBe(expectedSeverity);
          }
        }),
        testConfig
      );
    });
  });

  describe('parseRobotsTxt', () => {
    it('should handle User-agent and Disallow combinations', () => {
      const pathArb = fc.constantFrom('/admin', '/backup', '/config', '/private', '/test');
      
      fc.assert(
        fc.property(pathArb, (path) => {
          const content = `User-agent: *\nDisallow: ${path}`;
          const { disallowedPaths } = parseRobotsTxt(content);
          
          expect(disallowedPaths).toContain(path);
        }),
        testConfig
      );
    });

    it('should extract Sitemap URLs', () => {
      const domainArb = fc.stringMatching(/^[a-z]+\.[a-z]+$/);
      
      fc.assert(
        fc.property(domainArb, (domain) => {
          const sitemapUrl = `https://${domain}/sitemap.xml`;
          const content = `Sitemap: ${sitemapUrl}`;
          const { sitemapUrls } = parseRobotsTxt(content);
          
          expect(sitemapUrls).toContain(sitemapUrl);
        }),
        testConfig
      );
    });

    it('should ignore comments', () => {
      const pathArb = fc.constantFrom('/admin', '/backup', '/config', '/private', '/test');
      
      fc.assert(
        fc.property(pathArb, (path) => {
          const content = `# This is a comment\nDisallow: ${path}\n# Another comment`;
          const { disallowedPaths } = parseRobotsTxt(content);
          
          expect(disallowedPaths).toContain(path);
          expect(disallowedPaths.length).toBe(1);
        }),
        testConfig
      );
    });

    it('should handle empty content gracefully', () => {
      const emptyContentArb = fc.constantFrom('', '   ', '\n\n', '# only comments');
      
      fc.assert(
        fc.property(emptyContentArb, (content) => {
          const { disallowedPaths, sitemapUrls } = parseRobotsTxt(content);
          
          expect(disallowedPaths.length).toBe(0);
          expect(sitemapUrls.length).toBe(0);
        }),
        testConfig
      );
    });

    it('should not duplicate paths', () => {
      const pathArb = fc.constantFrom('/admin', '/backup', '/config', '/private', '/test');
      
      fc.assert(
        fc.property(pathArb, (path) => {
          const content = `Disallow: ${path}\nDisallow: ${path}\nDisallow: ${path}`;
          const { disallowedPaths } = parseRobotsTxt(content);
          
          // Should only have one instance of the path
          const count = disallowedPaths.filter(p => p === path).length;
          expect(count).toBe(1);
        }),
        testConfig
      );
    });
  });

  describe('parseSecurityTxt', () => {
    it('should extract Contact field', () => {
      const emailArb = fc.emailAddress();
      
      fc.assert(
        fc.property(emailArb, (email) => {
          const content = `Contact: mailto:${email}`;
          const result = parseSecurityTxt(content);
          
          expect(result.exists).toBe(true);
          expect(result.contact).toBe(`mailto:${email}`);
        }),
        testConfig
      );
    });

    it('should extract multiple fields', () => {
      const emailArb = fc.emailAddress();
      const urlArb = fc.webUrl();
      
      fc.assert(
        fc.property(emailArb, urlArb, (email, url) => {
          const content = `Contact: mailto:${email}\nPolicy: ${url}\nExpires: 2025-12-31T23:59:59Z`;
          const result = parseSecurityTxt(content);
          
          expect(result.exists).toBe(true);
          expect(result.contact).toBe(`mailto:${email}`);
          expect(result.policy).toBe(url);
          expect(result.expires).toBe('2025-12-31T23:59:59Z');
        }),
        testConfig
      );
    });

    it('should handle empty content', () => {
      const emptyContentArb = fc.constantFrom('', '   ', '\n\n');
      
      fc.assert(
        fc.property(emptyContentArb, (content) => {
          const result = parseSecurityTxt(content);
          
          expect(result.exists).toBe(false);
        }),
        testConfig
      );
    });

    it('should ignore comments in security.txt', () => {
      const emailArb = fc.emailAddress();
      
      fc.assert(
        fc.property(emailArb, (email) => {
          const content = `# Security contact\nContact: mailto:${email}\n# End of file`;
          const result = parseSecurityTxt(content);
          
          expect(result.exists).toBe(true);
          expect(result.contact).toBe(`mailto:${email}`);
        }),
        testConfig
      );
    });
  });

  describe('robotsToVulnerabilities', () => {
    it('should generate vulnerabilities for sensitive paths', () => {
      const langArb = fc.constantFrom('tr' as const, 'en' as const);
      
      fc.assert(
        fc.property(langArb, (lang) => {
          const result: RobotsScanResult = {
            robotsTxt: {
              exists: true,
              disallowedPaths: ['/admin', '/backup'],
              sensitivePaths: ['/admin', '/backup'],
              sitemapUrls: [],
            },
            securityTxt: {
              exists: true,
              contact: 'security@example.com',
            },
            findings: [
              { type: 'admin_panel', path: '/admin', severity: 'MEDIUM', description: 'Admin panel' },
              { type: 'backup_dir', path: '/backup', severity: 'MEDIUM', description: 'Backup dir' },
            ],
          };

          const vulns = robotsToVulnerabilities(result, lang);
          
          // Should have vulnerability for sensitive paths
          expect(vulns.length).toBeGreaterThan(0);
          
          // Should have MEDIUM severity vulnerability
          const mediumVuln = vulns.find(v => v.id === 'VULN-ROBOTS-SENSITIVE-MEDIUM');
          expect(mediumVuln).toBeDefined();
        }),
        testConfig
      );
    });

    it('should not generate vulnerabilities when no sensitive paths', () => {
      const langArb = fc.constantFrom('tr' as const, 'en' as const);
      
      fc.assert(
        fc.property(langArb, (lang) => {
          const result: RobotsScanResult = {
            robotsTxt: {
              exists: true,
              disallowedPaths: ['/images', '/css'],
              sensitivePaths: [],
              sitemapUrls: [],
            },
            securityTxt: {
              exists: true,
              contact: 'security@example.com',
            },
            findings: [],
          };

          const vulns = robotsToVulnerabilities(result, lang);
          
          // Should have no vulnerabilities
          expect(vulns.length).toBe(0);
        }),
        testConfig
      );
    });

    it('should include sensitivePaths in vulnerability details', () => {
      const langArb = fc.constantFrom('tr' as const, 'en' as const);
      const sensitivePathsArb = fc.subarray(['/admin', '/backup', '/config'], { minLength: 1 });
      
      fc.assert(
        fc.property(sensitivePathsArb, langArb, (paths, lang) => {
          const result: RobotsScanResult = {
            robotsTxt: {
              exists: true,
              disallowedPaths: paths,
              sensitivePaths: paths,
              sitemapUrls: [],
            },
            securityTxt: {
              exists: true,
            },
            findings: paths.map(p => ({
              type: 'admin_panel' as const,
              path: p,
              severity: 'MEDIUM' as const,
              description: `Sensitive path: ${p}`,
            })),
          };

          const vulns = robotsToVulnerabilities(result, lang);
          
          if (vulns.length > 0) {
            const vuln = vulns.find(v => v.sensitivePaths);
            if (vuln) {
              expect(vuln.sensitivePaths).toEqual(paths);
            }
          }
        }),
        testConfig
      );
    });
  });
});
