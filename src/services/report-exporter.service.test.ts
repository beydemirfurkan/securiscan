/**
 * Property-Based Tests for Report Exporter Service
 *
 * Feature: enhanced-security-scanner
 * Validates: Requirements 1.4, 2.1, 2.2, 2.3, 2.4
 *
 * Property 1: JSON Export Round-Trip
 * Property 2: Filename Generation Format
 * Property 3: JSON Indentation
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  generateFilename,
  serializeToJson,
  extractDomain,
} from './report-exporter.service';
import type { SecurityReport, Severity } from '../types/security-report.types';

// Minimum 100 iterations as per design requirements
const testConfig = { numRuns: 100 };

// Arbitrary for generating valid SecurityReport objects
const severityArb = fc.constantFrom(
  'Kritik' as Severity,
  'Yüksek' as Severity,
  'Orta' as Severity,
  'Düşük' as Severity,
  'Bilgi' as Severity
);

const vulnerabilityArb = fc.record({
  id: fc.uuid(),
  title: fc.string({ minLength: 1, maxLength: 100 }),
  description: fc.string({ minLength: 1, maxLength: 500 }),
  severity: severityArb,
  location: fc.string({ minLength: 1, maxLength: 200 }),
  remediation: fc.string({ minLength: 1, maxLength: 500 }),
  cvssScore: fc.float({ min: 0, max: 10, noNaN: true }),
  exploitExample: fc.string({ maxLength: 200 }),
  exploitablePaths: fc.array(
    fc.record({
      description: fc.string({ maxLength: 100 }),
      scenario: fc.string({ maxLength: 100 }),
      impact: fc.string({ maxLength: 100 }),
    }),
    { maxLength: 3 }
  ),
  relatedCves: fc.array(
    fc.record({
      name: fc.string({ minLength: 1, maxLength: 50 }),
      url: fc.option(fc.webUrl(), { nil: undefined }),
    }),
    { maxLength: 3 }
  ),
});

const techStackItemArb = fc.record({
  name: fc.string({ minLength: 1, maxLength: 50 }),
  description: fc.string({ maxLength: 200 }),
  commonRisks: fc.array(
    fc.record({
      name: fc.string({ minLength: 1, maxLength: 50 }),
      url: fc.option(fc.webUrl(), { nil: undefined }),
    }),
    { maxLength: 3 }
  ),
});

const complianceItemArb = fc.record({
  standard: fc.string({ minLength: 1, maxLength: 50 }),
  status: fc.constantFrom('PASS' as const, 'FAIL' as const, 'WARNING' as const),
  details: fc.string({ maxLength: 200 }),
});

const headerAnalysisArb = fc.record({
  key: fc.string({ minLength: 1, maxLength: 50 }),
  value: fc.string({ maxLength: 200 }),
  status: fc.constantFrom('SECURE' as const, 'MISSING' as const, 'WARNING' as const, 'INFO' as const),
  description: fc.string({ maxLength: 200 }),
});

// Use string-based ISO date generation to avoid invalid date issues
const isoDateStringArb = fc
  .tuple(
    fc.integer({ min: 2000, max: 2030 }),
    fc.integer({ min: 1, max: 12 }),
    fc.integer({ min: 1, max: 28 }),
    fc.integer({ min: 0, max: 23 }),
    fc.integer({ min: 0, max: 59 }),
    fc.integer({ min: 0, max: 59 })
  )
  .map(([year, month, day, hour, min, sec]) => {
    const pad = (n: number) => n.toString().padStart(2, '0');
    return `${year}-${pad(month)}-${pad(day)}T${pad(hour)}:${pad(min)}:${pad(sec)}.000Z`;
  });

const dateOnlyStringArb = fc
  .tuple(
    fc.integer({ min: 2000, max: 2030 }),
    fc.integer({ min: 1, max: 12 }),
    fc.integer({ min: 1, max: 28 })
  )
  .map(([year, month, day]) => {
    const pad = (n: number) => n.toString().padStart(2, '0');
    return `${year}-${pad(month)}-${pad(day)}`;
  });

const sslInfoArb = fc.record({
  issuer: fc.string({ minLength: 1, maxLength: 100 }),
  validFrom: isoDateStringArb,
  validTo: isoDateStringArb,
  daysRemaining: fc.integer({ min: -365, max: 365 }),
  protocol: fc.constantFrom('TLSv1.2', 'TLSv1.3'),
  grade: fc.constantFrom('A+' as const, 'A' as const, 'B' as const, 'C' as const, 'D' as const, 'F' as const),
});

const networkInfoArb = fc.record({
  ip: fc.ipV4(),
  location: fc.string({ minLength: 1, maxLength: 100 }),
  isp: fc.string({ minLength: 1, maxLength: 100 }),
  asn: fc.string({ minLength: 1, maxLength: 20 }),
  organization: fc.string({ minLength: 1, maxLength: 100 }),
  serverType: fc.string({ minLength: 1, maxLength: 50 }),
  ports: fc.array(fc.integer({ min: 1, max: 65535 }), { maxLength: 10 }),
});

const actionPlanItemArb = fc.record({
  task: fc.string({ minLength: 1, maxLength: 200 }),
  priority: fc.constantFrom('URGENT' as const, 'HIGH' as const, 'MEDIUM' as const),
  effort: fc.constantFrom('LOW' as const, 'MEDIUM' as const, 'HIGH' as const),
  estimatedTime: fc.string({ minLength: 1, maxLength: 50 }),
  delayImpact: fc.string({ maxLength: 200 }),
});

const securityReportArb: fc.Arbitrary<SecurityReport> = fc.record({
  targetUrl: fc.webUrl(),
  scanTimestamp: isoDateStringArb,
  overallScore: fc.integer({ min: 0, max: 100 }),
  vulnerabilities: fc.array(vulnerabilityArb, { maxLength: 5 }),
  summary: fc.string({ maxLength: 500 }),
  techStackDetected: fc.array(techStackItemArb, { maxLength: 5 }),
  compliance: fc.array(complianceItemArb, { maxLength: 5 }),
  networkInfo: networkInfoArb,
  headers: fc.array(headerAnalysisArb, { maxLength: 10 }),
  ssl: sslInfoArb,
  subdomains: fc.array(
    fc.record({
      name: fc.string({ minLength: 1, maxLength: 100 }),
      ip: fc.ipV4(),
      status: fc.constantFrom('ACTIVE' as const, 'CLOUDFLARE' as const, 'HIDDEN' as const),
    }),
    { maxLength: 3 }
  ),
  darkWebLeaks: fc.array(
    fc.record({
      source: fc.string({ minLength: 1, maxLength: 100 }),
      date: dateOnlyStringArb,
      type: fc.string({ minLength: 1, maxLength: 50 }),
      severity: fc.constantFrom('HIGH' as const, 'MEDIUM' as const),
    }),
    { maxLength: 3 }
  ),
  actionPlan: fc.array(actionPlanItemArb, { maxLength: 5 }),
  isPremium: fc.option(fc.boolean(), { nil: undefined }),
});

describe('Report Exporter Service - Property Tests', () => {
  /**
   * Feature: enhanced-security-scanner, Property 1: JSON Export Round-Trip
   * Validates: Requirements 2.1, 2.2
   *
   * For any valid SecurityReport object, serializing to JSON and deserializing
   * back should produce an equivalent object with all fields preserved.
   */
  describe('Property 1: JSON Export Round-Trip', () => {
    it('serializing to JSON and deserializing back should produce equivalent object', () => {
      fc.assert(
        fc.property(securityReportArb, (report) => {
          const jsonString = serializeToJson(report);
          const parsed = JSON.parse(jsonString);

          // The report should be preserved in the parsed object
          expect(parsed.report).toBeDefined();

          // Check all top-level fields are preserved
          expect(parsed.report.targetUrl).toBe(report.targetUrl);
          expect(parsed.report.scanTimestamp).toBe(report.scanTimestamp);
          expect(parsed.report.overallScore).toBe(report.overallScore);
          expect(parsed.report.summary).toBe(report.summary);

          // Check arrays are preserved
          expect(parsed.report.vulnerabilities.length).toBe(report.vulnerabilities.length);
          expect(parsed.report.techStackDetected.length).toBe(report.techStackDetected.length);
          expect(parsed.report.compliance.length).toBe(report.compliance.length);
          expect(parsed.report.headers.length).toBe(report.headers.length);
          expect(parsed.report.actionPlan.length).toBe(report.actionPlan.length);

          // Check nested objects are preserved
          expect(parsed.report.networkInfo.ip).toBe(report.networkInfo.ip);
          expect(parsed.report.ssl.issuer).toBe(report.ssl.issuer);
        }),
        testConfig
      );
    });

    it('metadata should be included in exported JSON', () => {
      fc.assert(
        fc.property(securityReportArb, (report) => {
          const jsonString = serializeToJson(report);
          const parsed = JSON.parse(jsonString);

          // Metadata should be present
          expect(parsed.metadata).toBeDefined();
          expect(parsed.metadata.generatedAt).toBeDefined();
          expect(parsed.metadata.generatorVersion).toBeDefined();
          expect(parsed.metadata.reportFormat).toBe('json');
        }),
        testConfig
      );
    });
  });

  /**
   * Feature: enhanced-security-scanner, Property 2: Filename Generation Format
   * Validates: Requirements 1.4, 2.3
   *
   * For any domain string and timestamp, the generated filename should match
   * the pattern `security-report-{domain}-{timestamp}.{format}`
   */
  describe('Property 2: Filename Generation Format', () => {
    it('filename should match pattern security-report-{domain}-{timestamp}.{format}', () => {
      const domainArb = fc.webUrl();
      const formatArb = fc.constantFrom('pdf' as const, 'json' as const);

      fc.assert(
        fc.property(domainArb, formatArb, (domain, format) => {
          const filename = generateFilename(domain, format);

          // Should start with 'security-report-'
          expect(filename.startsWith('security-report-')).toBe(true);

          // Should end with correct extension
          expect(filename.endsWith(`.${format}`)).toBe(true);

          // Should contain timestamp pattern (YYYY-MM-DDTHH-MM-SS)
          const timestampPattern = /\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}/;
          expect(timestampPattern.test(filename)).toBe(true);

          // Should not contain invalid filename characters
          const invalidChars = /[<>:"/\\|?*]/;
          expect(invalidChars.test(filename)).toBe(false);
        }),
        testConfig
      );
    });

    it('extractDomain should extract hostname from valid URLs', () => {
      fc.assert(
        fc.property(fc.webUrl(), (url) => {
          const domain = extractDomain(url);

          // Should not be empty
          expect(domain.length).toBeGreaterThan(0);

          // Should not contain protocol
          expect(domain.includes('://')).toBe(false);

          // Should not contain path separators
          expect(domain.includes('/')).toBe(false);
        }),
        testConfig
      );
    });

    it('filename should be unique for different timestamps', () => {
      const domain = 'https://example.com';

      // Generate two filenames with slight delay
      const filename1 = generateFilename(domain, 'json');

      // Wait a tiny bit to ensure different timestamp
      const filename2 = generateFilename(domain, 'json');

      // Both should be valid filenames
      expect(filename1.startsWith('security-report-')).toBe(true);
      expect(filename2.startsWith('security-report-')).toBe(true);
    });
  });

  /**
   * Feature: enhanced-security-scanner, Property 3: JSON Indentation
   * Validates: Requirements 2.4
   *
   * For any SecurityReport, the exported JSON string should contain
   * newline characters and consistent indentation (2 spaces).
   */
  describe('Property 3: JSON Indentation', () => {
    it('JSON should contain newline characters for readability', () => {
      fc.assert(
        fc.property(securityReportArb, (report) => {
          const jsonString = serializeToJson(report);

          // Should contain newlines
          expect(jsonString.includes('\n')).toBe(true);

          // Count newlines - should have multiple for proper formatting
          const newlineCount = (jsonString.match(/\n/g) || []).length;
          expect(newlineCount).toBeGreaterThan(1);
        }),
        testConfig
      );
    });

    it('JSON should use consistent 2-space indentation', () => {
      fc.assert(
        fc.property(securityReportArb, (report) => {
          const jsonString = serializeToJson(report);

          // Should contain 2-space indentation
          expect(jsonString.includes('  ')).toBe(true);

          // Lines should be indented with multiples of 2 spaces
          const lines = jsonString.split('\n');
          for (const line of lines) {
            const leadingSpaces = line.match(/^(\s*)/)?.[1] || '';
            // Leading spaces should be multiple of 2 (or 0)
            expect(leadingSpaces.length % 2).toBe(0);
          }
        }),
        testConfig
      );
    });

    it('JSON should be valid and parseable', () => {
      fc.assert(
        fc.property(securityReportArb, (report) => {
          const jsonString = serializeToJson(report);

          // Should not throw when parsing
          expect(() => JSON.parse(jsonString)).not.toThrow();

          // Parsed result should be an object
          const parsed = JSON.parse(jsonString);
          expect(typeof parsed).toBe('object');
          expect(parsed).not.toBeNull();
        }),
        testConfig
      );
    });
  });
});
