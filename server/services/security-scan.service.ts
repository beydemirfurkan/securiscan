/**
 * Security Scan Service
 * Main service for performing real security scans with progress tracking
 */
import { performSecurityScan, SecurityReport } from '../scanners';
import { ScanProgressEmitter } from './scan-progress.service';

/**
 * Analyze URL with real security scanning
 * @param url - Target URL to scan
 * @param isPremium - Whether user has premium access
 * @param lang - Language for report (tr/en)
 * @param progressEmitter - Optional progress emitter for real-time updates
 * @returns Security report
 */
export async function analyzeUrlWithRealScan(
  url: string,
  isPremium: boolean,
  lang: 'tr' | 'en' = 'tr',
  progressEmitter?: ScanProgressEmitter
): Promise<SecurityReport> {
  try {
    console.log(`[SecurityScanService] Starting scan for ${url}`);

    // Create 120 second timeout (increased for comprehensive scanning)
    const scanPromise = performSecurityScan(url, isPremium, lang, progressEmitter);
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Scan timeout after 120 seconds')), 120000)
    );

    const report = await Promise.race([scanPromise, timeoutPromise]);

    console.log(`[SecurityScanService] Scan completed successfully - Score: ${report.overallScore}/100`);
    return report;
  } catch (error: any) {
    console.error('[SecurityScanService] Scan failed:', error);
    throw new Error(`Security scan failed: ${error.message}`);
  }
}
