/**
 * Security Scan Service
 * Main service for performing real security scans (replaces OpenRouter/AI)
 */
import { performSecurityScan, SecurityReport } from '../scanners';

/**
 * Analyze URL with real security scanning
 * @param url - Target URL to scan
 * @param isPremium - Whether user has premium access
 * @param lang - Language for report (tr/en)
 * @returns Security report
 */
export async function analyzeUrlWithRealScan(
  url: string,
  isPremium: boolean,
  lang: 'tr' | 'en' = 'tr'
): Promise<SecurityReport> {
  try {
    console.log(`[SecurityScanService] Starting scan for ${url}`);

    // Create 60 second timeout
    const scanPromise = performSecurityScan(url, isPremium, lang);
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Scan timeout after 60 seconds')), 60000)
    );

    const report = await Promise.race([scanPromise, timeoutPromise]);

    console.log(`[SecurityScanService] Scan completed successfully - Score: ${report.overallScore}/100`);
    return report;
  } catch (error: any) {
    console.error('[SecurityScanService] Scan failed:', error);
    throw new Error(`Security scan failed: ${error.message}`);
  }
}
