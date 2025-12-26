/**
 * Scan Routes
 *
 * Handles security scanning requests
 */

import { Router, Request, Response } from 'express';
import { isValidAndSafeUrl } from '../utils/url-validator';
import { analyzeUrlWithRealScan } from '../services/security-scan.service';
import { verifyPayment } from '../services/payment.service';
import { asyncHandler } from '../middleware/error-handler';
import { scanRateLimiter } from '../middleware/rate-limit';

const router = Router();

interface ScanRequest {
  url: string;
  lang?: 'tr' | 'en';
  paymentToken?: string;
}

/**
 * POST /api/scan
 * Perform security scan on a URL
 */
router.post(
  '/',
  scanRateLimiter,
  asyncHandler(async (req: Request, res: Response) => {
    const { url, lang = 'tr', paymentToken }: ScanRequest = req.body;

    // Validate request
    if (!url) {
      return res.status(400).json({
        error: 'URL is required',
      });
    }

    // Add protocol if missing
    let fullUrl = url.trim();
    if (!fullUrl.startsWith('http://') && !fullUrl.startsWith('https://')) {
      fullUrl = `https://${fullUrl}`;
    }

    // Validate URL and check for SSRF
    if (!isValidAndSafeUrl(fullUrl)) {
      return res.status(400).json({
        error: lang === 'tr'
          ? 'Geçersiz veya güvenli olmayan URL. Dahili ağ adreslerine tarama yapılamaz.'
          : 'Invalid or unsafe URL. Cannot scan internal network addresses.',
      });
    }

    // Validate language
    if (lang !== 'tr' && lang !== 'en') {
      return res.status(400).json({
        error: 'Invalid language. Must be "tr" or "en".',
      });
    }

    try {
      // Check if user has paid for premium features
      const hasPremiumAccess = paymentToken ? await verifyPayment(paymentToken) : false;

      // Perform real security scan
      console.log(`[Scan] Analyzing ${fullUrl} (lang: ${lang}, premium: ${hasPremiumAccess})`);
      const report = await analyzeUrlWithRealScan(fullUrl, hasPremiumAccess, lang);

      // Return report (already has isPremium flag and correct features based on access level)
      res.json(report);
    } catch (error: any) {
      console.error('[Scan] Error:', error);

      // Check if it's a scan timeout
      if (error.message?.includes('timeout')) {
        return res.status(504).json({
          error: lang === 'tr'
            ? 'Tarama zaman aşımına uğradı. Lütfen tekrar deneyin.'
            : 'Scan timed out. Please try again.',
          details: error.message,
        });
      }

      // Generic error response
      res.status(500).json({
        error: lang === 'tr'
          ? 'Tarama sırasında bir hata oluştu. Lütfen tekrar deneyin.'
          : 'An error occurred during scanning. Please try again.',
      });
    }
  })
);

export default router;
