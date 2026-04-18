/**
 * Scan Routes
 *
 * Handles security scanning requests with real-time progress via SSE
 */

import { Router, Request, Response } from 'express';
import { isValidAndSafeUrl } from '../utils/url-validator';
import { performSecurityScan } from '../scanners';
import { asyncHandler } from '../middleware/error-handler';
import { scanRateLimiter } from '../middleware/rate-limit';
import { createScanSession, removeScanSession, ScanProgress } from '../services/scan-progress.service';
import { v4 as uuidv4 } from 'uuid';

const router = Router();

// Store active SSE connections
const sseConnections = new Map<string, Response>();

interface ScanRequest {
  url: string;
  lang?: 'tr' | 'en';
}

/**
 * GET /api/scan/progress/:scanId
 * SSE endpoint for real-time scan progress
 */
router.get('/progress/:scanId', (req: Request, res: Response) => {
  const { scanId } = req.params;
  
  // Set SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  // Store connection
  sseConnections.set(scanId, res);

  // Send initial connection event
  res.write(`data: ${JSON.stringify({ type: 'connected', scanId })}\n\n`);

  // Handle client disconnect
  req.on('close', () => {
    sseConnections.delete(scanId);
    removeScanSession(scanId);
  });
});

/**
 * POST /api/scan
 * Perform security scan on a URL with real-time progress
 */
router.post(
  '/',
  scanRateLimiter,
  asyncHandler(async (req: Request, res: Response) => {
    const { url, lang = 'tr' }: ScanRequest = req.body;

    if (!url) {
      return res.status(400).json({
        error: 'URL is required',
      });
    }

    let fullUrl = url.trim();
    if (!fullUrl.startsWith('http://') && !fullUrl.startsWith('https://')) {
      fullUrl = `https://${fullUrl}`;
    }

    if (!isValidAndSafeUrl(fullUrl)) {
      return res.status(400).json({
        error: lang === 'tr'
          ? 'Geçersiz veya güvenli olmayan URL. Dahili ağ adreslerine tarama yapılamaz.'
          : 'Invalid or unsafe URL. Cannot scan internal network addresses.',
      });
    }

    if (lang !== 'tr' && lang !== 'en') {
      return res.status(400).json({
        error: 'Invalid language. Must be "tr" or "en".',
      });
    }

    try {
      const scanId = uuidv4();
      const progressEmitter = createScanSession(scanId, lang);
      const sseConnection = sseConnections.get(scanId);

      progressEmitter.on('progress', (progress: ScanProgress) => {
        const connection = sseConnections.get(scanId);
        if (connection) {
          connection.write(`data: ${JSON.stringify({ type: 'progress', phase: progress.phase, progress: progress.progress, msgType: progress.type, details: progress.details })}\n\n`);
        }
      });

      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Scan timeout after 120 seconds')), 120000)
      );

      const report = await Promise.race([
        performSecurityScan(fullUrl, true, lang, progressEmitter),
        timeoutPromise
      ]);

      const connection = sseConnections.get(scanId);
      if (connection) {
        connection.write(`data: ${JSON.stringify({ type: 'complete', scanId })}\n\n`);
      }

      removeScanSession(scanId);
      res.json({ ...report, scanId });
    } catch (error: any) {
      console.error('[Scan] Error:', error);

      if (error.message?.includes('timeout')) {
        return res.status(504).json({
          error: lang === 'tr'
            ? 'Tarama zaman aşımına uğradı. Lütfen tekrar deneyin.'
            : 'Scan timed out. Please try again.',
          details: error.message,
        });
      }

      res.status(500).json({
        error: lang === 'tr'
          ? 'Tarama sırasında bir hata oluştu. Lütfen tekrar deneyin.'
          : 'An error occurred during scanning. Please try again.',
      });
    }
  })
);

/**
 * POST /api/scan/start
 * Start a scan and return scanId for progress tracking
 */
router.post(
  '/start',
  scanRateLimiter,
  asyncHandler(async (req: Request, res: Response) => {
    const { url, lang = 'tr' }: ScanRequest = req.body;

    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    let fullUrl = url.trim();
    if (!fullUrl.startsWith('http://') && !fullUrl.startsWith('https://')) {
      fullUrl = `https://${fullUrl}`;
    }

    if (!isValidAndSafeUrl(fullUrl)) {
      return res.status(400).json({
        error: lang === 'tr'
          ? 'Geçersiz veya güvenli olmayan URL.'
          : 'Invalid or unsafe URL.',
      });
    }

    const scanId = uuidv4();
    const progressEmitter = createScanSession(scanId, lang);

    progressEmitter.on('progress', (progress: ScanProgress) => {
      const connection = sseConnections.get(scanId);
      if (connection) {
        connection.write(`data: ${JSON.stringify({ type: 'progress', phase: progress.phase, progress: progress.progress, msgType: progress.type, details: progress.details })}\n\n`);
      }
    });

    res.json({ scanId, status: 'started' });

    try {
      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Scan timeout after 120 seconds')), 120000)
      );

      const report = await Promise.race([
        performSecurityScan(fullUrl, true, lang, progressEmitter),
        timeoutPromise
      ]);

      const connection = sseConnections.get(scanId);
      if (connection) {
        connection.write(`data: ${JSON.stringify({ type: 'complete', report })}\n\n`);
      }
    } catch (error: any) {
      const connection = sseConnections.get(scanId);
      if (connection) {
        connection.write(`data: ${JSON.stringify({
          type: 'error',
          error: error.message || 'Scan failed'
        })}\n\n`);
      }
    } finally {
      removeScanSession(scanId);
    }
  })
);

export default router;
