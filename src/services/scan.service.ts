/**
 * Scan Service
 *
 * Handles communication with backend scan API
 */

import { apiClient } from '../lib/api/client';
import type { SecurityReport } from '../types';

interface ScanRequest {
  url: string;
  lang: 'tr' | 'en';
  paymentToken?: string;
}

interface ScanStartResponse {
  scanId: string;
  status: 'started';
}

/**
 * Analyze a URL and get security report
 *
 * @param url - The URL to scan
 * @param lang - Language for the report (tr or en)
 * @param paymentToken - Optional payment token for premium features
 * @returns Security report from backend
 */
export async function analyzeUrl(
  url: string,
  lang: 'tr' | 'en' = 'tr',
  paymentToken?: string
): Promise<SecurityReport & { scanId?: string }> {
  const requestData: ScanRequest = {
    url,
    lang,
    ...(paymentToken && { paymentToken })
  };

  const response = await apiClient.post<SecurityReport & { scanId?: string }>('/scan', requestData);

  return response.data;
}

/**
 * Start a scan and get scanId for progress tracking
 *
 * @param url - The URL to scan
 * @param lang - Language for the report (tr or en)
 * @param paymentToken - Optional payment token for premium features
 * @returns Scan ID for progress tracking
 */
export async function startScanWithProgress(
  url: string,
  lang: 'tr' | 'en' = 'tr',
  paymentToken?: string
): Promise<ScanStartResponse> {
  const requestData: ScanRequest = {
    url,
    lang,
    ...(paymentToken && { paymentToken })
  };

  const response = await apiClient.post<ScanStartResponse>('/scan/start', requestData);

  return response.data;
}

/**
 * Verify payment token
 *
 * @param paymentToken - Payment token to verify
 * @returns Verification result
 */
export async function verifyPayment(paymentToken: string): Promise<{ success: boolean; message: string }> {
  const response = await apiClient.post('/payment/verify', { paymentToken });
  return response.data;
}
