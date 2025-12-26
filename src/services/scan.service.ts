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
): Promise<SecurityReport> {
  const requestData: ScanRequest = {
    url,
    lang,
    ...(paymentToken && { paymentToken })
  };

  const response = await apiClient.post<SecurityReport>('/scan', requestData);

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
