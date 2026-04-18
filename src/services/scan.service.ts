import { apiClient } from '../lib/api/client';
import type { SecurityReport } from '../types';

interface ScanRequest {
  url: string;
  lang: 'tr' | 'en';
}

interface ScanStartResponse {
  scanId: string;
  status: 'started';
}

export async function analyzeUrl(
  url: string,
  lang: 'tr' | 'en' = 'tr',
): Promise<SecurityReport & { scanId?: string }> {
  const requestData: ScanRequest = { url, lang };

  const response = await apiClient.post<SecurityReport & { scanId?: string }>('/scan', requestData);

  return response.data;
}

export async function startScanWithProgress(
  url: string,
  lang: 'tr' | 'en' = 'tr',
): Promise<ScanStartResponse> {
  const requestData: ScanRequest = { url, lang };

  const response = await apiClient.post<ScanStartResponse>('/scan/start', requestData);

  return response.data;
}
