/**
 * useScan Hook
 *
 * Manages security scan state and operations with real-time progress
 */

import { useState, useCallback, useEffect } from 'react';
import { analyzeUrl, startScanWithProgress } from '../services/scan.service';
import type { SecurityReport, ScanStatus } from '../types';

export function useScan(lang: 'tr' | 'en') {
  const [url, setUrl] = useState('');
  const [status, setStatus] = useState<ScanStatus>('IDLE');
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [isTerminalReady, setIsTerminalReady] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);

  // When terminal completes and report is ready, transition to COMPLETE
  useEffect(() => {
    if (status === 'SCANNING' && isTerminalReady) {
      if (report) {
        setStatus('COMPLETE');
      } else if (error) {
        setStatus('ERROR');
      }
    }
  }, [status, isTerminalReady, report, error]);

  const handleTerminalComplete = useCallback(() => {
    setIsTerminalReady(true);
  }, []);

  const startScan = useCallback(
    (targetUrl: string) => {
      const trimmedUrl = targetUrl.trim();

      // Validation
      if (!trimmedUrl) {
        setValidationError(lang === 'tr' ? 'Lütfen geçerli bir URL giriniz.' : 'Please enter a valid URL.');
        return;
      }

      const urlPattern = /^(https?:\/\/)?((([a-z\d]([a-z\d-]*[a-z\d])*)\.)+[a-z]{2,}|((\d{1,3}\.){3}\d{1,3}))(\:\d+)?(\/[-a-z\d%_.~+]*)*(\?[;&a-z\d%_.~+=-]*)?(\#[-a-z\d_]*)?$/i;

      if (!urlPattern.test(trimmedUrl)) {
        setValidationError(lang === 'tr' ? 'Geçersiz URL formatı. Lütfen kontrol ediniz.' : 'Invalid URL format. Please check.');
        return;
      }

      // Add protocol if missing
      let formattedUrl = trimmedUrl;
      if (!formattedUrl.startsWith('http') && !formattedUrl.startsWith('https')) {
        formattedUrl = `https://${formattedUrl}`;
      }

      // Start scan
      setStatus('SCANNING');
      setError(null);
      setReport(null);
      setIsTerminalReady(false);
      setValidationError(null);
      setScanId(null);

      // Use the standard scan endpoint which returns report directly
      analyzeUrl(formattedUrl, lang)
        .then(result => {
          if (result.scanId) {
            setScanId(result.scanId);
          }
          setReport(result);
        })
        .catch(err => {
          setError(
            lang === 'tr'
              ? 'Analiz motoru bir hata ile karşılaştı.'
              : 'Analysis engine encountered an error.'
          );
        });
    },
    [lang]
  );

  const reset = useCallback(() => {
    setStatus('IDLE');
    setUrl('');
    setReport(null);
    setError(null);
    setValidationError(null);
    setIsTerminalReady(false);
    setScanId(null);
  }, []);

  const clearValidationError = useCallback(() => {
    setValidationError(null);
  }, []);

  const refetchReport = useCallback((targetUrl: string) => {
    analyzeUrl(targetUrl, lang)
      .then(result => setReport(result))
      .catch(err => console.error('Failed to refetch report:', err));
  }, [lang]);

  return {
    url,
    setUrl,
    status,
    report,
    error,
    validationError,
    isTerminalReady,
    scanId,
    startScan,
    reset,
    handleTerminalComplete,
    clearValidationError,
    refetchReport,
  };
}
