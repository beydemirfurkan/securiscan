/**
 * HTTP Headers Scanner
 * Analyzes security headers and server information
 */

import axios from 'axios';
import { SECURITY_HEADERS_RULES } from '../utils/security-constants';

export interface HeaderAnalysis {
  key: string;
  value: string;
  status: 'SECURE' | 'MISSING' | 'WARNING' | 'INFO';
  description: string;
}

/**
 * Scan HTTP headers for security configuration
 * @param url - The URL to analyze
 * @returns Array of header analysis results
 */
export async function scanHeaders(url: string): Promise<HeaderAnalysis[]> {
  const analysis: HeaderAnalysis[] = [];

  try {
    // Make HEAD request to get headers without downloading body
    const response = await axios.head(url, {
      timeout: 10000,
      validateStatus: () => true, // Accept any status code
      maxRedirects: 3,
    });

    const headers = response.headers;

    // Check security headers
    Object.entries(SECURITY_HEADERS_RULES).forEach(([headerKey, rule]) => {
      const value = headers[headerKey.toLowerCase()];

      if (!value) {
        analysis.push({
          key: headerKey,
          value: 'Missing',
          status: 'WARNING',
          description: rule.description,
        });
      } else {
        // Header exists - validate its value
        const isValid = validateHeaderValue(headerKey, value);

        analysis.push({
          key: headerKey,
          value: String(value),
          status: isValid ? 'SECURE' : 'WARNING',
          description: rule.description,
        });
      }
    });

    // Check for information disclosure headers
    const infoHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator'];

    infoHeaders.forEach((headerKey) => {
      const value = headers[headerKey];
      if (value) {
        analysis.push({
          key: headerKey.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('-'),
          value: String(value),
          status: 'INFO',
          description: 'Server information disclosure - reveals technology stack',
        });
      }
    });

    // Check cache-control
    const cacheControl = headers['cache-control'];
    if (cacheControl) {
      analysis.push({
        key: 'Cache-Control',
        value: String(cacheControl),
        status: 'INFO',
        description: 'Caching policy configuration',
      });
    }

  } catch (error: any) {
    // If HEAD fails, try GET with minimal data
    try {
      const response = await axios.get(url, {
        timeout: 10000,
        validateStatus: () => true,
        maxRedirects: 3,
        maxContentLength: 1024, // Only download first 1KB
      });

      const headers = response.headers;

      // Repeat security headers check
      Object.entries(SECURITY_HEADERS_RULES).forEach(([headerKey, rule]) => {
        const value = headers[headerKey.toLowerCase()];

        analysis.push({
          key: headerKey,
          value: value ? String(value) : 'Missing',
          status: value ? 'SECURE' : 'WARNING',
          description: rule.description,
        });
      });

    } catch (fallbackError: any) {
      throw new Error(`Headers scan failed: ${error.message}`);
    }
  }

  return analysis;
}

/**
 * Validate header value for common misconfigurations
 * @param headerKey - The header name
 * @param value - The header value
 * @returns true if valid, false otherwise
 */
function validateHeaderValue(headerKey: string, value: string): boolean {
  const lowerKey = headerKey.toLowerCase();
  const lowerValue = String(value).toLowerCase();

  switch (lowerKey) {
    case 'strict-transport-security':
      // Should have max-age
      return lowerValue.includes('max-age');

    case 'content-security-policy':
      // Should not be "none" or empty
      return lowerValue.length > 10 && !lowerValue.includes('unsafe-inline');

    case 'x-frame-options':
      // Should be DENY or SAMEORIGIN
      return lowerValue === 'deny' || lowerValue === 'sameorigin';

    case 'x-content-type-options':
      // Should be nosniff
      return lowerValue === 'nosniff';

    case 'referrer-policy':
      // Should have a policy set
      return lowerValue.length > 0;

    default:
      // For other headers, just check if they exist
      return true;
  }
}
