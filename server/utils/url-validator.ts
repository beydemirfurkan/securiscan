/**
 * URL Validation with SSRF (Server-Side Request Forgery) Protection
 *
 * This module prevents malicious users from scanning internal/private network resources
 * by blocking localhost, private IP ranges, and link-local addresses.
 */

/**
 * Validates a URL and checks for SSRF vulnerabilities
 *
 * @param url - The URL to validate
 * @returns true if URL is valid and safe, false otherwise
 */
export function isValidAndSafeUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;

    // Only allow HTTP and HTTPS protocols
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return false;
    }

    // Block localhost
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]') {
      return false;
    }

    // Block private IP ranges (IPv4)
    const privateIPv4Patterns = [
      /^10\./,                          // 10.0.0.0/8
      /^172\.(1[6-9]|2\d|3[01])\./,    // 172.16.0.0/12
      /^192\.168\./,                    // 192.168.0.0/16
      /^169\.254\./,                    // Link-local (169.254.0.0/16)
      /^127\./,                         // Loopback (127.0.0.0/8)
    ];

    if (privateIPv4Patterns.some(pattern => pattern.test(hostname))) {
      return false;
    }

    // Block private IPv6 ranges
    const privateIPv6Patterns = [
      /^fc00:/,  // Unique local addresses
      /^fd00:/,  // Unique local addresses
      /^fe80:/,  // Link-local addresses
      /^::1$/,   // Loopback
    ];

    if (privateIPv6Patterns.some(pattern => pattern.test(hostname))) {
      return false;
    }

    // Block IP addresses in square brackets (IPv6 notation) that are private
    if (hostname.startsWith('[') && hostname.endsWith(']')) {
      const ipv6 = hostname.slice(1, -1);
      if (privateIPv6Patterns.some(pattern => pattern.test(ipv6))) {
        return false;
      }
    }

    return true;
  } catch (error) {
    // Invalid URL format
    return false;
  }
}

/**
 * Validates URL format for client-side feedback
 * Less strict than server-side validation
 *
 * @param url - The URL to validate
 * @returns Object with validation result and optional error message
 */
export function validateUrlFormat(url: string): { valid: boolean; error?: string } {
  const trimmed = url.trim();

  if (!trimmed) {
    return { valid: false, error: 'URL cannot be empty' };
  }

  try {
    // Try to parse with or without protocol
    const urlToParse = trimmed.startsWith('http') ? trimmed : `https://${trimmed}`;
    const parsed = new URL(urlToParse);

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { valid: false, error: 'Only HTTP/HTTPS protocols are allowed' };
    }

    // Basic hostname validation
    if (!parsed.hostname || parsed.hostname.length < 3) {
      return { valid: false, error: 'Invalid hostname' };
    }

    return { valid: true };
  } catch {
    return { valid: false, error: 'Invalid URL format' };
  }
}
