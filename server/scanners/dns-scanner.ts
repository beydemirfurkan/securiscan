/**
 * DNS Scanner
 * Performs DNS lookups and subdomain enumeration
 */

import * as dns from 'dns/promises';
import { COMMON_SUBDOMAINS } from '../utils/security-constants';

export interface DNSInfo {
  ip: string;
  ipv6?: string;
}

export interface SubdomainInfo {
  name: string;
  ip: string;
  status: 'ACTIVE' | 'CLOUDFLARE' | 'HIDDEN';
}

/**
 * Get basic DNS information for a hostname
 * @param hostname - The hostname to lookup
 * @returns DNS information including IPv4 and optionally IPv6
 */
export async function getDNSInfo(hostname: string): Promise<DNSInfo> {
  try {
    // Resolve IPv4 address
    const ipv4Addresses = await dns.resolve4(hostname);
    const ip = ipv4Addresses[0];

    let ipv6: string | undefined;

    // Try to resolve IPv6 (optional)
    try {
      const ipv6Addresses = await dns.resolve6(hostname);
      ipv6 = ipv6Addresses[0];
    } catch {
      // IPv6 not available, that's okay
    }

    return { ip, ipv6 };
  } catch (error: any) {
    throw new Error(`DNS resolution failed: ${error.message}`);
  }
}

/**
 * Scan for common subdomains (Premium feature)
 * @param hostname - The root domain to scan
 * @returns Array of discovered subdomains with their IPs
 */
export async function scanSubdomains(hostname: string): Promise<SubdomainInfo[]> {
  const results: SubdomainInfo[] = [];
  const checkedSubdomains = new Set<string>();

  // Use common subdomains list
  const subdomainsToCheck = COMMON_SUBDOMAINS.slice(0, 50); // Limit to first 50 for performance

  // Check subdomains concurrently in batches
  const batchSize = 10;
  for (let i = 0; i < subdomainsToCheck.length; i += batchSize) {
    const batch = subdomainsToCheck.slice(i, i + batchSize);

    const batchResults = await Promise.allSettled(
      batch.map(async (subdomain) => {
        const fullDomain = `${subdomain}.${hostname}`;

        // Skip if already checked
        if (checkedSubdomains.has(fullDomain)) {
          return null;
        }

        checkedSubdomains.add(fullDomain);

        try {
          const addresses = await dns.resolve4(fullDomain);
          const ip = addresses[0];

          // Detect Cloudflare IPs (rough detection)
          const isCloudflare = isCloudflareIP(ip);

          return {
            name: fullDomain,
            ip,
            status: isCloudflare ? 'CLOUDFLARE' as const : 'ACTIVE' as const,
          };
        } catch {
          // Subdomain doesn't exist or failed to resolve
          return null;
        }
      })
    );

    // Collect successful results
    batchResults.forEach((result) => {
      if (result.status === 'fulfilled' && result.value) {
        results.push(result.value);
      }
    });

    // Small delay between batches to avoid rate limiting
    if (i + batchSize < subdomainsToCheck.length) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  return results;
}

/**
 * Check if an IP belongs to Cloudflare (rough detection)
 * @param ip - The IP address to check
 * @returns true if likely Cloudflare, false otherwise
 */
function isCloudflareIP(ip: string): boolean {
  // Cloudflare IP ranges (simplified check)
  const cloudflareRanges = [
    '173.245.',
    '103.21.',
    '103.22.',
    '103.31.',
    '141.101.',
    '108.162.',
    '190.93.',
    '188.114.',
    '197.234.',
    '198.41.',
    '162.158.',
    '104.16.',
    '104.17.',
    '104.18.',
    '104.19.',
    '104.20.',
    '104.21.',
    '104.22.',
    '104.23.',
    '104.24.',
    '104.25.',
    '104.26.',
    '104.27.',
    '104.28.',
    '172.64.',
    '172.65.',
    '172.66.',
    '172.67.',
    '172.68.',
    '172.69.',
    '172.70.',
    '172.71.',
  ];

  return cloudflareRanges.some((range) => ip.startsWith(range));
}

/**
 * Perform reverse DNS lookup to get hostname from IP
 * @param ip - The IP address to lookup
 * @returns Hostname(s) associated with the IP
 */
export async function reverseDNS(ip: string): Promise<string[]> {
  try {
    const hostnames = await dns.reverse(ip);
    return hostnames;
  } catch (error: any) {
    // Reverse DNS may not be available
    return [];
  }
}

/**
 * Get MX (mail exchange) records for a domain
 * @param hostname - The domain to check
 * @returns Array of MX records
 */
export async function getMXRecords(hostname: string): Promise<Array<{ exchange: string; priority: number }>> {
  try {
    const mxRecords = await dns.resolveMx(hostname);
    return mxRecords;
  } catch {
    return [];
  }
}

/**
 * Get TXT records for a domain (useful for SPF, DKIM, DMARC)
 * @param hostname - The domain to check
 * @returns Array of TXT records
 */
export async function getTXTRecords(hostname: string): Promise<string[]> {
  try {
    const txtRecords = await dns.resolveTxt(hostname);
    // Flatten array of arrays
    return txtRecords.map((record) => record.join(''));
  } catch {
    return [];
  }
}
