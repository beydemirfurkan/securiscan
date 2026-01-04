/**
 * DNS Scanner
 * Performs DNS lookups and subdomain enumeration
 * Including Certificate Transparency (crt.sh) integration
 */

import * as dns from 'dns/promises';
import axios from 'axios';
import { COMMON_SUBDOMAINS } from '../utils/security-constants';

export interface DNSInfo {
  ip: string;
  ipv6?: string;
}

export interface SubdomainInfo {
  name: string;
  ip: string;
  status: 'ACTIVE' | 'CLOUDFLARE' | 'HIDDEN' | 'TAKEOVER_RISK';
  source?: 'wordlist' | 'crt.sh';
}

export interface SubdomainTakeoverResult {
  subdomain: string;
  vulnerable: boolean;
  service: string;
  evidence: string;
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

// ==================== CRT.SH INTEGRATION ====================

/**
 * Get subdomains from Certificate Transparency logs via crt.sh
 * @param hostname - The root domain to search
 * @returns Array of unique subdomains found in CT logs
 */
export async function getSubdomainsFromCT(hostname: string): Promise<string[]> {
  try {
    const response = await axios.get(`https://crt.sh/?q=%.${hostname}&output=json`, {
      timeout: 15000,
      headers: {
        'User-Agent': 'SecuriScan Security Scanner',
      },
    });

    if (!Array.isArray(response.data)) {
      return [];
    }

    // Extract unique subdomains
    const subdomains = new Set<string>();

    for (const cert of response.data) {
      const nameValue = cert.name_value;
      if (!nameValue) continue;

      // Split by newline (certificates can have multiple names)
      const names = nameValue.split('\n');

      for (const name of names) {
        const cleanName = name.trim().toLowerCase();

        // Skip wildcards and the root domain
        if (cleanName.startsWith('*.')) continue;
        if (cleanName === hostname) continue;

        // Only include subdomains of the target domain
        if (cleanName.endsWith(`.${hostname}`)) {
          subdomains.add(cleanName);
        }
      }
    }

    // Limit to prevent overwhelming
    return Array.from(subdomains).slice(0, 200);
  } catch (error) {
    console.error('[DNS] crt.sh lookup failed:', error);
    return [];
  }
}

/**
 * Enhanced subdomain scanning with crt.sh integration
 * @param hostname - The root domain to scan
 * @returns Array of discovered subdomains with their IPs
 */
export async function scanSubdomainsEnhanced(hostname: string): Promise<SubdomainInfo[]> {
  const results: SubdomainInfo[] = [];
  const checkedSubdomains = new Set<string>();

  console.log(`[DNS] Starting enhanced subdomain scan for ${hostname}`);

  // Step 1: Get subdomains from Certificate Transparency
  console.log('[DNS] Fetching subdomains from crt.sh...');
  const ctSubdomains = await getSubdomainsFromCT(hostname);
  console.log(`[DNS] Found ${ctSubdomains.length} subdomains from crt.sh`);

  // Step 2: Combine with wordlist
  const wordlistSubdomains = COMMON_SUBDOMAINS.slice(0, 100).map(s => `${s}.${hostname}`);
  const allSubdomains = [...new Set([...ctSubdomains, ...wordlistSubdomains])];

  console.log(`[DNS] Total unique subdomains to check: ${allSubdomains.length}`);

  // Step 3: Resolve all subdomains
  const batchSize = 15;
  for (let i = 0; i < allSubdomains.length; i += batchSize) {
    const batch = allSubdomains.slice(i, i + batchSize);

    const batchResults = await Promise.allSettled(
      batch.map(async (subdomain) => {
        if (checkedSubdomains.has(subdomain)) return null;
        checkedSubdomains.add(subdomain);

        try {
          const addresses = await dns.resolve4(subdomain);
          const ip = addresses[0];
          const isCloudflare = isCloudflareIP(ip);
          const source = ctSubdomains.includes(subdomain) ? 'crt.sh' : 'wordlist';

          return {
            name: subdomain,
            ip,
            status: isCloudflare ? 'CLOUDFLARE' as const : 'ACTIVE' as const,
            source: source as 'wordlist' | 'crt.sh',
          };
        } catch {
          return null;
        }
      })
    );

    batchResults.forEach((result) => {
      if (result.status === 'fulfilled' && result.value) {
        results.push(result.value);
      }
    });

    // Rate limiting
    if (i + batchSize < allSubdomains.length) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }

  console.log(`[DNS] Found ${results.length} active subdomains`);
  return results;
}

// ==================== SUBDOMAIN TAKEOVER ====================

// Services known to be vulnerable to subdomain takeover
const TAKEOVER_FINGERPRINTS = [
  { service: 'GitHub Pages', pattern: /There isn't a GitHub Pages site here/i },
  { service: 'Heroku', pattern: /No such app|There is no app configured at that hostname/i },
  { service: 'AWS S3', pattern: /NoSuchBucket|The specified bucket does not exist/i },
  { service: 'Azure', pattern: /404 Web Site not found/i },
  { service: 'Shopify', pattern: /Sorry, this shop is currently unavailable/i },
  { service: 'Tumblr', pattern: /There's nothing here|Whatever you were looking for doesn't currently exist/i },
  { service: 'WordPress.com', pattern: /Do you want to register/i },
  { service: 'Zendesk', pattern: /Help Center Closed/i },
  { service: 'Fastly', pattern: /Fastly error: unknown domain/i },
  { service: 'Pantheon', pattern: /404 error unknown site/i },
  { service: 'Netlify', pattern: /Not Found - Request ID/i },
  { service: 'Cargo', pattern: /If you're moving your domain away/i },
  { service: 'Surge', pattern: /project not found/i },
  { service: 'Bitbucket', pattern: /Repository not found/i },
];

/**
 * Check if a subdomain is vulnerable to takeover
 * @param subdomain - The subdomain to check
 * @returns Takeover result
 */
export async function checkSubdomainTakeover(subdomain: string): Promise<SubdomainTakeoverResult | null> {
  try {
    // First check if it has a CNAME record
    let cname: string | null = null;
    try {
      const cnameRecords = await dns.resolveCname(subdomain);
      cname = cnameRecords[0];
    } catch {
      // No CNAME record
      return null;
    }

    if (!cname) return null;

    // Try to fetch the subdomain
    try {
      const response = await axios.get(`http://${subdomain}`, {
        timeout: 10000,
        validateStatus: () => true,
        maxRedirects: 3,
      });

      const body = String(response.data);

      // Check against fingerprints
      for (const fingerprint of TAKEOVER_FINGERPRINTS) {
        if (fingerprint.pattern.test(body)) {
          return {
            subdomain,
            vulnerable: true,
            service: fingerprint.service,
            evidence: `CNAME: ${cname} - Service returned takeover fingerprint`,
          };
        }
      }
    } catch (error: any) {
      // Connection refused or DNS failure with existing CNAME = potential takeover
      if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED') {
        return {
          subdomain,
          vulnerable: true,
          service: 'Unknown',
          evidence: `CNAME: ${cname} - Target does not exist (dangling CNAME)`,
        };
      }
    }

    return null;
  } catch (error) {
    return null;
  }
}

/**
 * Check multiple subdomains for takeover vulnerabilities
 * @param subdomains - Array of subdomains to check
 * @returns Array of vulnerable subdomains
 */
export async function checkSubdomainsTakeover(
  subdomains: SubdomainInfo[]
): Promise<SubdomainTakeoverResult[]> {
  const results: SubdomainTakeoverResult[] = [];

  // Only check subdomains that resolved (they might have dangling CNAMEs to external services)
  const batchSize = 5;
  for (let i = 0; i < subdomains.length; i += batchSize) {
    const batch = subdomains.slice(i, i + batchSize);

    const batchResults = await Promise.allSettled(
      batch.map(s => checkSubdomainTakeover(s.name))
    );

    batchResults.forEach((result) => {
      if (result.status === 'fulfilled' && result.value) {
        results.push(result.value);
      }
    });

    if (i + batchSize < subdomains.length) {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  }

  return results;
}

/**
 * Convert subdomain takeover results to vulnerabilities
 */
export function takeoverToVulnerabilities(
  results: SubdomainTakeoverResult[],
  lang: 'tr' | 'en'
): any[] {
  return results.filter(r => r.vulnerable).map((result, index) => ({
    id: `VULN-TAKEOVER-${index + 1}`,
    title: lang === 'tr'
      ? `Subdomain Takeover Riski: ${result.subdomain}`
      : `Subdomain Takeover Risk: ${result.subdomain}`,
    description: lang === 'tr'
      ? `${result.subdomain} subdomain'i takeover saldırısına açık. Servis: ${result.service}. ${result.evidence}`
      : `${result.subdomain} is vulnerable to subdomain takeover. Service: ${result.service}. ${result.evidence}`,
    severity: 'Kritik',
    location: result.subdomain,
    remediation: lang === 'tr'
      ? 'CNAME kaydını kaldırın veya hedef servisi yeniden yapılandırın.'
      : 'Remove the CNAME record or reconfigure the target service.',
    cvssScore: 8.5,
    exploitExample: `# Saldırgan ${result.service} üzerinde subdomain'i claim edebilir`,
    exploitablePaths: [{
      description: lang === 'tr' ? 'Subdomain Takeover' : 'Subdomain Takeover',
      scenario: lang === 'tr'
        ? 'Saldırgan bu subdomain üzerinde içerik yayınlayabilir'
        : 'Attacker can publish content on this subdomain',
      impact: lang === 'tr'
        ? 'Phishing, malware dağıtımı, cookie çalma'
        : 'Phishing, malware distribution, cookie theft',
    }],
    relatedCves: ['CWE-913'],
  }));
}
