/**
 * Port Scanner
 * Scans for open TCP ports using socket connections
 * Enhanced with banner grabbing for service version detection
 */

import * as net from 'net';
import { TOP_100_PORTS, PORT_DESCRIPTIONS, DANGEROUS_PORTS } from '../utils/common-ports';

export interface PortScanResult {
  port: number;
  status: 'open' | 'closed';
  service?: string;
}

export interface BannerInfo {
  port: number;
  service: string;
  banner: string;
  version?: string;
  product?: string;
  os?: string;
  risk?: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  vulnerabilityHint?: string;
}

export interface EnhancedPortResult {
  port: number;
  status: 'open' | 'closed' | 'filtered';
  service: string;
  banner?: BannerInfo;
}

// Service-specific probes for banner grabbing
const SERVICE_PROBES: Record<number, { probe: string; timeout: number }> = {
  21: { probe: '', timeout: 3000 }, // FTP - usually sends banner automatically
  22: { probe: '', timeout: 3000 }, // SSH - sends banner automatically
  23: { probe: '', timeout: 3000 }, // Telnet - sends banner automatically
  25: { probe: 'EHLO scanner\r\n', timeout: 3000 }, // SMTP
  80: { probe: 'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n', timeout: 3000 }, // HTTP
  110: { probe: '', timeout: 3000 }, // POP3 - sends banner automatically
  143: { probe: '', timeout: 3000 }, // IMAP - sends banner automatically
  443: { probe: '', timeout: 3000 }, // HTTPS - needs TLS
  465: { probe: '', timeout: 3000 }, // SMTPS
  587: { probe: 'EHLO scanner\r\n', timeout: 3000 }, // SMTP Submission
  993: { probe: '', timeout: 3000 }, // IMAPS
  995: { probe: '', timeout: 3000 }, // POP3S
  3306: { probe: '', timeout: 3000 }, // MySQL - sends greeting
  5432: { probe: '', timeout: 3000 }, // PostgreSQL
  6379: { probe: 'INFO\r\n', timeout: 3000 }, // Redis
  27017: { probe: '', timeout: 3000 }, // MongoDB
  8080: { probe: 'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n', timeout: 3000 }, // HTTP Alt
  8443: { probe: '', timeout: 3000 }, // HTTPS Alt
};

// Version extraction patterns
const VERSION_PATTERNS: Array<{
  pattern: RegExp;
  service: string;
  extract: (match: RegExpMatchArray) => { product?: string; version?: string; os?: string };
}> = [
  // SSH
  {
    pattern: /SSH-[\d.]+-(OpenSSH[_\s]*([\d.p]+))/i,
    service: 'SSH',
    extract: (m) => ({ product: 'OpenSSH', version: m[2] }),
  },
  {
    pattern: /SSH-[\d.]+-(.+)/,
    service: 'SSH',
    extract: (m) => ({ product: 'SSH', version: m[1]?.trim() }),
  },
  // HTTP Server headers
  {
    pattern: /Server:\s*(Apache)\/([\d.]+)/i,
    service: 'HTTP',
    extract: (m) => ({ product: 'Apache', version: m[2] }),
  },
  {
    pattern: /Server:\s*(nginx)\/([\d.]+)/i,
    service: 'HTTP',
    extract: (m) => ({ product: 'nginx', version: m[2] }),
  },
  {
    pattern: /Server:\s*(Microsoft-IIS)\/([\d.]+)/i,
    service: 'HTTP',
    extract: (m) => ({ product: 'Microsoft IIS', version: m[2] }),
  },
  {
    pattern: /Server:\s*(cloudflare)/i,
    service: 'HTTP',
    extract: () => ({ product: 'Cloudflare' }),
  },
  {
    pattern: /Server:\s*(AmazonS3)/i,
    service: 'HTTP',
    extract: () => ({ product: 'Amazon S3' }),
  },
  {
    pattern: /Server:\s*(.+)/i,
    service: 'HTTP',
    extract: (m) => ({ product: m[1]?.trim() }),
  },
  // FTP
  {
    pattern: /220[- ].*?(vsftpd)\s*([\d.]+)/i,
    service: 'FTP',
    extract: (m) => ({ product: 'vsftpd', version: m[2] }),
  },
  {
    pattern: /220[- ].*?(ProFTPD)\s*([\d.]+)/i,
    service: 'FTP',
    extract: (m) => ({ product: 'ProFTPD', version: m[2] }),
  },
  {
    pattern: /220[- ].*?(FileZilla Server)\s*([\d.]+)/i,
    service: 'FTP',
    extract: (m) => ({ product: 'FileZilla Server', version: m[2] }),
  },
  // SMTP
  {
    pattern: /220[- ].*?(Postfix)/i,
    service: 'SMTP',
    extract: () => ({ product: 'Postfix' }),
  },
  {
    pattern: /220[- ].*?(Exim)\s*([\d.]+)/i,
    service: 'SMTP',
    extract: (m) => ({ product: 'Exim', version: m[2] }),
  },
  {
    pattern: /220[- ].*?(Microsoft ESMTP)/i,
    service: 'SMTP',
    extract: () => ({ product: 'Microsoft Exchange' }),
  },
  // MySQL
  {
    pattern: /mysql_native_password/i,
    service: 'MySQL',
    extract: () => ({ product: 'MySQL' }),
  },
  {
    pattern: /([\d.]+)-MariaDB/i,
    service: 'MySQL',
    extract: (m) => ({ product: 'MariaDB', version: m[1] }),
  },
  // Redis
  {
    pattern: /redis_version:([\d.]+)/i,
    service: 'Redis',
    extract: (m) => ({ product: 'Redis', version: m[1] }),
  },
  // MongoDB
  {
    pattern: /MongoDB/i,
    service: 'MongoDB',
    extract: () => ({ product: 'MongoDB' }),
  },
  // PostgreSQL
  {
    pattern: /PostgreSQL/i,
    service: 'PostgreSQL',
    extract: () => ({ product: 'PostgreSQL' }),
  },
];

// Known vulnerable versions (simplified check)
const VULNERABLE_VERSIONS: Array<{
  product: string;
  versionPattern: RegExp;
  risk: 'HIGH' | 'MEDIUM' | 'LOW';
  hint: string;
}> = [
  { product: 'OpenSSH', versionPattern: /^[0-6]\./, risk: 'HIGH', hint: 'OpenSSH < 7.0 has known vulnerabilities' },
  { product: 'OpenSSH', versionPattern: /^7\.[0-3]/, risk: 'MEDIUM', hint: 'OpenSSH 7.0-7.3 may have security issues' },
  { product: 'Apache', versionPattern: /^2\.[0-3]\./, risk: 'MEDIUM', hint: 'Apache < 2.4 is outdated' },
  { product: 'nginx', versionPattern: /^1\.[0-9]\./, risk: 'MEDIUM', hint: 'nginx < 1.10 is outdated' },
  { product: 'nginx', versionPattern: /^0\./, risk: 'HIGH', hint: 'nginx 0.x is very outdated' },
  { product: 'vsftpd', versionPattern: /^2\.3\.4$/, risk: 'HIGH', hint: 'vsftpd 2.3.4 has backdoor vulnerability (CVE-2011-2523)' },
  { product: 'ProFTPD', versionPattern: /^1\.[0-2]\./, risk: 'HIGH', hint: 'ProFTPD < 1.3 has known vulnerabilities' },
  { product: 'Exim', versionPattern: /^4\.[0-8]/, risk: 'HIGH', hint: 'Exim < 4.9 has remote code execution vulnerabilities' },
  { product: 'Redis', versionPattern: /^[0-5]\./, risk: 'MEDIUM', hint: 'Redis < 6.0 lacks important security features' },
];

/**
 * Check if a single port is open
 * @param host - The hostname or IP to scan
 * @param port - The port number to check
 * @param timeout - Timeout in milliseconds (default: 2000)
 * @returns true if port is open, false otherwise
 */
function checkPort(host: string, port: number, timeout: number = 2000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();

    // Set connection timeout
    socket.setTimeout(timeout);

    socket.on('connect', () => {
      socket.destroy();
      resolve(true); // Port is open
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(false); // Port is closed/filtered
    });

    socket.on('error', () => {
      socket.destroy();
      resolve(false); // Port is closed/filtered
    });

    // Attempt connection
    socket.connect(port, host);
  });
}

/**
 * Scan multiple ports for a host
 * @param hostname - The hostname or IP to scan
 * @param ports - Array of ports to scan (default: TOP_100_PORTS)
 * @param concurrentScans - Number of concurrent port checks (default: 10)
 * @returns Array of open port numbers
 */
export async function scanPorts(
  hostname: string,
  ports: number[] = TOP_100_PORTS,
  concurrentScans: number = 10
): Promise<number[]> {
  const openPorts: number[] = [];

  // Scan in batches to avoid overwhelming the target or network
  for (let i = 0; i < ports.length; i += concurrentScans) {
    const batch = ports.slice(i, i + concurrentScans);

    // Check all ports in the current batch concurrently
    const results = await Promise.all(batch.map((port) => checkPort(hostname, port)));

    // Collect open ports
    batch.forEach((port, idx) => {
      if (results[idx]) {
        openPorts.push(port);
      }
    });

    // Small delay between batches to be respectful to the target
    if (i + concurrentScans < ports.length) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }

  return openPorts;
}

/**
 * Get detailed information about scanned ports
 * @param openPorts - Array of open port numbers
 * @returns Array of port scan results with service names
 */
export function getPortDetails(openPorts: number[]): PortScanResult[] {
  return openPorts.map((port) => ({
    port,
    status: 'open' as const,
    service: PORT_DESCRIPTIONS[port] || 'Unknown Service',
  }));
}

/**
 * Identify dangerous open ports
 * @param openPorts - Array of open port numbers
 * @returns Array of dangerous port numbers that are open
 */
export function getDangerousPorts(openPorts: number[]): number[] {
  return openPorts.filter((port) => DANGEROUS_PORTS.includes(port));
}

/**
 * Categorize open ports by service type
 * @param openPorts - Array of open port numbers
 * @returns Object with categorized ports
 */
export function categorizeOpenPorts(openPorts: number[]): {
  web: number[];
  database: number[];
  email: number[];
  remoteAccess: number[];
  other: number[];
} {
  const categories = {
    web: [80, 443, 8000, 8080, 8443, 8888, 3000, 4200, 5000, 9000],
    database: [3306, 5432, 27017, 6379, 1433, 1521, 11211, 5984, 9200, 9300],
    email: [25, 110, 143, 465, 587, 993, 995],
    remoteAccess: [22, 23, 3389, 5900],
    other: [] as number[],
  };

  const result: typeof categories = {
    web: [],
    database: [],
    email: [],
    remoteAccess: [],
    other: [],
  };

  openPorts.forEach((port) => {
    if (categories.web.includes(port)) {
      result.web.push(port);
    } else if (categories.database.includes(port)) {
      result.database.push(port);
    } else if (categories.email.includes(port)) {
      result.email.push(port);
    } else if (categories.remoteAccess.includes(port)) {
      result.remoteAccess.push(port);
    } else {
      result.other.push(port);
    }
  });

  return result;
}

// ==================== BANNER GRABBING ====================

/**
 * Grab banner from a single open port
 * @param host - The hostname or IP
 * @param port - The port number
 * @returns Banner information or null
 */
export async function grabBanner(host: string, port: number): Promise<BannerInfo | null> {
  return new Promise((resolve) => {
    const probeConfig = SERVICE_PROBES[port] || { probe: '', timeout: 3000 };
    const socket = new net.Socket();
    let bannerData = '';
    let resolved = false;

    const finish = () => {
      if (resolved) return;
      resolved = true;
      socket.destroy();

      if (!bannerData) {
        resolve(null);
        return;
      }

      // Parse the banner
      const bannerInfo = parseBanner(port, bannerData);
      resolve(bannerInfo);
    };

    socket.setTimeout(probeConfig.timeout);

    socket.on('connect', () => {
      // Send probe if needed
      if (probeConfig.probe) {
        socket.write(probeConfig.probe);
      }
    });

    socket.on('data', (data) => {
      bannerData += data.toString('utf8');
      // Limit banner size
      if (bannerData.length > 2048) {
        finish();
      }
    });

    socket.on('timeout', finish);
    socket.on('error', finish);
    socket.on('close', finish);

    // Auto-finish after timeout
    setTimeout(finish, probeConfig.timeout + 500);

    socket.connect(port, host);
  });
}

/**
 * Parse banner string to extract version information
 */
function parseBanner(port: number, rawBanner: string): BannerInfo {
  const banner = rawBanner.substring(0, 500); // Limit display length
  const serviceName = PORT_DESCRIPTIONS[port] || 'Unknown';

  const result: BannerInfo = {
    port,
    service: serviceName,
    banner: banner.replace(/[\x00-\x1F\x7F]/g, ' ').trim(), // Clean control chars
    risk: 'INFO',
  };

  // Try to match version patterns
  for (const vp of VERSION_PATTERNS) {
    const match = rawBanner.match(vp.pattern);
    if (match) {
      const extracted = vp.extract(match);
      result.product = extracted.product;
      result.version = extracted.version;
      result.os = extracted.os;
      break;
    }
  }

  // Check for vulnerable versions
  if (result.product && result.version) {
    for (const vuln of VULNERABLE_VERSIONS) {
      if (result.product === vuln.product && vuln.versionPattern.test(result.version)) {
        result.risk = vuln.risk;
        result.vulnerabilityHint = vuln.hint;
        break;
      }
    }
  }

  return result;
}

/**
 * Scan ports with banner grabbing
 * @param hostname - The hostname or IP to scan
 * @param ports - Array of ports to scan (default: TOP_100_PORTS)
 * @param grabBanners - Whether to grab banners (default: true)
 * @returns Array of enhanced port results with banners
 */
export async function scanPortsEnhanced(
  hostname: string,
  ports: number[] = TOP_100_PORTS,
  grabBanners: boolean = true
): Promise<EnhancedPortResult[]> {
  console.log(`[PortScanner] Starting enhanced scan for ${hostname} (${ports.length} ports)`);

  const results: EnhancedPortResult[] = [];
  const concurrentScans = 10;

  // Phase 1: Find open ports
  for (let i = 0; i < ports.length; i += concurrentScans) {
    const batch = ports.slice(i, i + concurrentScans);

    const batchResults = await Promise.all(
      batch.map(async (port) => {
        const isOpen = await checkPort(hostname, port);
        return { port, isOpen };
      })
    );

    for (const { port, isOpen } of batchResults) {
      if (isOpen) {
        results.push({
          port,
          status: 'open',
          service: PORT_DESCRIPTIONS[port] || 'Unknown',
        });
      }
    }

    if (i + concurrentScans < ports.length) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }

  console.log(`[PortScanner] Found ${results.length} open ports`);

  // Phase 2: Grab banners for open ports
  if (grabBanners && results.length > 0) {
    console.log('[PortScanner] Grabbing banners...');

    const bannerBatchSize = 5;
    for (let i = 0; i < results.length; i += bannerBatchSize) {
      const batch = results.slice(i, i + bannerBatchSize);

      const banners = await Promise.all(
        batch.map((result) => grabBanner(hostname, result.port))
      );

      banners.forEach((banner, idx) => {
        if (banner) {
          batch[idx].banner = banner;
          // Update service name if we got better info
          if (banner.product) {
            batch[idx].service = banner.product + (banner.version ? ` ${banner.version}` : '');
          }
        }
      });

      if (i + bannerBatchSize < results.length) {
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }

    const bannersGrabbed = results.filter(r => r.banner).length;
    console.log(`[PortScanner] Grabbed ${bannersGrabbed} banners`);
  }

  return results;
}

/**
 * Convert port scan results to vulnerabilities
 * @param results - Enhanced port results
 * @param lang - Language for descriptions
 * @returns Array of vulnerabilities
 */
export function portsToVulnerabilities(
  results: EnhancedPortResult[],
  lang: 'tr' | 'en'
): any[] {
  const vulnerabilities: any[] = [];

  // Check for dangerous ports
  const dangerousPorts = results.filter(r => DANGEROUS_PORTS.includes(r.port));

  for (const portResult of dangerousPorts) {
    vulnerabilities.push({
      id: `VULN-PORT-${portResult.port}`,
      title: lang === 'tr'
        ? `Tehlikeli Port Açık: ${portResult.port} (${portResult.service})`
        : `Dangerous Port Open: ${portResult.port} (${portResult.service})`,
      description: lang === 'tr'
        ? `Port ${portResult.port} (${portResult.service}) açık ve potansiyel güvenlik riski oluşturuyor.`
        : `Port ${portResult.port} (${portResult.service}) is open and poses potential security risk.`,
      severity: 'Orta',
      location: `TCP/${portResult.port}`,
      remediation: lang === 'tr'
        ? 'Bu port gerekli değilse kapatın. Gerekliyse güvenlik duvarı kuralları ile erişimi sınırlayın.'
        : 'Close this port if not needed. If required, restrict access using firewall rules.',
      cvssScore: 5.5,
      exploitExample: `nmap -sV -p ${portResult.port} [TARGET]`,
      exploitablePaths: [],
      relatedCves: [],
    });
  }

  // Check for vulnerable service versions
  for (const portResult of results) {
    if (portResult.banner?.risk === 'HIGH' || portResult.banner?.risk === 'MEDIUM') {
      vulnerabilities.push({
        id: `VULN-VERSION-${portResult.port}`,
        title: lang === 'tr'
          ? `Güvenlik Açığı Olan Servis Versiyonu: ${portResult.banner.product} ${portResult.banner.version || ''}`
          : `Vulnerable Service Version: ${portResult.banner.product} ${portResult.banner.version || ''}`,
        description: lang === 'tr'
          ? portResult.banner.vulnerabilityHint || `${portResult.banner.product} eski bir versiyon kullanıyor.`
          : portResult.banner.vulnerabilityHint || `${portResult.banner.product} is using an outdated version.`,
        severity: portResult.banner.risk === 'HIGH' ? 'Yüksek' : 'Orta',
        location: `TCP/${portResult.port}`,
        remediation: lang === 'tr'
          ? `${portResult.banner.product} servisini en güncel versiyona yükseltin.`
          : `Upgrade ${portResult.banner.product} to the latest version.`,
        cvssScore: portResult.banner.risk === 'HIGH' ? 7.5 : 5.5,
        exploitExample: `# Banner: ${portResult.banner.banner.substring(0, 100)}`,
        exploitablePaths: [{
          description: lang === 'tr' ? 'Versiyon Bazlı Saldırı' : 'Version-Based Attack',
          scenario: lang === 'tr'
            ? 'Saldırgan bilinen güvenlik açıklarını kullanabilir'
            : 'Attacker can exploit known vulnerabilities',
          impact: lang === 'tr'
            ? 'Uzaktan kod çalıştırma, veri sızıntısı'
            : 'Remote code execution, data breach',
        }],
        relatedCves: [],
      });
    }
  }

  return vulnerabilities;
}
