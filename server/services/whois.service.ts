/**
 * WHOIS Service
 * Provides domain registration and ownership information
 */

import whois from 'whois';

export interface WhoisInfo {
  domainName: string;
  registrar: string;
  creationDate: string | null;
  expirationDate: string | null;
  lastUpdated: string | null;
  nameServers: string[];
  status: string[];
  dnssec: string;
}

/**
 * Perform WHOIS lookup for a domain
 * @param domain - Domain name to lookup
 * @returns WHOIS information or null if lookup fails
 */
export async function getWhoisInfo(domain: string): Promise<WhoisInfo | null> {
  return new Promise((resolve) => {
    // Remove protocol and path, keep only domain
    const cleanDomain = domain
      .replace(/^https?:\/\//, '')
      .replace(/^www\./, '')
      .split('/')[0]
      .split(':')[0];

    whois.lookup(cleanDomain, (err: Error | null, data: string) => {
      if (err) {
        console.error('[WHOIS] Lookup failed:', err.message);
        resolve(null);
        return;
      }

      try {
        const parsed = parseWhoisData(data, cleanDomain);
        resolve(parsed);
      } catch (error: any) {
        console.error('[WHOIS] Parse error:', error.message);
        resolve(null);
      }
    });
  });
}

/**
 * Parse raw WHOIS data
 */
function parseWhoisData(data: string, domain: string): WhoisInfo {
  const lines = data.split('\n');
  const info: WhoisInfo = {
    domainName: domain,
    registrar: 'Unknown',
    creationDate: null,
    expirationDate: null,
    lastUpdated: null,
    nameServers: [],
    status: [],
    dnssec: 'Unknown',
  };

  lines.forEach((line) => {
    const lower = line.toLowerCase();

    // Registrar
    if (lower.includes('registrar:') && !lower.includes('iana')) {
      info.registrar = line.split(':')[1]?.trim() || info.registrar;
    }

    // Creation date
    if (lower.includes('creation date:') || lower.includes('created:')) {
      const dateStr = line.split(':').slice(1).join(':').trim();
      info.creationDate = parseDateString(dateStr);
    }

    // Expiration date
    if (lower.includes('expir') && lower.includes('date:')) {
      const dateStr = line.split(':').slice(1).join(':').trim();
      info.expirationDate = parseDateString(dateStr);
    }

    // Last updated
    if (lower.includes('updated date:') || lower.includes('last updated:')) {
      const dateStr = line.split(':').slice(1).join(':').trim();
      info.lastUpdated = parseDateString(dateStr);
    }

    // Name servers
    if (lower.includes('name server:') || lower.includes('nserver:')) {
      const ns = line.split(':')[1]?.trim().toLowerCase();
      if (ns && !info.nameServers.includes(ns)) {
        info.nameServers.push(ns);
      }
    }

    // Status
    if (lower.includes('status:') || lower.includes('domain status:')) {
      const status = line.split(':')[1]?.trim();
      if (status && !info.status.includes(status)) {
        info.status.push(status);
      }
    }

    // DNSSEC
    if (lower.includes('dnssec:')) {
      info.dnssec = line.split(':')[1]?.trim() || info.dnssec;
    }
  });

  return info;
}

/**
 * Parse date string from WHOIS data
 */
function parseDateString(dateStr: string): string | null {
  if (!dateStr) return null;

  try {
    // Remove timezone info and clean up
    const cleaned = dateStr.split('T')[0].trim();
    const date = new Date(cleaned);

    if (isNaN(date.getTime())) {
      return null;
    }

    return date.toISOString();
  } catch {
    return null;
  }
}

/**
 * Calculate days until domain expiration
 */
export function getDaysUntilExpiration(whoisInfo: WhoisInfo | null): number {
  if (!whoisInfo?.expirationDate) {
    return -1;
  }

  try {
    const expirationDate = new Date(whoisInfo.expirationDate);
    const today = new Date();
    const diffTime = expirationDate.getTime() - today.getTime();
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    return diffDays;
  } catch {
    return -1;
  }
}
