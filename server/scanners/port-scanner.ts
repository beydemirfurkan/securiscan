/**
 * Port Scanner
 * Scans for open TCP ports using socket connections
 */

import * as net from 'net';
import { TOP_100_PORTS, PORT_DESCRIPTIONS, DANGEROUS_PORTS } from '../utils/common-ports';

export interface PortScanResult {
  port: number;
  status: 'open' | 'closed';
  service?: string;
}

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
