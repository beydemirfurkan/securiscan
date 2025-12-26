/**
 * SSL/TLS Scanner
 * Analyzes SSL certificate and TLS configuration
 */

import * as tls from 'tls';
import { TLS_PROTOCOL_GRADES } from '../utils/security-constants';

export interface SSLInfo {
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  protocol: string;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
}

/**
 * Scan SSL/TLS certificate and configuration
 * @param hostname - The hostname to scan
 * @param port - The port to connect to (default: 443)
 * @returns SSL information including certificate details and TLS grade
 */
export async function scanSSL(hostname: string, port: number = 443): Promise<SSLInfo> {
  return new Promise((resolve, reject) => {
    const timeoutMs = 10000; // 10 second timeout

    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname, // For SNI support
        rejectUnauthorized: false, // We want to analyze even invalid certs
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol(); // e.g., 'TLSv1.3'

          if (!cert || Object.keys(cert).length === 0) {
            socket.end();
            return reject(new Error('No certificate found'));
          }

          const validFrom = new Date(cert.valid_from);
          const validTo = new Date(cert.valid_to);
          const now = new Date();
          const daysRemaining = Math.floor(
            (validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
          );

          // Extract issuer organization
          const issuer = cert.issuer?.O || cert.issuer?.CN || 'Unknown';

          // Determine TLS grade based on protocol version
          const grade = (TLS_PROTOCOL_GRADES[protocol || 'Unknown'] as SSLInfo['grade']) || 'F';

          socket.end();

          resolve({
            issuer,
            validFrom: validFrom.toISOString(),
            validTo: validTo.toISOString(),
            daysRemaining,
            protocol: protocol || 'Unknown',
            grade,
          });
        } catch (error: any) {
          socket.destroy();
          reject(new Error(`SSL analysis failed: ${error.message}`));
        }
      }
    );

    // Set timeout
    socket.setTimeout(timeoutMs);

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('SSL connection timeout'));
    });

    socket.on('error', (error) => {
      socket.destroy();
      reject(new Error(`SSL connection error: ${error.message}`));
    });
  });
}

/**
 * Get default/fallback SSL info for failed scans
 * @returns Default SSLInfo object with 'F' grade
 */
export function getDefaultSSLInfo(): SSLInfo {
  const now = new Date();
  return {
    issuer: 'Unknown',
    validFrom: now.toISOString(),
    validTo: now.toISOString(),
    daysRemaining: 0,
    protocol: 'Unknown',
    grade: 'F',
  };
}
