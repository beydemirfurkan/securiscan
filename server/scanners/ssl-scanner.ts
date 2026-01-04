/**
 * SSL/TLS Scanner
 * Analyzes SSL certificate, TLS configuration, and cipher suites
 */

import * as tls from 'tls';
import * as https from 'https';
import { TLS_PROTOCOL_GRADES } from '../utils/security-constants';

export interface SSLInfo {
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  protocol: string;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  cipher?: CipherInfo;
  certificateChain?: CertificateChainInfo;
  warnings?: string[];
}

export interface CipherInfo {
  name: string;
  version: string;
  bits: number;
  forwardSecrecy: boolean;
  isWeak: boolean;
}

export interface CertificateChainInfo {
  length: number;
  isValid: boolean;
  selfSigned: boolean;
  certificates: Array<{
    subject: string;
    issuer: string;
    validTo: string;
  }>;
}

// Weak cipher patterns that should be avoided
const WEAK_CIPHERS = [
  /^RC4/i,
  /^DES/i,
  /^3DES/i,
  /^EXPORT/i,
  /^NULL/i,
  /^anon/i,
  /MD5/i,
  /CBC.*SHA$/i, // CBC with SHA1 (vulnerable to BEAST)
];

// Forward secrecy cipher patterns
const FORWARD_SECRECY_PATTERNS = [
  /^ECDHE/i,
  /^DHE/i,
  /^ECDH/i,
];

/**
 * Scan SSL/TLS certificate and configuration
 * @param hostname - The hostname to scan
 * @param port - The port to connect to (default: 443)
 * @returns SSL information including certificate details, cipher suite, and TLS grade
 */
export async function scanSSL(hostname: string, port: number = 443): Promise<SSLInfo> {
  return new Promise((resolve, reject) => {
    const timeoutMs = 10000; // 10 second timeout
    const warnings: string[] = [];

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
          const cipherInfo = socket.getCipher();

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

          // Analyze cipher suite
          const cipher = analyzeCipher(cipherInfo, warnings);

          // Analyze certificate chain
          const certificateChain = analyzeCertificateChain(cert, warnings);

          // Check for common issues
          if (daysRemaining < 30) {
            warnings.push(`Certificate expires in ${daysRemaining} days`);
          }
          if (daysRemaining < 0) {
            warnings.push('Certificate has expired!');
          }
          if (certificateChain.selfSigned) {
            warnings.push('Self-signed certificate detected');
          }

          // Calculate enhanced grade
          const grade = calculateEnhancedGrade(protocol, cipher, certificateChain, daysRemaining, warnings);

          socket.end();

          resolve({
            issuer,
            validFrom: validFrom.toISOString(),
            validTo: validTo.toISOString(),
            daysRemaining,
            protocol: protocol || 'Unknown',
            grade,
            cipher,
            certificateChain,
            warnings: warnings.length > 0 ? warnings : undefined,
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
 * Analyze cipher suite for security
 */
function analyzeCipher(cipherInfo: tls.CipherNameAndProtocol | null, warnings: string[]): CipherInfo {
  if (!cipherInfo) {
    return {
      name: 'Unknown',
      version: 'Unknown',
      bits: 0,
      forwardSecrecy: false,
      isWeak: true,
    };
  }

  const cipherName = cipherInfo.name || 'Unknown';
  const version = cipherInfo.version || 'Unknown';

  // Check if cipher is weak
  const isWeak = WEAK_CIPHERS.some(pattern => pattern.test(cipherName));
  if (isWeak) {
    warnings.push(`Weak cipher detected: ${cipherName}`);
  }

  // Check for forward secrecy
  const forwardSecrecy = FORWARD_SECRECY_PATTERNS.some(pattern => pattern.test(cipherName));
  if (!forwardSecrecy) {
    warnings.push('No forward secrecy - past sessions can be decrypted if private key is compromised');
  }

  // Extract key bits from cipher name (e.g., AES256 -> 256)
  const bitsMatch = cipherName.match(/(\d{3})/);
  const bits = bitsMatch ? parseInt(bitsMatch[1], 10) : 128;

  if (bits < 128) {
    warnings.push(`Weak key length: ${bits} bits`);
  }

  return {
    name: cipherName,
    version,
    bits,
    forwardSecrecy,
    isWeak,
  };
}

/**
 * Analyze certificate chain
 */
function analyzeCertificateChain(
  cert: tls.PeerCertificate,
  warnings: string[]
): CertificateChainInfo {
  const certificates: CertificateChainInfo['certificates'] = [];
  let currentCert: tls.DetailedPeerCertificate | undefined = cert as tls.DetailedPeerCertificate;
  let chainLength = 0;
  const maxChainLength = 10; // Prevent infinite loops

  while (currentCert && chainLength < maxChainLength) {
    certificates.push({
      subject: currentCert.subject?.CN || currentCert.subject?.O || 'Unknown',
      issuer: currentCert.issuer?.CN || currentCert.issuer?.O || 'Unknown',
      validTo: currentCert.valid_to || 'Unknown',
    });

    chainLength++;

    // Move to issuer certificate if available
    if (currentCert.issuerCertificate && currentCert.issuerCertificate !== currentCert) {
      currentCert = currentCert.issuerCertificate as tls.DetailedPeerCertificate;
    } else {
      break;
    }
  }

  // Check if self-signed (subject === issuer for root)
  const selfSigned = certificates.length === 1 &&
    certificates[0].subject === certificates[0].issuer;

  // Validate chain
  const isValid = certificates.length > 0 && !selfSigned;

  if (chainLength === 1 && !selfSigned) {
    warnings.push('Incomplete certificate chain - intermediate certificates may be missing');
  }

  return {
    length: chainLength,
    isValid,
    selfSigned,
    certificates,
  };
}

/**
 * Calculate enhanced SSL grade based on multiple factors
 */
function calculateEnhancedGrade(
  protocol: string | null,
  cipher: CipherInfo,
  chain: CertificateChainInfo,
  daysRemaining: number,
  warnings: string[]
): SSLInfo['grade'] {
  let score = 100;

  // Protocol scoring
  switch (protocol) {
    case 'TLSv1.3':
      // Best protocol
      break;
    case 'TLSv1.2':
      score -= 5;
      break;
    case 'TLSv1.1':
      score -= 20;
      warnings.push('TLS 1.1 is deprecated');
      break;
    case 'TLSv1.0':
      score -= 30;
      warnings.push('TLS 1.0 is deprecated and insecure');
      break;
    case 'SSLv3':
      score -= 50;
      warnings.push('SSLv3 is vulnerable to POODLE attack');
      break;
    default:
      score -= 40;
  }

  // Cipher scoring
  if (cipher.isWeak) {
    score -= 30;
  }
  if (!cipher.forwardSecrecy) {
    score -= 15;
  }
  if (cipher.bits < 128) {
    score -= 20;
  } else if (cipher.bits < 256) {
    score -= 5;
  }

  // Certificate chain scoring
  if (chain.selfSigned) {
    score -= 25;
  }
  if (!chain.isValid) {
    score -= 15;
  }

  // Expiration scoring
  if (daysRemaining < 0) {
    score -= 50; // Expired
  } else if (daysRemaining < 7) {
    score -= 20;
  } else if (daysRemaining < 30) {
    score -= 10;
  }

  // Convert score to grade
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
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
