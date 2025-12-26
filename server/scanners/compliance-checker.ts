/**
 * Compliance Checker
 * Checks compliance with security standards:
 * - GDPR (General Data Protection Regulation)
 * - KVKK (Kişisel Verilerin Korunması Kanunu - Turkey)
 * - PCI-DSS (Payment Card Industry Data Security Standard)
 * - OWASP Top 10
 */

import { SSLInfo } from './ssl-scanner';
import { HeaderAnalysis } from './header-scanner';
import { Vulnerability } from './vulnerability-detector';

export interface ComplianceItem {
  standard: string;
  status: 'PASS' | 'FAIL' | 'WARNING';
  details: string;
}

/**
 * Check compliance with various security standards
 */
export function checkCompliance(
  headers: HeaderAnalysis[],
  ssl: SSLInfo,
  vulnerabilities: Vulnerability[],
  hasHTTPS: boolean,
  lang: 'tr' | 'en'
): ComplianceItem[] {
  const compliance: ComplianceItem[] = [];

  // 1. GDPR Compliance
  const gdprStatus = checkGDPRCompliance(headers, ssl, hasHTTPS);
  compliance.push({
    standard: 'GDPR',
    status: gdprStatus.status,
    details: lang === 'tr' ? gdprStatus.detailsTr : gdprStatus.detailsEn,
  });

  // 2. KVKK Compliance (Turkey)
  const kvkkStatus = checkKVKKCompliance(headers, ssl, hasHTTPS);
  compliance.push({
    standard: 'KVKK',
    status: kvkkStatus.status,
    details: lang === 'tr' ? kvkkStatus.detailsTr : kvkkStatus.detailsEn,
  });

  // 3. PCI-DSS Compliance (for payment processing)
  const pciStatus = checkPCIDSSCompliance(headers, ssl, hasHTTPS);
  compliance.push({
    standard: 'PCI-DSS',
    status: pciStatus.status,
    details: lang === 'tr' ? pciStatus.detailsTr : pciStatus.detailsEn,
  });

  // 4. OWASP Top 10
  const owaspStatus = checkOWASPTop10(vulnerabilities);
  compliance.push({
    standard: 'OWASP Top 10',
    status: owaspStatus.status,
    details: lang === 'tr' ? owaspStatus.detailsTr : owaspStatus.detailsEn,
  });

  return compliance;
}

/**
 * Check GDPR compliance
 */
function checkGDPRCompliance(
  headers: HeaderAnalysis[],
  ssl: SSLInfo,
  hasHTTPS: boolean
): { status: 'PASS' | 'FAIL' | 'WARNING'; detailsTr: string; detailsEn: string } {
  const issues: string[] = [];
  const issuesTr: string[] = [];

  // GDPR requires HTTPS for data transmission
  if (!hasHTTPS) {
    issues.push('Missing HTTPS');
    issuesTr.push('HTTPS eksik');
  }

  // Check for security headers
  const requiredHeaders = ['Strict-Transport-Security', 'Content-Security-Policy'];
  requiredHeaders.forEach((header) => {
    const found = headers.find((h) => h.key === header && h.status !== 'WARNING');
    if (!found) {
      issues.push(`Missing ${header}`);
      issuesTr.push(`${header} eksik`);
    }
  });

  // Check SSL grade
  if (ssl.grade === 'F' || ssl.grade === 'D' || ssl.grade === 'C') {
    issues.push('Weak SSL/TLS configuration');
    issuesTr.push('Zayıf SSL/TLS yapılandırması');
  }

  if (issues.length === 0) {
    return {
      status: 'PASS',
      detailsTr: 'Temel GDPR güvenlik gereksinimleri karşılanıyor',
      detailsEn: 'Basic GDPR security requirements are met',
    };
  } else if (issues.length <= 2) {
    return {
      status: 'WARNING',
      detailsTr: `Bazı iyileştirmeler gerekli: ${issuesTr.join(', ')}`,
      detailsEn: `Some improvements needed: ${issues.join(', ')}`,
    };
  } else {
    return {
      status: 'FAIL',
      detailsTr: `Ciddi eksiklikler: ${issuesTr.join(', ')}`,
      detailsEn: `Serious deficiencies: ${issues.join(', ')}`,
    };
  }
}

/**
 * Check KVKK compliance (Turkish data protection law)
 */
function checkKVKKCompliance(
  headers: HeaderAnalysis[],
  ssl: SSLInfo,
  hasHTTPS: boolean
): { status: 'PASS' | 'FAIL' | 'WARNING'; detailsTr: string; detailsEn: string } {
  // KVKK has similar requirements to GDPR
  const issues: string[] = [];
  const issuesTr: string[] = [];

  if (!hasHTTPS) {
    issues.push('HTTPS required for personal data protection');
    issuesTr.push('Kişisel verilerin korunması için HTTPS gerekli');
  }

  const hsts = headers.find((h) => h.key === 'Strict-Transport-Security');
  if (!hsts || hsts.status === 'WARNING') {
    issues.push('HSTS header missing');
    issuesTr.push('HSTS başlığı eksik');
  }

  if (ssl.grade === 'F' || ssl.grade === 'D') {
    issues.push('Inadequate encryption');
    issuesTr.push('Yetersiz şifreleme');
  }

  if (issues.length === 0) {
    return {
      status: 'PASS',
      detailsTr: 'KVKK teknik güvenlik önlemleri uygun',
      detailsEn: 'KVKK technical security measures are appropriate',
    };
  } else if (issues.length <= 1) {
    return {
      status: 'WARNING',
      detailsTr: `İyileştirme önerileri: ${issuesTr.join(', ')}`,
      detailsEn: `Improvement recommendations: ${issues.join(', ')}`,
    };
  } else {
    return {
      status: 'FAIL',
      detailsTr: `KVKK gereksinimlerini karşılamıyor: ${issuesTr.join(', ')}`,
      detailsEn: `Does not meet KVKK requirements: ${issues.join(', ')}`,
    };
  }
}

/**
 * Check PCI-DSS compliance (Payment Card Industry)
 */
function checkPCIDSSCompliance(
  headers: HeaderAnalysis[],
  ssl: SSLInfo,
  hasHTTPS: boolean
): { status: 'PASS' | 'FAIL' | 'WARNING'; detailsTr: string; detailsEn: string } {
  const issues: string[] = [];
  const issuesTr: string[] = [];

  // PCI-DSS Requirement 4: Encrypt transmission of cardholder data
  if (!hasHTTPS) {
    issues.push('HTTPS mandatory for payment processing');
    issuesTr.push('Ödeme işlemleri için HTTPS zorunlu');
  }

  // Must use TLS 1.2 or higher
  if (ssl.protocol !== 'TLSv1.2' && ssl.protocol !== 'TLSv1.3') {
    issues.push('TLS 1.2+ required');
    issuesTr.push('TLS 1.2 veya üzeri gerekli');
  }

  // Security headers
  const csp = headers.find((h) => h.key === 'Content-Security-Policy');
  if (!csp || csp.status === 'WARNING') {
    issues.push('CSP header missing (anti-XSS)');
    issuesTr.push('CSP başlığı eksik (XSS koruması)');
  }

  const xfo = headers.find((h) => h.key === 'X-Frame-Options');
  if (!xfo || xfo.status === 'WARNING') {
    issues.push('X-Frame-Options missing (anti-clickjacking)');
    issuesTr.push('X-Frame-Options eksik (clickjacking koruması)');
  }

  if (issues.length === 0) {
    return {
      status: 'PASS',
      detailsTr: 'PCI-DSS temel şifreleme gereksinimlerini karşılıyor',
      detailsEn: 'Meets PCI-DSS basic encryption requirements',
    };
  } else if (issues.length <= 2) {
    return {
      status: 'WARNING',
      detailsTr: `PCI-DSS için iyileştirmeler: ${issuesTr.join(', ')}`,
      detailsEn: `PCI-DSS improvements needed: ${issues.join(', ')}`,
    };
  } else {
    return {
      status: 'FAIL',
      detailsTr: `PCI-DSS uyumlu değil: ${issuesTr.join(', ')}. Ödeme işlemleri için uygun değil!`,
      detailsEn: `Not PCI-DSS compliant: ${issues.join(', ')}. Not suitable for payment processing!`,
    };
  }
}

/**
 * Check OWASP Top 10 coverage
 */
function checkOWASPTop10(
  vulnerabilities: Vulnerability[]
): { status: 'PASS' | 'FAIL' | 'WARNING'; detailsTr: string; detailsEn: string } {
  const criticalCount = vulnerabilities.filter((v) => v.severity === 'Kritik').length;
  const highCount = vulnerabilities.filter((v) => v.severity === 'Yüksek').length;

  if (criticalCount === 0 && highCount === 0) {
    return {
      status: 'PASS',
      detailsTr: 'OWASP Top 10 kapsamında kritik zafiyet tespit edilmedi',
      detailsEn: 'No critical OWASP Top 10 vulnerabilities detected',
    };
  } else if (criticalCount === 0 && highCount <= 2) {
    return {
      status: 'WARNING',
      detailsTr: `${highCount} yüksek öncelikli zafiyet tespit edildi`,
      detailsEn: `${highCount} high-priority vulnerabilities detected`,
    };
  } else {
    return {
      status: 'FAIL',
      detailsTr: `${criticalCount} kritik ve ${highCount} yüksek öncelikli zafiyet tespit edildi (OWASP Top 10)`,
      detailsEn: `${criticalCount} critical and ${highCount} high-priority vulnerabilities detected (OWASP Top 10)`,
    };
  }
}
