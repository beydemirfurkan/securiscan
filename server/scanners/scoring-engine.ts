/**
 * Security Scoring Engine
 * Calculates overall security score (0-100) based on findings
 */
import { Vulnerability, Severity } from './vulnerability-detector';
import { SSLInfo } from './ssl-scanner';
import { HeaderAnalysis } from './header-scanner';

export interface ScoreBreakdown {
  total: number;
  vulnerabilityPenalty: number;
  sslPenalty: number;
  headerPenalty: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
}

/**
 * Calculate security score from 0-100
 * Higher is better
 */
export function calculateSecurityScore(
  vulnerabilities: Vulnerability[],
  ssl: SSLInfo,
  headers: HeaderAnalysis[]
): ScoreBreakdown {
  let score = 100;
  let vulnPenalty = 0;
  let sslPenalty = 0;
  let headerPenalty = 0;

  // 1. Vulnerability penalties
  vulnerabilities.forEach((vuln) => {
    let penalty = 0;
    switch (vuln.severity) {
      case Severity.CRITICAL:
        penalty = 20;
        break;
      case Severity.HIGH:
        penalty = 10;
        break;
      case Severity.MEDIUM:
        penalty = 5;
        break;
      case Severity.LOW:
        penalty = 2;
        break;
      case Severity.INFO:
        penalty = 1;
        break;
    }
    vulnPenalty += penalty;
  });

  score -= vulnPenalty;

  // 2. SSL/TLS grade penalty
  const sslGradePenalties: Record<string, number> = {
    'A+': 0,
    'A': 0,
    'B': -5,
    'C': -10,
    'D': -15,
    'F': -25,
  };

  sslPenalty = Math.abs(sslGradePenalties[ssl.grade] || -25);
  score += sslGradePenalties[ssl.grade] || -25;

  // 3. Missing critical security headers
  const criticalHeaders = [
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-Content-Type-Options',
  ];

  const missingCritical = headers.filter(
    (h) => criticalHeaders.includes(h.key) && h.status === 'WARNING' && h.value === 'Missing'
  ).length;

  headerPenalty = missingCritical * 3;
  score -= headerPenalty;

  // Clamp score between 0-100
  score = Math.max(0, Math.min(100, score));

  // Determine letter grade
  let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  if (score >= 95) grade = 'A+';
  else if (score >= 85) grade = 'A';
  else if (score >= 70) grade = 'B';
  else if (score >= 55) grade = 'C';
  else if (score >= 40) grade = 'D';
  else grade = 'F';

  return {
    total: Math.round(score),
    vulnerabilityPenalty: vulnPenalty,
    sslPenalty,
    headerPenalty,
    grade,
  };
}
