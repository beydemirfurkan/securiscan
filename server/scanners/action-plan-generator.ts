/**
 * Action Plan Generator
 * Generates prioritized remediation action plan
 */
import { Vulnerability, Severity } from './vulnerability-detector';
import { SSLInfo } from './ssl-scanner';

export interface ActionPlanItem {
  task: string;
  priority: 'URGENT' | 'HIGH' | 'MEDIUM' | 'LOW';
  effort: 'LOW' | 'MEDIUM' | 'HIGH';
  estimatedTime: string;
  delayImpact: string;
}

/**
 * Generate prioritized action plan from vulnerabilities and findings
 */
export function generateActionPlan(
  vulnerabilities: Vulnerability[],
  ssl: SSLInfo,
  lang: 'tr' | 'en'
): ActionPlanItem[] {
  const plan: ActionPlanItem[] = [];

  // 1. SSL Certificate Renewal (if expiring)
  if (ssl.daysRemaining < 30 && ssl.daysRemaining >= 0) {
    plan.push({
      task: lang === 'tr' ? 'SSL sertifikasını yenile' : 'Renew SSL certificate',
      priority: ssl.daysRemaining < 7 ? 'URGENT' : 'HIGH',
      effort: 'LOW',
      estimatedTime: lang === 'tr' ? '30 dakika' : '30 minutes',
      delayImpact: lang === 'tr'
        ? `Sertifika ${ssl.daysRemaining} gün içinde sona erecek`
        : `Certificate expires in ${ssl.daysRemaining} days`,
    });
  } else if (ssl.daysRemaining < 0) {
    plan.push({
      task: lang === 'tr' ? 'SSL sertifikasını acilen yenile (SÜRESİ DOLMUŞ!)' : 'Urgently renew SSL certificate (EXPIRED!)',
      priority: 'URGENT',
      effort: 'LOW',
      estimatedTime: lang === 'tr' ? '30 dakika' : '30 minutes',
      delayImpact: lang === 'tr'
        ? 'Site erişilemez, kullanıcılar uyarı görüyor'
        : 'Site inaccessible, users see warnings',
    });
  }

  // 2. CRITICAL vulnerabilities
  vulnerabilities
    .filter((v) => v.severity === Severity.CRITICAL)
    .forEach((v) => {
      plan.push({
        task: v.remediation,
        priority: 'URGENT',
        effort: estimateEffort(v),
        estimatedTime: estimateTime(v, lang),
        delayImpact: lang === 'tr'
          ? 'Sistem kritik saldırılara açık'
          : 'System exposed to critical attacks',
      });
    });

  // 3. HIGH severity vulnerabilities
  vulnerabilities
    .filter((v) => v.severity === Severity.HIGH)
    .forEach((v) => {
      plan.push({
        task: v.remediation,
        priority: 'HIGH',
        effort: estimateEffort(v),
        estimatedTime: estimateTime(v, lang),
        delayImpact: lang === 'tr'
          ? 'Güvenlik riski yüksek'
          : 'High security risk',
      });
    });

  // 4. MEDIUM severity vulnerabilities
  vulnerabilities
    .filter((v) => v.severity === Severity.MEDIUM)
    .forEach((v) => {
      plan.push({
        task: v.remediation,
        priority: 'MEDIUM',
        effort: estimateEffort(v),
        estimatedTime: estimateTime(v, lang),
        delayImpact: lang === 'tr'
          ? 'Güvenlik açığı mevcut'
          : 'Security gap exists',
      });
    });

  // 5. LOW severity vulnerabilities
  vulnerabilities
    .filter((v) => v.severity === Severity.LOW)
    .forEach((v) => {
      plan.push({
        task: v.remediation,
        priority: 'LOW',
        effort: 'LOW',
        estimatedTime: lang === 'tr' ? '1 saat' : '1 hour',
        delayImpact: lang === 'tr'
          ? 'Küçük iyileştirme'
          : 'Minor improvement',
      });
    });

  // Return top 10 items
  return plan.slice(0, 10);
}

/**
 * Estimate effort for remediation
 */
function estimateEffort(vuln: Vulnerability): 'LOW' | 'MEDIUM' | 'HIGH' {
  // Header configuration is usually low effort
  if (vuln.id.startsWith('VULN-HDR')) {
    return 'LOW';
  }

  // SSL configuration is medium effort
  if (vuln.id.startsWith('VULN-SSL')) {
    return 'MEDIUM';
  }

  // Port/firewall changes are medium effort
  if (vuln.id.startsWith('VULN-PORT')) {
    return 'MEDIUM';
  }

  // Technology updates can be high effort
  if (vuln.id.startsWith('VULN-TECH')) {
    return 'HIGH';
  }

  // Default to medium
  return 'MEDIUM';
}

/**
 * Estimate time for remediation
 */
function estimateTime(vuln: Vulnerability, lang: 'tr' | 'en'): string {
  const effort = estimateEffort(vuln);

  if (lang === 'tr') {
    switch (effort) {
      case 'LOW':
        return '30 dakika - 1 saat';
      case 'MEDIUM':
        return '2-4 saat';
      case 'HIGH':
        return '1-2 gün';
    }
  } else {
    switch (effort) {
      case 'LOW':
        return '30 minutes - 1 hour';
      case 'MEDIUM':
        return '2-4 hours';
      case 'HIGH':
        return '1-2 days';
    }
  }
}
