/**
 * Scan Progress Service
 * Manages real-time scan progress updates via Server-Sent Events
 */

import { EventEmitter } from 'events';

export interface ScanProgress {
  phase: string;
  message: string;
  progress: number; // 0-100
  type: 'info' | 'success' | 'warning' | 'error' | 'neutral';
  details?: string;
}

// Progress messages for each phase
export const PROGRESS_MESSAGES = {
  tr: {
    connecting: 'Hedef sisteme bağlantı kuruluyor...',
    dns: 'DNS kayıtları ve IP adresi çözümleniyor...',
    dns_complete: 'DNS kayıtları çözümlendi',
    ssl: 'SSL/TLS güvenlik sertifikası analiz ediliyor...',
    ssl_complete: 'SSL sertifikası analizi tamamlandı',
    headers: 'HTTP güvenlik başlıkları inceleniyor...',
    headers_complete: 'Başlık analizi tamamlandı',
    cookies: 'Cookie güvenliği kontrol ediliyor...',
    ports: 'Port taraması yapılıyor...',
    ports_complete: 'Port taraması tamamlandı',
    tech: 'Teknoloji tespiti yapılıyor...',
    tech_complete: 'Teknoloji tespiti tamamlandı',
    cve: 'CVE veritabanı ile eşleştirme yapılıyor...',
    cve_complete: 'CVE korelasyonu tamamlandı',
    subdomains: 'Alt alan adları taranıyor...',
    subdomains_complete: 'Alt alan adı taraması tamamlandı',
    content: 'Sayfa içeriği analiz ediliyor...',
    content_complete: 'İçerik analizi tamamlandı',
    active: 'Aktif güvenlik taraması başlatıldı...',
    active_sqli: 'SQL Injection vektörleri test ediliyor...',
    active_xss: 'XSS açıkları taranıyor...',
    active_traversal: 'Dizin gezinme açıkları kontrol ediliyor...',
    active_cors: 'CORS yapılandırması test ediliyor...',
    active_redirect: 'Açık yönlendirme açıkları taranıyor...',
    active_files: 'Hassas dosyalar aranıyor...',
    active_complete: 'Aktif tarama tamamlandı',
    http_methods: 'HTTP metodları test ediliyor...',
    http_methods_complete: 'HTTP metod taraması tamamlandı',
    robots: 'Robots.txt ve security.txt analiz ediliyor...',
    robots_complete: 'Robots analizi tamamlandı',
    geoip: 'GeoIP bilgileri alınıyor...',
    whois: 'WHOIS sorgusu yapılıyor...',
    scoring: 'Güvenlik skoru hesaplanıyor...',
    compliance: 'Uyumluluk kontrolleri yapılıyor...',
    report: 'Rapor derleniyor...',
    complete: 'Tarama tamamlandı!',
    error: 'Tarama sırasında hata oluştu',
  },
  en: {
    connecting: 'Connecting to target system...',
    dns: 'Resolving DNS records and IP address...',
    dns_complete: 'DNS records resolved',
    ssl: 'Analyzing SSL/TLS security certificate...',
    ssl_complete: 'SSL certificate analysis complete',
    headers: 'Inspecting HTTP security headers...',
    headers_complete: 'Header analysis complete',
    cookies: 'Checking cookie security...',
    ports: 'Scanning ports...',
    ports_complete: 'Port scan complete',
    tech: 'Detecting technologies...',
    tech_complete: 'Technology detection complete',
    cve: 'Correlating with CVE database...',
    cve_complete: 'CVE correlation complete',
    subdomains: 'Scanning subdomains...',
    subdomains_complete: 'Subdomain scan complete',
    content: 'Analyzing page content...',
    content_complete: 'Content analysis complete',
    active: 'Starting active security scan...',
    active_sqli: 'Testing SQL Injection vectors...',
    active_xss: 'Scanning for XSS vulnerabilities...',
    active_traversal: 'Checking directory traversal...',
    active_cors: 'Testing CORS configuration...',
    active_redirect: 'Scanning for open redirects...',
    active_files: 'Searching for sensitive files...',
    active_complete: 'Active scan complete',
    http_methods: 'Testing HTTP methods...',
    http_methods_complete: 'HTTP methods scan complete',
    robots: 'Analyzing robots.txt and security.txt...',
    robots_complete: 'Robots analysis complete',
    geoip: 'Fetching GeoIP information...',
    whois: 'Performing WHOIS lookup...',
    scoring: 'Calculating security score...',
    compliance: 'Running compliance checks...',
    report: 'Compiling report...',
    complete: 'Scan complete!',
    error: 'Error during scan',
  },
};

// Scan progress emitter - one per scan session
class ScanProgressEmitter extends EventEmitter {
  private scanId: string;
  private lang: 'tr' | 'en';

  constructor(scanId: string, lang: 'tr' | 'en' = 'tr') {
    super();
    this.scanId = scanId;
    this.lang = lang;
  }

  emitProgress(phase: keyof typeof PROGRESS_MESSAGES['tr'], progress: number, type: ScanProgress['type'] = 'info', details?: string) {
    const message = PROGRESS_MESSAGES[this.lang][phase] || phase;
    const progressData: ScanProgress = {
      phase,
      message,
      progress: Math.min(100, Math.max(0, progress)),
      type,
      details,
    };
    this.emit('progress', progressData);
  }
}

// Store active scan sessions
const activeSessions = new Map<string, ScanProgressEmitter>();

export function createScanSession(scanId: string, lang: 'tr' | 'en'): ScanProgressEmitter {
  const emitter = new ScanProgressEmitter(scanId, lang);
  activeSessions.set(scanId, emitter);
  return emitter;
}

export function getScanSession(scanId: string): ScanProgressEmitter | undefined {
  return activeSessions.get(scanId);
}

export function removeScanSession(scanId: string): void {
  activeSessions.delete(scanId);
}

export { ScanProgressEmitter };
