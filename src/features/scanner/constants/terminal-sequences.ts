/**
 * Terminal Scan Sequences
 *
 * Predefined log sequences for the scan terminal animation
 */

export interface ScanLog {
  text: string;
  type: 'info' | 'success' | 'warning' | 'error' | 'neutral';
}

export const TR_SEQUENCE: ScanLog[] = [
  { text: "Hedef sisteme bağlantı kuruluyor...", type: 'info' },
  { text: "DNS kayıtları ve IP adresi çözümlendi.", type: 'success' },
  { text: "Port taraması başlatıldı...", type: 'info' },
  { text: "Servis ve versiyon bilgileri çekiliyor...", type: 'neutral' },
  { text: "SSL/TLS güvenlik sertifikası analizi yapılıyor...", type: 'info' },
  { text: "Güvenlik başlıkları (Headers) inceleniyor...", type: 'neutral' },
  { text: "OWASP Top 10 zafiyet taraması başlatıldı...", type: 'info' },
  { text: "XSS ve SQL Injection vektörleri test ediliyor...", type: 'warning' },
  { text: "Rapor derleniyor ve AI motoruna aktarılıyor...", type: 'success' }
];

export const EN_SEQUENCE: ScanLog[] = [
  { text: "Establishing connection to target...", type: 'info' },
  { text: "DNS records and IP resolved.", type: 'success' },
  { text: "Port scan initiated...", type: 'info' },
  { text: "Fetching service and version info...", type: 'neutral' },
  { text: "Analyzing SSL/TLS security certificate...", type: 'info' },
  { text: "Inspecting HTTP security headers...", type: 'neutral' },
  { text: "OWASP Top 10 vulnerability scan started...", type: 'info' },
  { text: "Testing XSS and SQL Injection vectors...", type: 'warning' },
  { text: "Compiling report and transmitting to AI engine...", type: 'success' }
];
