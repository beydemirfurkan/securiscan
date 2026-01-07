/**
 * Terminal Scan Sequences
 *
 * Progress messages for real-time scan updates
 */

export interface ScanLog {
  text: string;
  type: 'info' | 'success' | 'warning' | 'error' | 'neutral';
  details?: string;
}

// Phase to message mapping for Turkish
export const TR_MESSAGES: Record<string, { text: string; type: ScanLog['type'] }> = {
  connecting: { text: 'Hedef sisteme bağlantı kuruluyor...', type: 'info' },
  dns: { text: 'DNS kayıtları ve IP adresi çözümleniyor...', type: 'info' },
  dns_complete: { text: 'DNS kayıtları çözümlendi', type: 'success' },
  ssl: { text: 'SSL/TLS güvenlik sertifikası analiz ediliyor...', type: 'info' },
  ssl_complete: { text: 'SSL sertifikası analizi tamamlandı', type: 'success' },
  headers: { text: 'HTTP güvenlik başlıkları inceleniyor...', type: 'info' },
  headers_complete: { text: 'Başlık analizi tamamlandı', type: 'success' },
  cookies: { text: 'Cookie güvenliği kontrol ediliyor...', type: 'info' },
  ports: { text: 'Port taraması yapılıyor...', type: 'info' },
  ports_complete: { text: 'Port taraması tamamlandı', type: 'success' },
  tech: { text: 'Teknoloji tespiti yapılıyor...', type: 'info' },
  tech_complete: { text: 'Teknoloji tespiti tamamlandı', type: 'success' },
  cve: { text: 'CVE veritabanı ile eşleştirme yapılıyor...', type: 'info' },
  cve_complete: { text: 'CVE korelasyonu tamamlandı', type: 'success' },
  subdomains: { text: 'Alt alan adları taranıyor...', type: 'info' },
  subdomains_complete: { text: 'Alt alan adı taraması tamamlandı', type: 'success' },
  content: { text: 'Sayfa içeriği analiz ediliyor...', type: 'info' },
  content_complete: { text: 'İçerik analizi tamamlandı', type: 'success' },
  active: { text: 'Aktif güvenlik taraması başlatıldı...', type: 'info' },
  active_sqli: { text: 'SQL Injection vektörleri test ediliyor...', type: 'warning' },
  active_xss: { text: 'XSS açıkları taranıyor...', type: 'warning' },
  active_traversal: { text: 'Dizin gezinme açıkları kontrol ediliyor...', type: 'info' },
  active_cors: { text: 'CORS yapılandırması test ediliyor...', type: 'info' },
  active_redirect: { text: 'Açık yönlendirme açıkları taranıyor...', type: 'info' },
  active_files: { text: 'Hassas dosyalar aranıyor...', type: 'info' },
  active_complete: { text: 'Aktif tarama tamamlandı', type: 'success' },
  http_methods: { text: 'HTTP metodları test ediliyor...', type: 'info' },
  http_methods_complete: { text: 'HTTP metod taraması tamamlandı', type: 'success' },
  robots: { text: 'Robots.txt ve security.txt analiz ediliyor...', type: 'info' },
  robots_complete: { text: 'Robots analizi tamamlandı', type: 'success' },
  geoip: { text: 'GeoIP bilgileri alınıyor...', type: 'info' },
  whois: { text: 'WHOIS sorgusu yapılıyor...', type: 'info' },
  scoring: { text: 'Güvenlik skoru hesaplanıyor...', type: 'info' },
  compliance: { text: 'Uyumluluk kontrolleri yapılıyor...', type: 'info' },
  report: { text: 'Rapor derleniyor...', type: 'info' },
  complete: { text: 'Tarama tamamlandı!', type: 'success' },
  error: { text: 'Tarama sırasında hata oluştu', type: 'error' },
};

// Phase to message mapping for English
export const EN_MESSAGES: Record<string, { text: string; type: ScanLog['type'] }> = {
  connecting: { text: 'Connecting to target system...', type: 'info' },
  dns: { text: 'Resolving DNS records and IP address...', type: 'info' },
  dns_complete: { text: 'DNS records resolved', type: 'success' },
  ssl: { text: 'Analyzing SSL/TLS security certificate...', type: 'info' },
  ssl_complete: { text: 'SSL certificate analysis complete', type: 'success' },
  headers: { text: 'Inspecting HTTP security headers...', type: 'info' },
  headers_complete: { text: 'Header analysis complete', type: 'success' },
  cookies: { text: 'Checking cookie security...', type: 'info' },
  ports: { text: 'Scanning ports...', type: 'info' },
  ports_complete: { text: 'Port scan complete', type: 'success' },
  tech: { text: 'Detecting technologies...', type: 'info' },
  tech_complete: { text: 'Technology detection complete', type: 'success' },
  cve: { text: 'Correlating with CVE database...', type: 'info' },
  cve_complete: { text: 'CVE correlation complete', type: 'success' },
  subdomains: { text: 'Scanning subdomains...', type: 'info' },
  subdomains_complete: { text: 'Subdomain scan complete', type: 'success' },
  content: { text: 'Analyzing page content...', type: 'info' },
  content_complete: { text: 'Content analysis complete', type: 'success' },
  active: { text: 'Starting active security scan...', type: 'info' },
  active_sqli: { text: 'Testing SQL Injection vectors...', type: 'warning' },
  active_xss: { text: 'Scanning for XSS vulnerabilities...', type: 'warning' },
  active_traversal: { text: 'Checking directory traversal...', type: 'info' },
  active_cors: { text: 'Testing CORS configuration...', type: 'info' },
  active_redirect: { text: 'Scanning for open redirects...', type: 'info' },
  active_files: { text: 'Searching for sensitive files...', type: 'info' },
  active_complete: { text: 'Active scan complete', type: 'success' },
  http_methods: { text: 'Testing HTTP methods...', type: 'info' },
  http_methods_complete: { text: 'HTTP methods scan complete', type: 'success' },
  robots: { text: 'Analyzing robots.txt and security.txt...', type: 'info' },
  robots_complete: { text: 'Robots analysis complete', type: 'success' },
  geoip: { text: 'Fetching GeoIP information...', type: 'info' },
  whois: { text: 'Performing WHOIS lookup...', type: 'info' },
  scoring: { text: 'Calculating security score...', type: 'info' },
  compliance: { text: 'Running compliance checks...', type: 'info' },
  report: { text: 'Compiling report...', type: 'info' },
  complete: { text: 'Scan complete!', type: 'success' },
  error: { text: 'Error during scan', type: 'error' },
};

// Legacy sequences for fallback (when SSE is not available)
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
