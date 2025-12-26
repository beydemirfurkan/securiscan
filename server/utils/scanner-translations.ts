/**
 * Scanner Translations
 * Centralized translation system for all security scanner modules
 */

export type Language = 'tr' | 'en';

interface TranslationMap {
  [key: string]: {
    tr: string;
    en: string;
  };
}

// Vulnerability titles and descriptions
export const VULNERABILITY_TRANSLATIONS: TranslationMap = {
  // HTTP Headers
  'vuln.header.hsts.title': {
    tr: 'Eksik HSTS Başlığı',
    en: 'Missing HSTS Header',
  },
  'vuln.header.hsts.description': {
    tr: 'HTTP Strict Transport Security (HSTS) başlığı eksik. Bu, man-in-the-middle saldırılarına ve protocol downgrade saldırılarına karşı savunmasızlığa yol açar.',
    en: 'HTTP Strict Transport Security (HSTS) header is missing. This leads to vulnerability against man-in-the-middle and protocol downgrade attacks.',
  },
  'vuln.header.hsts.remediation': {
    tr: 'Web sunucu yapılandırmasına "Strict-Transport-Security: max-age=31536000; includeSubDomains" başlığını ekleyin',
    en: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" header to web server configuration',
  },
  'vuln.header.hsts.exploit.step1': {
    tr: 'SSL Stripping Saldırısı',
    en: 'SSL Stripping Attack',
  },
  'vuln.header.hsts.exploit.scenario': {
    tr: 'Saldırgan, kullanıcı ile sunucu arasına girerek HTTPS bağlantıyı HTTP\'ye dönüştürür',
    en: 'Attacker intercepts connection and downgrades HTTPS to HTTP',
  },
  'vuln.header.hsts.exploit.impact': {
    tr: 'Tüm iletişim düz metin olarak ele geçirilebilir',
    en: 'All communication can be intercepted in plaintext',
  },

  // CSP
  'vuln.header.csp.title': {
    tr: 'Eksik Content Security Policy',
    en: 'Missing Content Security Policy',
  },
  'vuln.header.csp.description': {
    tr: 'Content Security Policy (CSP) başlığı eksik. Bu, XSS (Cross-Site Scripting) ve veri enjeksiyonu saldırılarına karşı savunmasızlığa yol açar.',
    en: 'Content Security Policy (CSP) header is missing. This leads to vulnerability against XSS and data injection attacks.',
  },
  'vuln.header.csp.remediation': {
    tr: 'Güçlü bir CSP başlığı tanımlayın: "default-src \'self\'; script-src \'self\'; object-src \'none\'"',
    en: 'Define a strong CSP header: "default-src \'self\'; script-src \'self\'; object-src \'none\'"',
  },
  'vuln.header.csp.exploit.step1': {
    tr: 'XSS (Cross-Site Scripting)',
    en: 'XSS (Cross-Site Scripting)',
  },
  'vuln.header.csp.exploit.scenario': {
    tr: 'Saldırgan, kullanıcı girdileri aracılığıyla kötü amaçlı JavaScript kodu enjekte eder',
    en: 'Attacker injects malicious JavaScript through user inputs',
  },
  'vuln.header.csp.exploit.impact': {
    tr: 'Oturum çalınması, veri hırsızlığı, kullanıcı kimliğine bürünme',
    en: 'Session theft, data theft, user impersonation',
  },

  // X-Frame-Options
  'vuln.header.xfo.title': {
    tr: 'Clickjacking Koruması Eksik',
    en: 'Missing Clickjacking Protection',
  },
  'vuln.header.xfo.description': {
    tr: 'X-Frame-Options başlığı eksik. Site iframe içine gömülebilir ve clickjacking saldırılarına açıktır.',
    en: 'X-Frame-Options header is missing. Site can be embedded in iframes and is vulnerable to clickjacking.',
  },
  'vuln.header.xfo.remediation': {
    tr: '"X-Frame-Options: DENY" veya "X-Frame-Options: SAMEORIGIN" başlığını ekleyin',
    en: 'Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" header',
  },
  'vuln.header.xfo.exploit.step1': {
    tr: 'Clickjacking Saldırısı',
    en: 'Clickjacking Attack',
  },
  'vuln.header.xfo.exploit.scenario': {
    tr: 'Saldırgan, sayfayı görünmez iframe içine yerleştirir ve kullanıcıyı istemeden tıklamaya yönlendirir',
    en: 'Attacker embeds page in invisible iframe and tricks user into clicking',
  },
  'vuln.header.xfo.exploit.impact': {
    tr: 'Yetkisiz işlemler, hesap ele geçirme',
    en: 'Unauthorized actions, account takeover',
  },

  // X-Content-Type-Options
  'vuln.header.xcto.title': {
    tr: 'MIME Sniffing Koruması Eksik',
    en: 'Missing MIME Sniffing Protection',
  },
  'vuln.header.xcto.description': {
    tr: 'X-Content-Type-Options başlığı eksik. Tarayıcı MIME-type sniffing yapabilir.',
    en: 'X-Content-Type-Options header is missing. Browser can perform MIME-type sniffing.',
  },
  'vuln.header.xcto.remediation': {
    tr: '"X-Content-Type-Options: nosniff" başlığını ekleyin',
    en: 'Add "X-Content-Type-Options: nosniff" header',
  },

  // SSL/TLS
  'vuln.ssl.weak.title': {
    tr: 'Zayıf SSL/TLS Yapılandırması',
    en: 'Weak SSL/TLS Configuration',
  },
  'vuln.ssl.weak.description': {
    tr: 'SSL/TLS protokolü zayıf ({protocol}). Eski TLS versiyonları bilinen güvenlik açıklarına sahiptir.',
    en: 'SSL/TLS protocol is weak ({protocol}). Old TLS versions have known vulnerabilities.',
  },
  'vuln.ssl.weak.remediation': {
    tr: 'TLS 1.2 veya TLS 1.3 kullanacak şekilde sunucu yapılandırmasını güncelleyin',
    en: 'Update server configuration to use TLS 1.2 or TLS 1.3',
  },
  'vuln.ssl.weak.exploit.step1': {
    tr: 'Man-in-the-Middle (MITM)',
    en: 'Man-in-the-Middle (MITM)',
  },
  'vuln.ssl.weak.exploit.scenario': {
    tr: 'Saldırgan zayıf şifreleme kullanarak iletişimi ele geçirir',
    en: 'Attacker intercepts communication using weak encryption',
  },
  'vuln.ssl.weak.exploit.impact': {
    tr: 'Tüm hassas veriler okunabilir',
    en: 'All sensitive data can be read',
  },

  'vuln.ssl.expiring.title': {
    tr: 'SSL Sertifikası Yakında Sona Erecek',
    en: 'SSL Certificate Expiring Soon',
  },
  'vuln.ssl.expiring.description': {
    tr: 'SSL sertifikası {days} gün içinde sona erecek.',
    en: 'SSL certificate will expire in {days} days.',
  },
  'vuln.ssl.expiring.remediation': {
    tr: 'SSL sertifikasını derhal yenileyin',
    en: 'Renew SSL certificate immediately',
  },

  'vuln.ssl.expired.title': {
    tr: 'SSL Sertifikası Süresi Dolmuş',
    en: 'SSL Certificate Expired',
  },
  'vuln.ssl.expired.description': {
    tr: 'SSL sertifikasının süresi dolmuş! Bu çok ciddi bir güvenlik sorunudur.',
    en: 'SSL certificate has expired! This is a critical security issue.',
  },
  'vuln.ssl.expired.remediation': {
    tr: 'SSL sertifikasını acilen yenileyin',
    en: 'Renew SSL certificate urgently',
  },

  // Port vulnerabilities
  'vuln.port.ftp.title': {
    tr: 'FTP Servisi Açık (Şifrelenmemiş)',
    en: 'FTP Service Exposed (Unencrypted)',
  },
  'vuln.port.ftp.description': {
    tr: 'FTP (Port 21) açık. FTP şifrelenmemiş bir protokoldür ve tüm veriler düz metin olarak iletilir.',
    en: 'FTP (Port 21) is open. FTP is an unencrypted protocol and all data is transmitted in plaintext.',
  },

  'vuln.port.telnet.title': {
    tr: 'Telnet Servisi Açık (Güvensiz)',
    en: 'Telnet Service Exposed (Insecure)',
  },
  'vuln.port.telnet.description': {
    tr: 'Telnet (Port 23) açık. Telnet şifrelenmemiş bir uzak erişim protokolüdür. SSH kullanılmalıdır.',
    en: 'Telnet (Port 23) is open. Telnet is an unencrypted remote access protocol. SSH should be used instead.',
  },

  'vuln.port.rdp.title': {
    tr: 'RDP İnternete Açık',
    en: 'RDP Exposed to Internet',
  },
  'vuln.port.rdp.description': {
    tr: 'Remote Desktop Protocol (Port 3389) internete açık. Brute force saldırılarına hedef olabilir.',
    en: 'Remote Desktop Protocol (Port 3389) is exposed to internet. Can be target of brute force attacks.',
  },

  'vuln.port.mysql.title': {
    tr: 'MySQL Veritabanı İnternete Açık',
    en: 'MySQL Database Exposed to Internet',
  },
  'vuln.port.mysql.description': {
    tr: 'MySQL veritabanı (Port 3306) internete açık. Veritabanları asla doğrudan internete açılmamalıdır.',
    en: 'MySQL database (Port 3306) is exposed to internet. Databases should never be directly exposed.',
  },

  'vuln.port.postgres.title': {
    tr: 'PostgreSQL Veritabanı İnternete Açık',
    en: 'PostgreSQL Database Exposed to Internet',
  },
  'vuln.port.postgres.description': {
    tr: 'PostgreSQL veritabanı (Port 5432) internete açık.',
    en: 'PostgreSQL database (Port 5432) is exposed to internet.',
  },

  'vuln.port.mongodb.title': {
    tr: 'MongoDB Veritabanı İnternete Açık',
    en: 'MongoDB Database Exposed to Internet',
  },
  'vuln.port.mongodb.description': {
    tr: 'MongoDB veritabanı (Port 27017) internete açık. Sık sık kimlik doğrulama olmadan bulunur.',
    en: 'MongoDB database (Port 27017) is exposed to internet. Often found without authentication.',
  },

  'vuln.port.redis.title': {
    tr: 'Redis İnternete Açık',
    en: 'Redis Exposed to Internet',
  },
  'vuln.port.redis.description': {
    tr: 'Redis (Port 6379) internete açık. Redis genellikle kimlik doğrulama olmadan çalışır.',
    en: 'Redis (Port 6379) is exposed to internet. Redis often runs without authentication.',
  },

  'vuln.port.remediation': {
    tr: 'Port {port} firewall ile kapatılmalı veya VPN arkasına alınmalıdır',
    en: 'Port {port} should be blocked by firewall or placed behind VPN',
  },

  'vuln.port.exploit.bruteforce': {
    tr: 'Brute Force Saldırısı',
    en: 'Brute Force Attack',
  },
  'vuln.port.exploit.bruteforce.scenario': {
    tr: 'Saldırgan otomatik araçlarla binlerce şifre kombinasyonu dener',
    en: 'Attacker tries thousands of password combinations with automated tools',
  },
  'vuln.port.exploit.bruteforce.impact': {
    tr: 'Yetkisiz erişim, veri sızıntısı',
    en: 'Unauthorized access, data breach',
  },

  // Tech vulnerabilities
  'vuln.tech.title': {
    tr: '{name} - Bilinen Güvenlik Açıkları',
    en: '{name} - Known Vulnerabilities',
  },
  'vuln.tech.description': {
    tr: '{name} için bilinen güvenlik açıkları tespit edildi.',
    en: 'Known security vulnerabilities detected for {name}.',
  },
  'vuln.tech.remediation': {
    tr: '{name} yazılımını en son güvenli sürüme güncelleyin',
    en: 'Update {name} to the latest secure version',
  },
  'vuln.tech.exploit': {
    tr: 'Sürüme özel exploit',
    en: 'Version-specific exploit',
  },

  // Information disclosure
  'vuln.info.title': {
    tr: 'Sunucu Bilgi Sızıntısı',
    en: 'Server Information Disclosure',
  },
  'vuln.info.description': {
    tr: 'HTTP başlıkları sunucu ve teknoloji bilgilerini açığa çıkarıyor: {headers}',
    en: 'HTTP headers disclose server and technology information: {headers}',
  },
  'vuln.info.remediation': {
    tr: 'Server, X-Powered-By gibi başlıkları web sunucu yapılandırmasından kaldırın',
    en: 'Remove Server, X-Powered-By and similar headers from web server configuration',
  },
  'vuln.info.exploit.step1': {
    tr: 'Bilgi Toplama',
    en: 'Information Gathering',
  },
  'vuln.info.exploit.scenario': {
    tr: 'Saldırgan, sunucu versiyonunu öğrenerek hedefli saldırı geliştirebilir',
    en: 'Attacker learns server version to develop targeted attack',
  },
  'vuln.info.exploit.impact': {
    tr: 'Saldırı yüzeyini genişletir',
    en: 'Expands attack surface',
  },

  // Common fields
  'location.httpHeaders': {
    tr: 'HTTP Başlıkları',
    en: 'HTTP Headers',
  },
  'location.sslConfig': {
    tr: 'SSL/TLS Yapılandırması',
    en: 'SSL/TLS Configuration',
  },
  'location.sslCert': {
    tr: 'SSL Sertifikası',
    en: 'SSL Certificate',
  },
  'location.openPort': {
    tr: 'Açık Port {port}',
    en: 'Open Port {port}',
  },
  'exploitExample.curl': {
    tr: 'curl -I [HEDEF_URL]',
    en: 'curl -I [TARGET_URL]',
  },
  'exploitExample.nmap': {
    tr: 'nmap -p {port} [HEDEF]',
    en: 'nmap -p {port} [TARGET]',
  },
};

// Summary translations
export const SUMMARY_TRANSLATIONS: TranslationMap = {
  'summary.excellent': {
    tr: 'Güvenlik skoru: {score}/100 - İyi güvenlik seviyesi. {count} zafiyet tespit edildi.',
    en: 'Security score: {score}/100 - Good security level. {count} vulnerabilities detected.',
  },
  'summary.good': {
    tr: 'Güvenlik skoru: {score}/100 - Orta güvenlik seviyesi. {count} zafiyet tespit edildi ve iyileştirme gerekiyor.',
    en: 'Security score: {score}/100 - Medium security level. {count} vulnerabilities detected and improvement needed.',
  },
  'summary.medium': {
    tr: 'Güvenlik skoru: {score}/100 - Düşük güvenlik seviyesi. {count} zafiyet tespit edildi. Acil müdahale gerekli.',
    en: 'Security score: {score}/100 - Low security level. {count} vulnerabilities detected. Urgent action required.',
  },
  'summary.critical': {
    tr: 'Güvenlik skoru: {score}/100 - Kritik durum! {count} ciddi zafiyet tespit edildi. Derhal aksiyon alınmalı!',
    en: 'Security score: {score}/100 - Critical condition! {count} serious vulnerabilities detected. Take immediate action!',
  },
};

// Action plan translations
export const ACTION_PLAN_TRANSLATIONS: TranslationMap = {
  'action.renewSSL': {
    tr: 'SSL sertifikasını yenile',
    en: 'Renew SSL certificate',
  },
  'action.renewSSL.urgent': {
    tr: 'SSL sertifikasını acilen yenile (SÜRESİ DOLMUŞ!)',
    en: 'Urgently renew SSL certificate (EXPIRED!)',
  },
  'action.time.minutes': {
    tr: '{time} dakika',
    en: '{time} minutes',
  },
  'action.time.hours': {
    tr: '{time} saat',
    en: '{time} hours',
  },
  'action.time.days': {
    tr: '{time} gün',
    en: '{time} days',
  },
  'action.time.range': {
    tr: '{min}-{max} {unit}',
    en: '{min}-{max} {unit}',
  },
  'action.impact.certExpiring': {
    tr: 'Sertifika {days} gün içinde sona erecek',
    en: 'Certificate expires in {days} days',
  },
  'action.impact.certExpired': {
    tr: 'Site erişilemez, kullanıcılar uyarı görüyor',
    en: 'Site inaccessible, users see warnings',
  },
  'action.impact.critical': {
    tr: 'Sistem kritik saldırılara açık',
    en: 'System exposed to critical attacks',
  },
  'action.impact.high': {
    tr: 'Güvenlik riski yüksek',
    en: 'High security risk',
  },
  'action.impact.medium': {
    tr: 'Güvenlik açığı mevcut',
    en: 'Security gap exists',
  },
  'action.impact.low': {
    tr: 'Küçük iyileştirme',
    en: 'Minor improvement',
  },
};

/**
 * Get translated text with optional parameter substitution
 */
export function t(key: string, lang: Language, params?: Record<string, string | number>): string {
  const translation =
    VULNERABILITY_TRANSLATIONS[key] ||
    SUMMARY_TRANSLATIONS[key] ||
    ACTION_PLAN_TRANSLATIONS[key];

  if (!translation) {
    console.warn(`[Translation] Missing key: ${key}`);
    return key;
  }

  let text = translation[lang];

  // Replace parameters
  if (params) {
    Object.keys(params).forEach((paramKey) => {
      text = text.replace(new RegExp(`\\{${paramKey}\\}`, 'g'), String(params[paramKey]));
    });
  }

  return text;
}

/**
 * Check if translation key exists
 */
export function hasTranslation(key: string): boolean {
  return !!(
    VULNERABILITY_TRANSLATIONS[key] ||
    SUMMARY_TRANSLATIONS[key] ||
    ACTION_PLAN_TRANSLATIONS[key]
  );
}
