/**
 * Security Constants
 * Security headers rules, TLS grading, and vulnerability database
 */

export interface SecurityHeaderRule {
  required: boolean;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
}

export const SECURITY_HEADERS_RULES: Record<string, SecurityHeaderRule> = {
  'Strict-Transport-Security': {
    required: true,
    severity: 'HIGH',
    description: 'Forces HTTPS connections and prevents downgrade attacks',
  },
  'Content-Security-Policy': {
    required: true,
    severity: 'HIGH',
    description: 'Prevents XSS, clickjacking, and code injection attacks',
  },
  'X-Frame-Options': {
    required: true,
    severity: 'MEDIUM',
    description: 'Prevents clickjacking by controlling iframe embedding',
  },
  'X-Content-Type-Options': {
    required: true,
    severity: 'MEDIUM',
    description: 'Prevents MIME-sniffing attacks',
  },
  'Referrer-Policy': {
    required: true,
    severity: 'MEDIUM',
    description: 'Controls referrer information sent to other sites',
  },
  'Permissions-Policy': {
    required: false,
    severity: 'LOW',
    description: 'Controls browser features and APIs',
  },
  'X-XSS-Protection': {
    required: false,
    severity: 'LOW',
    description: 'Legacy XSS filter (replaced by CSP)',
  },
};

export const TLS_PROTOCOL_GRADES: Record<string, string> = {
  'TLSv1.3': 'A+',
  'TLSv1.2': 'A',
  'TLSv1.1': 'B',
  'TLSv1.0': 'C',
  'SSLv3': 'F',
  'SSLv2': 'F',
};

export const VULNERABLE_VERSIONS: Record<string, Record<string, string[]>> = {
  nginx: {
    '1.17.0': ['CVE-2019-9511', 'CVE-2019-9513'],
    '1.16.0': ['CVE-2019-9511'],
    '1.15.0': ['CVE-2018-16843', 'CVE-2018-16844'],
    '1.14.0': ['CVE-2018-16843'],
    '1.13.0': ['CVE-2017-7529'],
  },
  apache: {
    '2.4.48': ['CVE-2021-41773', 'CVE-2021-42013'],
    '2.4.46': ['CVE-2021-26690', 'CVE-2021-26691'],
    '2.4.43': ['CVE-2020-1927', 'CVE-2020-1934'],
    '2.4.41': ['CVE-2019-10081', 'CVE-2019-10082'],
    '2.4.39': ['CVE-2019-0211', 'CVE-2019-0215'],
  },
  iis: {
    '10.0': ['CVE-2017-7269'],
    '8.5': ['CVE-2015-1635'],
    '7.5': ['CVE-2010-3972'],
  },
  wordpress: {
    '6.1.0': ['CVE-2023-2745'],
    '6.0.0': ['CVE-2022-21663'],
    '5.9.0': ['CVE-2022-21664'],
    '5.8.0': ['CVE-2021-29447'],
    '5.7.0': ['CVE-2021-29450'],
  },
  joomla: {
    '4.2.0': ['CVE-2023-23752'],
    '4.0.0': ['CVE-2021-23132'],
    '3.9.0': ['CVE-2019-10945'],
  },
  drupal: {
    '9.0.0': ['CVE-2020-13666'],
    '8.7.0': ['CVE-2019-6340'],
    '7.0.0': ['CVE-2018-7600', 'CVE-2018-7602'],
  },
  php: {
    '8.1.0': ['CVE-2022-31625'],
    '8.0.0': ['CVE-2021-21702'],
    '7.4.0': ['CVE-2020-7066'],
    '7.3.0': ['CVE-2019-11043'],
  },
  nodejs: {
    '18.0.0': ['CVE-2022-32212'],
    '16.0.0': ['CVE-2021-22930'],
    '14.0.0': ['CVE-2020-8172'],
  },
};

export const CMS_SIGNATURES: Record<string, string[]> = {
  WordPress: ['wp-content', 'wp-includes', 'wp-admin', '/wp-json/'],
  Joomla: ['Joomla', '/components/', '/modules/', 'joomla.org'],
  Drupal: ['Drupal', '/sites/default/', '/misc/drupal.js'],
  Magento: ['Magento', '/skin/frontend/', 'Mage.Cookies'],
  Shopify: ['cdn.shopify.com', 'myshopify.com'],
  Wix: ['wix.com', 'parastorage.com'],
  Squarespace: ['squarespace.com', 'sqsp.net'],
};

export const FRAMEWORK_SIGNATURES: Record<string, string[]> = {
  React: ['react', '_jsx', 'createRoot', 'react-dom'],
  Vue: ['vue.js', 'Vue.component', '__vue'],
  Angular: ['ng-version', 'angular', 'ng-app'],
  jQuery: ['jquery', '$.fn.jquery'],
  Bootstrap: ['bootstrap', 'btn-primary'],
  Tailwind: ['tailwindcss'],
  Express: ['x-powered-by: express'],
  Laravel: ['laravel_session', 'XSRF-TOKEN'],
  Django: ['csrftoken', 'djdt'],
  Flask: ['werkzeug'],
  'ASP.NET': ['ASP.NET_SessionId', '__VIEWSTATE'],
};

export const COMPLIANCE_STANDARDS = {
  GDPR: {
    name: 'GDPR (EU Data Protection)',
    requirements: ['Cookie consent', 'Privacy policy', 'Data encryption', 'HTTPS'],
  },
  HIPAA: {
    name: 'HIPAA (Healthcare)',
    requirements: ['End-to-end encryption', 'Access controls', 'Audit logs'],
  },
  'PCI DSS': {
    name: 'PCI DSS (Payment Cards)',
    requirements: ['Strong encryption', 'Secure network', 'Access control', 'Regular testing'],
  },
  SOC2: {
    name: 'SOC 2 (Service Organization Control)',
    requirements: ['Security policies', 'Access control', 'Encryption', 'Monitoring'],
  },
};

export const SEVERITY_SCORES: Record<string, number> = {
  Kritik: 20,
  Yüksek: 10,
  Orta: 5,
  Düşük: 2,
  Bilgi: 1,
  Critical: 20,
  High: 10,
  Medium: 5,
  Low: 2,
  Info: 1,
};

export const SSL_GRADE_PENALTIES: Record<string, number> = {
  'A+': 0,
  A: 0,
  B: -5,
  C: -10,
  D: -15,
  F: -25,
};

export const COMMON_SUBDOMAINS = [
  'www',
  'mail',
  'ftp',
  'localhost',
  'webmail',
  'smtp',
  'pop',
  'ns1',
  'webdisk',
  'ns2',
  'cpanel',
  'whm',
  'autodiscover',
  'autoconfig',
  'm',
  'imap',
  'test',
  'ns',
  'blog',
  'pop3',
  'dev',
  'www2',
  'admin',
  'forum',
  'news',
  'vpn',
  'ns3',
  'mail2',
  'new',
  'mysql',
  'old',
  'lists',
  'support',
  'mobile',
  'mx',
  'static',
  'docs',
  'beta',
  'shop',
  'sql',
  'secure',
  'demo',
  'cp',
  'calendar',
  'wiki',
  'web',
  'media',
  'email',
  'images',
  'img',
  'www1',
  'intranet',
  'portal',
  'video',
  'sip',
  'dns2',
  'api',
  'cdn',
  'stats',
  'dns1',
  'ns4',
  'www3',
  'dns',
  'search',
  'staging',
  'server',
  'mx1',
  'chat',
  'wap',
  'my',
  'svn',
  'git',
  'ftp2',
  'info',
  'marketing',
  'crm',
  'app',
  'apps',
  'download',
  'downloads',
  'owa',
];
