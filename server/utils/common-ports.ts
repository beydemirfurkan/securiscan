/**
 * Common Ports Configuration
 * Top 100 most commonly used ports for security scanning
 */

export const TOP_100_PORTS = [
  // Web Services
  80,    // HTTP
  443,   // HTTPS
  8080,  // HTTP Proxy
  8443,  // HTTPS Alt
  8000,  // HTTP Alt
  8888,  // HTTP Alt

  // Secure Shell & Remote Access
  22,    // SSH
  23,    // Telnet
  3389,  // RDP (Remote Desktop)
  5900,  // VNC

  // Email Services
  25,    // SMTP
  110,   // POP3
  143,   // IMAP
  465,   // SMTPS
  587,   // SMTP (Submission)
  993,   // IMAPS
  995,   // POP3S

  // File Transfer
  21,    // FTP
  69,    // TFTP

  // DNS & Network
  53,    // DNS
  67,    // DHCP Server
  68,    // DHCP Client

  // Databases
  3306,  // MySQL
  5432,  // PostgreSQL
  27017, // MongoDB
  6379,  // Redis
  1433,  // MS SQL Server
  1521,  // Oracle DB

  // Web Frameworks & Proxies
  3000,  // Node.js / React Dev
  4200,  // Angular Dev
  5000,  // Flask / Python
  9000,  // PHP-FPM

  // Message Queues
  5672,  // RabbitMQ
  9092,  // Kafka

  // Monitoring & Management
  161,   // SNMP
  162,   // SNMP Trap
  514,   // Syslog

  // Windows Services
  135,   // MS RPC
  139,   // NetBIOS
  445,   // SMB

  // Application Servers
  8009,  // Apache JServ
  8180,  // Apache Tomcat Alt
  9090,  // WebSphere

  // Gaming & Streaming
  27015, // Steam
  1935,  // RTMP (Streaming)

  // VPN
  1194,  // OpenVPN
  1723,  // PPTP

  // Container & Orchestration
  2375,  // Docker
  2376,  // Docker (TLS)
  6443,  // Kubernetes API
  10250, // Kubelet

  // Search & Analytics
  9200,  // Elasticsearch
  9300,  // Elasticsearch (Nodes)

  // Caching
  11211, // Memcached

  // Additional Common Ports
  137,   // NetBIOS Name
  138,   // NetBIOS Datagram
  389,   // LDAP
  636,   // LDAPS
  873,   // rsync
  3690,  // SVN
  5060,  // SIP
  5061,  // SIP TLS
  5353,  // mDNS
  8081,  // HTTP Alt
  8082,  // HTTP Alt
  8083,  // HTTP Alt
  8084,  // HTTP Alt
  8085,  // HTTP Alt
  9001,  // Supervisor
  9091,  // Prometheus Pushgateway
  9100,  // Node Exporter
  9999,  // Generic
  10000, // Webmin

  // Additional services
  111,   // RPCbind
  179,   // BGP
  427,   // SLP
  548,   // AFP
  631,   // IPP (Printing)
  902,   // VMware
  3128,  // Squid Proxy
  5001,  // Synology DSM
  5222,  // XMPP
  5269,  // XMPP Server
  5357,  // WSDAPI
  5984,  // CouchDB
  6000,  // X11
  7001,  // WebLogic
  8089,  // Splunk
  8181,  // GlassFish
];

export const PORT_DESCRIPTIONS: Record<number, string> = {
  21: 'FTP',
  22: 'SSH/SFTP',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP Server',
  68: 'DHCP Client',
  69: 'TFTP',
  80: 'HTTP',
  110: 'POP3',
  111: 'RPCbind',
  135: 'MS RPC',
  137: 'NetBIOS Name',
  138: 'NetBIOS Datagram',
  139: 'NetBIOS Session',
  143: 'IMAP',
  161: 'SNMP',
  162: 'SNMP Trap',
  179: 'BGP',
  389: 'LDAP',
  427: 'SLP',
  443: 'HTTPS',
  445: 'SMB',
  465: 'SMTPS',
  514: 'Syslog',
  548: 'AFP',
  587: 'SMTP Submission',
  631: 'IPP',
  636: 'LDAPS',
  873: 'rsync',
  902: 'VMware',
  993: 'IMAPS',
  995: 'POP3S',
  1194: 'OpenVPN',
  1433: 'MS SQL Server',
  1521: 'Oracle DB',
  1723: 'PPTP',
  1935: 'RTMP',
  2375: 'Docker',
  2376: 'Docker TLS',
  3000: 'Node.js/React Dev',
  3128: 'Squid Proxy',
  3306: 'MySQL',
  3389: 'RDP',
  3690: 'SVN',
  4200: 'Angular Dev',
  5000: 'Flask/UPnP',
  5001: 'Synology DSM',
  5060: 'SIP',
  5061: 'SIP TLS',
  5222: 'XMPP Client',
  5269: 'XMPP Server',
  5353: 'mDNS',
  5357: 'WSDAPI',
  5432: 'PostgreSQL',
  5672: 'RabbitMQ',
  5900: 'VNC',
  5984: 'CouchDB',
  6000: 'X11',
  6379: 'Redis',
  6443: 'Kubernetes API',
  7001: 'WebLogic',
  8000: 'HTTP Alt',
  8009: 'Apache JServ',
  8080: 'HTTP Proxy',
  8081: 'HTTP Alt',
  8082: 'HTTP Alt',
  8083: 'HTTP Alt',
  8084: 'HTTP Alt',
  8085: 'HTTP Alt',
  8089: 'Splunk',
  8180: 'Tomcat Alt',
  8181: 'GlassFish',
  8443: 'HTTPS Alt',
  8888: 'HTTP Alt',
  9000: 'PHP-FPM/SonarQube',
  9001: 'Supervisor',
  9090: 'WebSphere/Prometheus',
  9091: 'Prometheus Pushgateway',
  9092: 'Kafka',
  9100: 'Node Exporter',
  9200: 'Elasticsearch',
  9300: 'Elasticsearch Nodes',
  9999: 'Generic Service',
  10000: 'Webmin',
  10250: 'Kubelet',
  11211: 'Memcached',
  27015: 'Steam',
  27017: 'MongoDB',
};

export const DANGEROUS_PORTS = [
  21,    // FTP - Unencrypted file transfer
  23,    // Telnet - Unencrypted remote access
  69,    // TFTP - No authentication
  135,   // MS RPC - Windows vulnerability target
  139,   // NetBIOS - Information leakage
  445,   // SMB - Ransomware vector
  1433,  // MS SQL - Database exposure
  3306,  // MySQL - Database exposure
  3389,  // RDP - Brute force target
  5432,  // PostgreSQL - Database exposure
  6379,  // Redis - Often unprotected
  27017, // MongoDB - Often unprotected
];
