# Requirements Document

## Introduction

Bu özellik, güvenlik tarama aracını iki ana alanda geliştirir: (1) tarama sonuçlarının PDF ve JSON formatlarında indirilmesi, (2) daha kapsamlı güvenlik açığı tespiti için yeni tarama modüllerinin eklenmesi.

## Glossary

- **Report_Exporter**: Güvenlik raporlarını farklı formatlara (PDF, JSON) dönüştüren modül
- **Security_Scanner**: Web sitelerini güvenlik açıkları için tarayan ana sistem
- **Vulnerability_Detector**: Tespit edilen güvenlik açıklarını analiz eden ve raporlayan bileşen
- **OWASP_Top_10**: En yaygın 10 web güvenlik açığını tanımlayan endüstri standardı
- **CVE**: Common Vulnerabilities and Exposures - bilinen güvenlik açıkları veritabanı
- **CORS_Scanner**: Cross-Origin Resource Sharing yapılandırma hatalarını tespit eden modül
- **Directory_Traversal_Scanner**: Dizin gezinme açıklarını tespit eden modül
- **Open_Redirect_Scanner**: Açık yönlendirme açıklarını tespit eden modül

## Requirements

### Requirement 1: PDF Rapor İndirme

**User Story:** As a security analyst, I want to download scan reports as PDF files, so that I can share findings with stakeholders and archive results.

#### Acceptance Criteria

1. WHEN a user clicks the PDF download button, THE Report_Exporter SHALL generate a PDF document containing all scan results
2. WHEN generating a PDF report, THE Report_Exporter SHALL include executive summary, vulnerability list, risk scores, and remediation recommendations
3. WHEN generating a PDF report, THE Report_Exporter SHALL format the document with proper styling including headers, tables, and color-coded severity indicators
4. WHEN the PDF generation is complete, THE Report_Exporter SHALL trigger a browser download with filename format "security-report-{domain}-{timestamp}.pdf"
5. IF PDF generation fails, THEN THE Report_Exporter SHALL display an error message to the user

### Requirement 2: JSON Rapor İndirme

**User Story:** As a developer, I want to download scan reports as JSON files, so that I can integrate results with other tools and automate security workflows.

#### Acceptance Criteria

1. WHEN a user clicks the JSON download button, THE Report_Exporter SHALL generate a JSON file containing the complete SecurityReport object
2. WHEN generating a JSON report, THE Report_Exporter SHALL include all scan data: vulnerabilities, network info, tech stack, compliance status, and action plan
3. WHEN the JSON generation is complete, THE Report_Exporter SHALL trigger a browser download with filename format "security-report-{domain}-{timestamp}.json"
4. THE Report_Exporter SHALL format the JSON with proper indentation for human readability

### Requirement 3: CORS Misconfiguration Detection

**User Story:** As a security analyst, I want to detect CORS misconfigurations, so that I can identify potential cross-origin attack vectors.

#### Acceptance Criteria

1. WHEN scanning a target URL, THE CORS_Scanner SHALL send requests with various Origin headers to test CORS policy
2. WHEN a wildcard (*) Access-Control-Allow-Origin is detected, THE CORS_Scanner SHALL report a HIGH severity vulnerability
3. WHEN credentials are allowed with permissive origins, THE CORS_Scanner SHALL report a CRITICAL severity vulnerability
4. WHEN the origin is reflected without validation, THE CORS_Scanner SHALL report a HIGH severity vulnerability
5. THE Vulnerability_Detector SHALL include CORS findings in the final vulnerability report with remediation steps

### Requirement 4: Directory Traversal Detection

**User Story:** As a security analyst, I want to detect directory traversal vulnerabilities, so that I can identify potential unauthorized file access risks.

#### Acceptance Criteria

1. WHEN scanning a target URL, THE Directory_Traversal_Scanner SHALL test common traversal patterns (../, ..%2f, etc.)
2. WHEN a traversal attempt returns sensitive file content indicators, THE Directory_Traversal_Scanner SHALL report a CRITICAL severity vulnerability
3. WHEN testing traversal patterns, THE Directory_Traversal_Scanner SHALL check for /etc/passwd, web.config, and other sensitive files
4. THE Directory_Traversal_Scanner SHALL include the successful payload in the vulnerability report

### Requirement 5: Open Redirect Detection

**User Story:** As a security analyst, I want to detect open redirect vulnerabilities, so that I can identify potential phishing attack vectors.

#### Acceptance Criteria

1. WHEN scanning a target URL, THE Open_Redirect_Scanner SHALL identify URL parameters that may accept redirect destinations
2. WHEN a parameter allows redirection to external domains, THE Open_Redirect_Scanner SHALL report a MEDIUM severity vulnerability
3. THE Open_Redirect_Scanner SHALL test common redirect parameters (url, redirect, next, return, goto, destination)
4. THE Vulnerability_Detector SHALL include open redirect findings with example exploit URLs

### Requirement 6: HTTP Method Testing

**User Story:** As a security analyst, I want to detect dangerous HTTP methods, so that I can identify potential unauthorized actions on the server.

#### Acceptance Criteria

1. WHEN scanning a target URL, THE Security_Scanner SHALL test for enabled HTTP methods (OPTIONS, PUT, DELETE, TRACE)
2. WHEN dangerous methods (PUT, DELETE, TRACE) are enabled, THE Security_Scanner SHALL report appropriate severity vulnerabilities
3. WHEN TRACE method is enabled, THE Security_Scanner SHALL report a MEDIUM severity vulnerability due to XST attack potential
4. THE Security_Scanner SHALL include the list of enabled methods in the vulnerability details

### Requirement 7: Security.txt and robots.txt Analysis

**User Story:** As a security analyst, I want to analyze security.txt and robots.txt files, so that I can discover hidden paths and security contact information.

#### Acceptance Criteria

1. WHEN scanning a target URL, THE Security_Scanner SHALL check for /.well-known/security.txt and /robots.txt
2. WHEN robots.txt contains Disallow entries, THE Security_Scanner SHALL extract and report potentially sensitive paths
3. WHEN security.txt is missing, THE Security_Scanner SHALL report an INFO level finding recommending its implementation
4. THE Security_Scanner SHALL parse robots.txt to identify admin panels, backup directories, and sensitive endpoints

### Requirement 8: Enhanced CVE Correlation

**User Story:** As a security analyst, I want detected technologies to be correlated with known CVEs, so that I can understand specific vulnerabilities affecting the target.

#### Acceptance Criteria

1. WHEN a technology with version is detected, THE Vulnerability_Detector SHALL query for known CVEs affecting that version
2. WHEN CVEs are found, THE Vulnerability_Detector SHALL include CVE IDs, CVSS scores, and NVD links in the report
3. THE Vulnerability_Detector SHALL prioritize CVEs with known exploits or high CVSS scores
4. WHEN no version is detected, THE Vulnerability_Detector SHALL report common CVEs for that technology family
