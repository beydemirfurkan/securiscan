# Implementation Plan: Enhanced Security Scanner

## Overview

Bu plan, güvenlik tarama aracına PDF/JSON rapor indirme ve gelişmiş güvenlik açığı tespit özelliklerini ekler. Önce backend tarayıcıları, sonra frontend export servisleri implement edilecektir.

## Tasks

- [x] 1. Proje bağımlılıklarını ekle
  - jsPDF ve jspdf-autotable paketlerini frontend için ekle
  - fast-check paketini test için ekle
  - `npm install jspdf jspdf-autotable fast-check`
  - _Requirements: 1.1, 1.3_

- [x] 2. HTTP Methods Scanner implement et
  - [x] 2.1 HTTP Methods Scanner modülünü oluştur
    - `server/scanners/http-methods-scanner.ts` dosyasını oluştur
    - OPTIONS request ile desteklenen metodları tespit et
    - PUT, DELETE, TRACE metodlarını tehlikeli olarak işaretle
    - Severity mapping: PUT/DELETE → HIGH, TRACE → MEDIUM
    - _Requirements: 6.1, 6.2, 6.3, 6.4_
  - [x] 2.2 HTTP Methods Scanner için property test yaz
    - **Property 7: HTTP Methods Vulnerability Mapping**
    - **Validates: Requirements 6.2, 6.3, 6.4**

- [x] 3. Robots.txt & Security.txt Scanner implement et
  - [x] 3.1 Robots Scanner modülünü oluştur
    - `server/scanners/robots-scanner.ts` dosyasını oluştur
    - robots.txt ve /.well-known/security.txt dosyalarını kontrol et
    - Disallow entry'lerini parse et
    - Admin, backup, config pattern'lerini hassas olarak işaretle
    - security.txt yoksa INFO seviyesinde bulgu oluştur
    - _Requirements: 7.1, 7.2, 7.3, 7.4_
  - [x] 3.2 Robots Scanner için property test yaz
    - **Property 8: Robots.txt Analysis**
    - **Validates: Requirements 7.2, 7.3, 7.4**

- [x] 4. CVE Correlator implement et
  - [x] 4.1 CVE Correlator modülünü oluştur
    - `server/scanners/cve-correlator.ts` dosyasını oluştur
    - Yaygın teknolojiler için lokal CVE veritabanı oluştur (WordPress, Apache, nginx, jQuery, etc.)
    - Versiyon eşleştirme mantığı implement et
    - CVE'leri CVSS skoruna göre sırala
    - _Requirements: 8.1, 8.2, 8.3, 8.4_
  - [x] 4.2 CVE Correlator için property test yaz
    - **Property 9: CVE Correlation**
    - **Validates: Requirements 8.1, 8.2, 8.3, 8.4**

- [x] 5. Active Scanner'ı genişlet
  - [x] 5.1 Directory Traversal taramasını geliştir
    - Daha fazla traversal pattern ekle (../, ..%2f, ..%252f, etc.)
    - /etc/passwd, web.config, win.ini gibi hedef dosyaları kontrol et
    - Başarılı payload'ı rapora dahil et
    - _Requirements: 4.1, 4.2, 4.3, 4.4_
  - [x] 5.2 Directory Traversal için property test yaz
    - **Property 5: Directory Traversal Detection**
    - **Validates: Requirements 4.2, 4.4**
  - [x] 5.3 CORS taramasını geliştir
    - Daha fazla test origin'i ekle (null, subdomain, scheme variation)
    - Severity mapping'i güncelle
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_
  - [x] 5.4 CORS Scanner için property test yaz
    - **Property 4: CORS Severity Mapping**
    - **Validates: Requirements 3.2, 3.3, 3.4**
  - [x] 5.5 Open Redirect taramasını geliştir
    - Daha fazla redirect parametresi ekle
    - Exploit URL örneği oluştur
    - _Requirements: 5.1, 5.2, 5.3, 5.4_
  - [x] 5.6 Open Redirect için property test yaz
    - **Property 6: Open Redirect Detection**
    - **Validates: Requirements 5.2, 5.4**

- [x] 6. Scanner Index'i güncelle
  - Yeni tarayıcıları ana orchestrator'a entegre et
  - `server/scanners/index.ts` dosyasını güncelle
  - HTTP Methods, Robots, CVE sonuçlarını SecurityReport'a ekle
  - _Requirements: 3.5, 5.4, 6.4, 7.4, 8.2_

- [x] 7. Checkpoint - Backend tarayıcıları test et
  - Tüm yeni tarayıcıların çalıştığını doğrula
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. JSON Export Service implement et
  - [x] 8.1 Report Exporter servisini oluştur
    - `src/services/report-exporter.service.ts` dosyasını oluştur
    - JSON serialization implement et
    - Filename generation implement et
    - Browser download trigger implement et
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
  - [x] 8.2 JSON Export için property testleri yaz
    - **Property 1: JSON Export Round-Trip**
    - **Property 2: Filename Generation Format**
    - **Property 3: JSON Indentation**
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 1.4**

- [x] 9. PDF Generator Service implement et
  - [x] 9.1 PDF Generator servisini oluştur
    - `src/services/pdf-generator.service.ts` dosyasını oluştur
    - jsPDF ile PDF oluşturma implement et
    - Executive summary section ekle
    - Vulnerability table (severity renkli) ekle
    - Action plan section ekle
    - Network info section ekle
    - _Requirements: 1.1, 1.2, 1.3_
  - [x] 9.2 Error handling ekle
    - PDF generation hatalarını yakala
    - Kullanıcıya hata mesajı göster
    - _Requirements: 1.5_

- [x] 10. Frontend UI'ı güncelle
  - [x] 10.1 Download butonlarını çalışır hale getir
    - ReportDashboard'daki PDF/JSON butonunu bağla
    - Loading state ekle
    - Success/error toast notification ekle
    - _Requirements: 1.1, 1.4, 2.1, 2.3_
  - [x] 10.2 Yeni tarama sonuçlarını göster
    - HTTP Methods sonuçlarını UI'a ekle
    - Robots.txt bulgularını göster
    - CVE korelasyonlarını vulnerability card'lara ekle
    - _Requirements: 6.4, 7.4, 8.2_

- [x] 11. Final Checkpoint
  - Tüm özelliklerin çalıştığını doğrula
  - PDF ve JSON indirme test et
  - Yeni tarayıcıların sonuç ürettiğini doğrula
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tüm task'lar zorunlu - kapsamlı test coverage için
- Backend tarayıcıları önce implement edilecek, sonra frontend
- jsPDF kütüphanesi client-side PDF generation için kullanılacak
- fast-check kütüphanesi property-based testing için kullanılacak
- Her property test minimum 100 iterasyon çalıştırmalı
