/**
 * Report Exporter Service
 *
 * Handles exporting security reports to different formats (PDF, JSON)
 * Feature: enhanced-security-scanner
 * Requirements: 1.1, 1.3, 1.4, 1.5, 2.1, 2.2, 2.3, 2.4
 */

import type { SecurityReport } from '../types/security-report.types';
import { generatePDF } from './pdf-generator.service';

export interface ReportExportOptions {
  format: 'pdf' | 'json';
  includeExecutiveSummary: boolean;
  includeRemediation: boolean;
  language: 'tr' | 'en';
}

export interface ExportResult {
  success: boolean;
  filename: string;
  error?: string;
}

export interface ExportMetadata {
  generatedAt: string;
  generatorVersion: string;
  reportFormat: 'pdf' | 'json';
  language: 'tr' | 'en';
}

// Localized error messages for Requirement 1.5
const ERROR_MESSAGES = {
  tr: {
    pdfGenerationFailed: 'PDF oluşturma başarısız oldu',
    jsonExportFailed: 'JSON dışa aktarma başarısız oldu',
    unsupportedFormat: 'Desteklenmeyen dışa aktarma formatı',
    unknownError: 'Bilinmeyen bir hata oluştu',
    downloadBlocked: 'İndirme engellenmiş olabilir. Lütfen tarayıcı ayarlarınızı kontrol edin.'
  },
  en: {
    pdfGenerationFailed: 'PDF generation failed',
    jsonExportFailed: 'JSON export failed',
    unsupportedFormat: 'Unsupported export format',
    unknownError: 'An unknown error occurred',
    downloadBlocked: 'Download may be blocked. Please check your browser settings.'
  }
};

/**
 * Get localized error message
 */
function getErrorMessage(key: keyof typeof ERROR_MESSAGES['en'], lang: 'tr' | 'en' = 'tr'): string {
  return ERROR_MESSAGES[lang][key];
}

/**
 * Extract domain from URL for filename generation
 */
export function extractDomain(url: string): string {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
  } catch {
    // Fallback for invalid URLs
    return url.replace(/[^a-zA-Z0-9.-]/g, '_').substring(0, 50);
  }
}

/**
 * Generate filename based on domain and timestamp
 * Format: security-report-{domain}-{timestamp}.{format}
 */
export function generateFilename(domain: string, format: 'pdf' | 'json'): string {
  const sanitizedDomain = extractDomain(domain);
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  return `security-report-${sanitizedDomain}-${timestamp}.${format}`;
}

/**
 * Serialize SecurityReport to JSON with proper indentation
 * Uses 2-space indentation for human readability
 */
export function serializeToJson(report: SecurityReport, metadata?: ExportMetadata): string {
  const exportData = {
    metadata: metadata || {
      generatedAt: new Date().toISOString(),
      generatorVersion: '1.0.0',
      reportFormat: 'json' as const,
      language: 'tr' as const
    },
    report
  };

  return JSON.stringify(exportData, null, 2);
}

/**
 * Trigger browser download for a blob
 */
export function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Export security report to JSON format
 */
export async function exportToJson(
  report: SecurityReport,
  options: Partial<ReportExportOptions> = {}
): Promise<ExportResult> {
  const language = options.language || 'tr';

  try {
    const metadata: ExportMetadata = {
      generatedAt: new Date().toISOString(),
      generatorVersion: '1.0.0',
      reportFormat: 'json',
      language
    };

    const jsonString = serializeToJson(report, metadata);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const filename = generateFilename(report.targetUrl, 'json');

    triggerDownload(blob, filename);

    return {
      success: true,
      filename
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error during JSON export';
    return {
      success: false,
      filename: '',
      error: errorMessage
    };
  }
}

/**
 * Main export function - routes to appropriate format handler
 */
export async function exportReport(
  report: SecurityReport,
  options: ReportExportOptions
): Promise<ExportResult> {
  if (options.format === 'json') {
    return exportToJson(report, options);
  }

  if (options.format === 'pdf') {
    return exportToPdf(report, options);
  }

  return {
    success: false,
    filename: '',
    error: getErrorMessage('unsupportedFormat', options.language)
  };
}

/**
 * Export security report to PDF format
 * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
 */
export async function exportToPdf(
  report: SecurityReport,
  options: Partial<ReportExportOptions> = {}
): Promise<ExportResult> {
  const language = options.language || 'tr';

  try {
    const result = await generatePDF(report, language);

    if (!result.success || !result.blob) {
      return {
        success: false,
        filename: '',
        error: result.error || getErrorMessage('pdfGenerationFailed', language)
      };
    }

    const filename = generateFilename(report.targetUrl, 'pdf');
    triggerDownload(result.blob, filename);

    return {
      success: true,
      filename
    };
  } catch (error) {
    // Requirement 1.5: Display localized error message to user
    let errorMessage = getErrorMessage('unknownError', language);
    
    if (error instanceof Error) {
      // Check for specific error types and provide helpful messages
      if (error.message.includes('blocked') || error.message.includes('popup')) {
        errorMessage = getErrorMessage('downloadBlocked', language);
      } else {
        errorMessage = `${getErrorMessage('pdfGenerationFailed', language)}: ${error.message}`;
      }
    }
    
    return {
      success: false,
      filename: '',
      error: errorMessage
    };
  }
}

/**
 * ReportExporter class for object-oriented usage
 */
export class ReportExporter {
  private defaultOptions: Partial<ReportExportOptions>;

  constructor(defaultOptions: Partial<ReportExportOptions> = {}) {
    this.defaultOptions = defaultOptions;
  }

  /**
   * Export security report to specified format
   */
  async export(report: SecurityReport, options: ReportExportOptions): Promise<ExportResult> {
    const mergedOptions = { ...this.defaultOptions, ...options };
    return exportReport(report, mergedOptions);
  }

  /**
   * Generate filename based on domain and timestamp
   */
  generateFilename(domain: string, format: 'pdf' | 'json'): string {
    return generateFilename(domain, format);
  }

  /**
   * Export to JSON format
   */
  async exportJson(report: SecurityReport, language: 'tr' | 'en' = 'tr'): Promise<ExportResult> {
    return exportToJson(report, { language });
  }

  /**
   * Export to PDF format
   * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
   */
  async exportPdf(report: SecurityReport, language: 'tr' | 'en' = 'tr'): Promise<ExportResult> {
    return exportToPdf(report, { language });
  }
}

export default ReportExporter;
