/**
 * Application Constants
 *
 * Centralized configuration values used throughout the application
 */

export const APP_CONFIG = {
  name: 'SecuriScan',
  version: '4.0.2',
  fullName: 'SecuriScan AI',
} as const;

export const SCAN_CONFIG = {
  maxUrlLength: 2048,
  scanTimeout: 30000, // 30 seconds
  terminalAnimationDelay: 600, // ms between terminal messages
} as const;

export const PAYMENT_CONFIG = {
  price: {
    tr: '₺250',
    en: '$29'
  }
} as const;

// API Base URL for SSE connections
export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001/api';
