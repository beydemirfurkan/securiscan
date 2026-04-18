export const APP_CONFIG = {
  name: 'SecuriScan',
  version: '1.0.0',
  fullName: 'SecuriScan AI',
} as const;

export const SCAN_CONFIG = {
  maxUrlLength: 2048,
  scanTimeout: 30000,
  terminalAnimationDelay: 600,
} as const;

export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001/api';
