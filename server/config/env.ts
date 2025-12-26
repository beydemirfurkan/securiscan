/**
 * Environment Configuration and Validation
 *
 * Validates required environment variables and provides typed access
 */

import dotenv from 'dotenv';

// Load environment variables from .env.local
dotenv.config({ path: '.env.local' });

interface EnvironmentConfig {
  PORT: number;
  NODE_ENV: 'development' | 'production' | 'test';
  CLIENT_URL: string;
}

function validateEnv(): EnvironmentConfig {
  const {
    PORT = '3001',
    NODE_ENV = 'development',
    CLIENT_URL = 'http://localhost:3000',
  } = process.env;

  // Validate NODE_ENV
  if (!['development', 'production', 'test'].includes(NODE_ENV)) {
    throw new Error(`Invalid NODE_ENV: ${NODE_ENV}. Must be 'development', 'production', or 'test'`);
  }

  return {
    PORT: parseInt(PORT, 10),
    NODE_ENV: NODE_ENV as 'development' | 'production' | 'test',
    CLIENT_URL,
  };
}

// Validate and export configuration
export const config = validateEnv();

// Export individual values for convenience
export const {
  PORT,
  NODE_ENV,
  CLIENT_URL,
} = config;
