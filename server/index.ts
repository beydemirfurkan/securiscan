/**
 * SecuriScan AI - Backend Server
 *
 * Express server providing secure AI-powered security scanning API
 */

import express from 'express';
import helmet from 'helmet';
import { PORT, NODE_ENV } from './config/env';
import { corsMiddleware } from './middleware/cors';
import { generalRateLimiter } from './middleware/rate-limit';
import { errorHandler, notFoundHandler } from './middleware/error-handler';
import scanRoutes from './routes/scan.routes';
import paymentRoutes from './routes/payment.routes';

// Initialize Express app
const app = express();

// ===== SECURITY MIDDLEWARE =====
// Helmet sets various HTTP headers for security
app.use(helmet());

// CORS configuration
app.use(corsMiddleware);

// ===== BODY PARSING =====
app.use(express.json()); // Parse JSON request bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies

// ===== RATE LIMITING =====
// Apply general rate limiting to all routes
app.use(generalRateLimiter);

// ===== ROUTES =====
// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
    message: 'SecuriScan AI Backend is running',
  });
});

// Scan endpoint
app.use('/api/scan', scanRoutes);

// Payment endpoints
app.use('/api/payment', paymentRoutes);

// ===== ERROR HANDLING =====
// 404 handler (must be after all routes)
app.use(notFoundHandler);

// Global error handler (must be last)
app.use(errorHandler);

// ===== START SERVER =====
app.listen(PORT, () => {
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║                                                           ║');
  console.log('║            🛡️  SecuriScan AI Backend Server              ║');
  console.log('║                                                           ║');
  console.log('╚═══════════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`  🚀 Server running on: http://localhost:${PORT}`);
  console.log(`  🌍 Environment: ${NODE_ENV}`);
  console.log(`  📊 Health check: http://localhost:${PORT}/api/health`);
  console.log('');
  console.log('  Available endpoints:');
  console.log(`    • POST /api/scan - Security scanning`);
  console.log(`    • POST /api/payment/verify - Payment verification`);
  console.log('');
  console.log('  Press Ctrl+C to stop the server');
  console.log('');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('\n🛑 SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('\n🛑 SIGINT received. Shutting down gracefully...');
  process.exit(0);
});

export default app;
