/**
 * Rate Limiting Middleware
 *
 * Prevents abuse by limiting the number of requests from a single IP
 */

import rateLimit from 'express-rate-limit';

/**
 * Rate limiter for scan endpoint
 * Limits to 10 requests per 15 minutes per IP
 */
export const scanRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Max 10 requests per windowMs
  message: {
    error: 'Too many scan requests from this IP. Please try again in 15 minutes.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
  // Skip rate limiting in development for easier testing (optional)
  skip: (req) => {
    // Uncomment to disable rate limiting in development
    // return process.env.NODE_ENV === 'development';
    return false;
  },
});

/**
 * General rate limiter for all endpoints
 * Limits to 100 requests per 15 minutes per IP
 */
export const generalRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Max 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP. Please slow down.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});
