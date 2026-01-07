/**
 * CORS Middleware Configuration
 *
 * Configures Cross-Origin Resource Sharing to allow frontend to communicate with backend
 */

import cors from 'cors';
import { CLIENT_URL, NODE_ENV } from '../config/env';

export const corsMiddleware = cors({
  origin: (origin, callback) => {
    // In development, allow all localhost origins (Vite may use different ports)
    if (NODE_ENV === 'development') {
      // Allow requests without origin (like Postman, curl)
      if (!origin) {
        return callback(null, true);
      }
      
      // Allow any localhost origin in development
      if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
        return callback(null, true);
      }
    }

    // Allow requests from the configured client URL
    const allowedOrigins = [CLIENT_URL];

    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
});
