/**
 * CORS Middleware Configuration
 *
 * Configures Cross-Origin Resource Sharing to allow frontend to communicate with backend
 */

import cors from 'cors';
import { CLIENT_URL, NODE_ENV } from '../config/env';

export const corsMiddleware = cors({
  origin: (origin, callback) => {
    // Allow requests from the client URL
    const allowedOrigins = [CLIENT_URL];

    // In development, also allow requests without origin (like Postman, curl)
    if (NODE_ENV === 'development' && !origin) {
      return callback(null, true);
    }

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
