/**
 * Centralized Error Handling Middleware
 *
 * Catches and formats errors consistently across the application
 */

import { Request, Response, NextFunction } from 'express';
import { NODE_ENV } from '../config/env';

export interface AppError extends Error {
  statusCode?: number;
  isOperational?: boolean;
}

/**
 * Error handler middleware
 * Must be used last in the middleware chain
 */
export function errorHandler(
  err: AppError,
  req: Request,
  res: Response,
  next: NextFunction
) {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';

  // Log error in development
  if (NODE_ENV === 'development') {
    console.error('[ERROR]', {
      method: req.method,
      path: req.path,
      statusCode,
      message,
      stack: err.stack,
    });
  } else {
    // In production, log only essential info
    console.error('[ERROR]', {
      method: req.method,
      path: req.path,
      statusCode,
      message,
    });
  }

  // Send error response
  res.status(statusCode).json({
    error: message,
    ...(NODE_ENV === 'development' && { stack: err.stack }),
  });
}

/**
 * 404 Not Found handler
 */
export function notFoundHandler(req: Request, res: Response) {
  res.status(404).json({
    error: 'Not Found',
    message: `Cannot ${req.method} ${req.path}`,
  });
}

/**
 * Async error wrapper
 * Wraps async route handlers to catch errors and pass them to error middleware
 */
export function asyncHandler(fn: Function) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}
