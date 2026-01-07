/**
 * API Client
 *
 * Axios wrapper for making API calls to the backend
 */

import axios from 'axios';

// Base URL for API calls (proxied through Vite in development)
const API_BASE_URL = '/api';

/**
 * Axios instance with default configuration
 */
export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 150000, // 150 seconds (backend has 120s timeout)
  headers: {
    'Content-Type': 'application/json',
  },
});

/**
 * Request interceptor
 * Can be used to add auth tokens, etc.
 */
apiClient.interceptors.request.use(
  (config) => {
    // You can add authentication tokens here if needed
    // const token = localStorage.getItem('auth_token');
    // if (token) {
    //   config.headers.Authorization = `Bearer ${token}`;
    // }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

/**
 * Response interceptor
 * Handles common error scenarios
 */
apiClient.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    if (error.response) {
      // Server responded with error status
      const { status, data } = error.response;

      if (status === 429) {
        // Rate limit exceeded
        throw new Error(data.error || 'Çok fazla istek. Lütfen daha sonra tekrar deneyin.');
      } else if (status === 503) {
        // Service unavailable
        throw new Error(data.error || 'Servis geçici olarak kullanılamıyor.');
      } else if (status >= 500) {
        // Server error
        throw new Error('Sunucu hatası. Lütfen daha sonra tekrar deneyin.');
      } else if (status === 400) {
        // Bad request
        throw new Error(data.error || 'Geçersiz istek.');
      }

      throw new Error(data.error || 'Bir hata oluştu.');
    } else if (error.request) {
      // Request made but no response
      throw new Error('Sunucuya bağlanılamadı. İnternet bağlantınızı kontrol edin.');
    } else {
      // Something else happened
      throw new Error(error.message || 'Bilinmeyen bir hata oluştu.');
    }
  }
);
