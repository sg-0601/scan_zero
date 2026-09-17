/**
 * ScanZero Frontend Configuration
 * Centralized API Base URL for seamless local development and cloud production deployment.
 */
export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/+$/, "") || "http://localhost:8000";
