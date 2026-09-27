/**
 * ScanZero Frontend Configuration
 * Centralized API Base URL for seamless local development and cloud production deployment.
 */
export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/+$/, "") ||
  (typeof window !== "undefined" && window.location.hostname !== "localhost" && window.location.hostname !== "127.0.0.1"
    ? "https://scan-zero.onrender.com"
    : "http://localhost:8000");
