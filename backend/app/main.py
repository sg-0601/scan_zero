import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.config import settings
from app.models.database import engine, create_tables
from app.api.scan import router as scan_router
from app.api.monitor import router as monitor_router

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Try to initialize DB tables if database is available
    try:
        await create_tables()
        logger.info("Connected to PostgreSQL database successfully.")
    except Exception as e:
        logger.warning(f"Database connection skipped - ScanZero running in high-availability in-memory mode: {e}")
    yield
    # Shutdown
    try:
        await engine.dispose()
    except Exception:
        pass

app = FastAPI(title="ScanZero API", lifespan=lifespan)

# Global CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handler ensuring CORS headers are present even on uncaught errors
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    origin = request.headers.get("origin", "*")
    logger.error(f"Global unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error", "error": str(exc)},
        headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "*",
        },
    )

@app.get("/api/health")
async def health_check():
    """Health check endpoint to verify the service is running."""
    return {"status": "ok", "service": "scanzero-backend"}

# Include routers for 1-Click Scan & Stage 9 Continuous Watch
app.include_router(scan_router, prefix="/api", tags=["scan"])
app.include_router(monitor_router, prefix="/api", tags=["monitor"])
