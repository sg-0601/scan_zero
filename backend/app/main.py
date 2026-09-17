from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.config import settings
from app.models.database import engine, create_tables
from app.api.scan import router as scan_router
from app.api.monitor import router as monitor_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Create tables if they don't exist
    try:
        await create_tables()
    except Exception:
        pass
    yield
    # Shutdown
    await engine.dispose()

app = FastAPI(title="ScanZero API", lifespan=lifespan)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
async def health_check():
    """Health check endpoint to verify the service is running."""
    return {"status": "ok", "service": "scanzero-backend"}

# Include routers for 1-Click Scan & Stage 9 Continuous Watch
app.include_router(scan_router, prefix="/api", tags=["scan"])
app.include_router(monitor_router, prefix="/api", tags=["monitor"])
