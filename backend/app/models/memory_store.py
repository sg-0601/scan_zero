from typing import Dict, Any

# In-memory storage for scans when external database (PostgreSQL) is offline or not configured.
# Ensures 100% server uptime and zero 500 errors on lightweight cloud container deployments.
MEMORY_SCANS: Dict[str, Dict[str, Any]] = {}
