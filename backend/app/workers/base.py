import asyncio
import logging
import traceback

logger = logging.getLogger(__name__)

class BaseWorker:
    name: str = "BaseWorker"
    category: str = "general"

    async def run(self, domain: str, url: str) -> dict:
        """Subclasses should implement this method."""
        raise NotImplementedError

    async def execute(self, domain: str, url: str, timeout: int = 30) -> dict:
        """Timeout wrapper and error handling for the worker."""
        result = {
            "status": "success",
            "worker": self.name,
            "category": self.category,
            "findings": [],
            "raw_data": {}
        }
        try:
            worker_task = self.run(domain, url)
            run_result = await asyncio.wait_for(worker_task, timeout=timeout)
            
            result["findings"] = run_result.get("findings", [])
            result["raw_data"] = run_result.get("raw_data", {})
            
        except asyncio.TimeoutError:
            logger.error(f"Worker {self.name} timed out after {timeout}s.")
            result["status"] = "timeout"
        except Exception as e:
            logger.error(f"Worker {self.name} failed: {str(e)}\n{traceback.format_exc()}")
            result["status"] = "error"
            result["error_details"] = str(e)
            
        return result
