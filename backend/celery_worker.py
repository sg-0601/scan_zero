from celery import Celery
import asyncio
from app.config import settings

# Initialize Celery app
celery_app = Celery(
    "scanzero_tasks",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

@celery_app.task(name="scan_task")
def run_scan_task(scan_id: str, domain: str, url: str):
    """
    Celery task that wraps the async dispatcher.run_scan.
    """
    from app.engine.dispatcher import run_scan
    
    # Create new event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        result = loop.run_until_complete(run_scan(scan_id, domain, url))
        return result
    finally:
        loop.close()
