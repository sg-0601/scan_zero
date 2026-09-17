import sys
import os

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from celery_worker import celery_app, run_scan_task

__all__ = ["celery_app", "run_scan_task"]
