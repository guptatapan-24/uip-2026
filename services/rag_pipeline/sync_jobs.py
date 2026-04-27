# services/rag_pipeline/sync_jobs.py
"""
Celery Beat scheduled sync tasks for threat intelligence sources.

Tasks:
- sync_kev: Daily sync from CISA KEV (11:00 PM UTC)
- sync_nvd_delta: Weekly delta sync from NVD (Sunday 2:00 AM UTC)
- sync_attack: Monthly full sync from MITRE ATT&CK (1st of month, 3:00 AM UTC)

These tasks refresh local caches and rebuild FAISS indexes incrementally.

TODO: Wire Tanushree's or Tapan's modules if they handle scheduled tasks
"""

import asyncio
import os
from celery import Celery, Task
from celery.schedules import crontab

# TODO: Import clients
# from nvd_client import get_nvd_client
# from attack_client import get_attack_client
# from kev_client import get_kev_client
# from faiss_index import get_faiss_index

celery_app = Celery(
    "rag_pipeline",
    broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/1"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/2")
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)


class CallbackTask(Task):
    """Task with callbacks for success/failure."""
    def on_success(self, retval, task_id, args, kwargs):
        print(f"Task {task_id} completed successfully")
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        print(f"Task {task_id} failed: {exc}")


@celery_app.task(base=CallbackTask, bind=True)
def sync_kev(self):
    """
    Sync CISA Known Exploited Vulnerabilities daily.
    
    Fetches latest KEV catalog and updates cache.
    """
    try:
        # TODO: Call kev_client.sync_data()
        # TODO: Rebuild FAISS index if needed
        print("KEV sync completed")
        return {"status": "success", "source": "KEV"}
    except Exception as e:
        print(f"KEV sync failed: {e}")
        raise


@celery_app.task(base=CallbackTask, bind=True)
def sync_nvd_delta(self):
    """
    Sync NVD vulnerability database weekly (delta/incremental).
    
    Fetches modified CVEs from last sync timestamp.
    """
    try:
        # TODO: Call nvd_client.sync_modified_since(last_sync_time)
        # TODO: Update FAISS index with new CVEs
        print("NVD delta sync completed")
        return {"status": "success", "source": "NVD"}
    except Exception as e:
        print(f"NVD sync failed: {e}")
        raise


@celery_app.task(base=CallbackTask, bind=True)
def sync_attack(self):
    """
    Sync MITRE ATT&CK framework monthly (full).
    
    Fetches all techniques, tactics, and relationships.
    """
    try:
        # TODO: Call attack_client.sync_data()
        # TODO: Rebuild FAISS index with all ATT&CK data
        print("ATT&CK sync completed")
        return {"status": "success", "source": "ATT&CK"}
    except Exception as e:
        print(f"ATT&CK sync failed: {e}")
        raise


# Celery Beat schedule
celery_app.conf.beat_schedule = {
    "sync-kev-daily": {
        "task": "sync_jobs.sync_kev",
        "schedule": crontab(hour=23, minute=0),  # 11 PM UTC
    },
    "sync-nvd-weekly": {
        "task": "sync_jobs.sync_nvd_delta",
        "schedule": crontab(day_of_week=6, hour=2, minute=0),  # Sunday 2 AM UTC
    },
    "sync-attack-monthly": {
        "task": "sync_jobs.sync_attack",
        "schedule": crontab(day_of_month=1, hour=3, minute=0),  # 1st of month, 3 AM UTC
    },
}


if __name__ == "__main__":
    celery_app.start()
