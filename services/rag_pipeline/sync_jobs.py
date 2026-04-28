"""Celery Beat scheduled sync tasks for threat intelligence sources."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from celery import Celery, Task
from celery.schedules import crontab


celery_app = Celery(
    "rag_pipeline",
    broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/1"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/2"),
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


def _to_document(doc_id: str, source: str, text: str, metadata: dict[str, Any]) -> dict[str, str]:
    return {
        "id": doc_id,
        "source": source,
        "text": text.strip(),
        "metadata": json.dumps(metadata, sort_keys=True, default=str),
    }


def _join_parts(*parts: Any) -> str:
    values = [str(part).strip() for part in parts if part not in (None, "")]
    return " ".join(values).strip()


async def _collect_kev_documents(kev_client) -> list[dict[str, str]]:
    documents: list[dict[str, str]] = []
    for cve_id, entry in kev_client.kev_data.items():
        text = _join_parts(
            cve_id,
            entry.get("vulnerabilityName"),
            entry.get("shortDescription"),
            entry.get("notes"),
            entry.get("dateAdded"),
            entry.get("dueDate"),
            entry.get("knownRansomwareCampaignUse"),
        )
        documents.append(_to_document(cve_id, "KEV", text, entry))
    return documents


async def _collect_attack_documents(attack_client) -> list[dict[str, str]]:
    documents: list[dict[str, str]] = []
    for technique_id, technique in attack_client.techniques.items():
        phases = [
            str(phase.get("phase_name", "")).replace("-", " ")
            for phase in technique.get("kill_chain_phases", [])
            if isinstance(phase, dict)
        ]
        platforms = [str(item) for item in technique.get("x_mitre_platforms", [])]
        text = _join_parts(
            technique_id,
            technique.get("name"),
            technique.get("description"),
            ", ".join(phases),
            ", ".join(platforms),
        )
        documents.append(_to_document(technique_id, "ATTACK", text, technique))
    return documents


async def _collect_nvd_documents(nvd_client) -> list[dict[str, str]]:
    documents: list[dict[str, str]] = []
    redis_client = getattr(nvd_client, "redis_client", None)
    if redis_client is None:
        return documents

    try:
        async for raw_key in redis_client.scan_iter(match="nvd:*"):
            key = raw_key.decode("utf-8") if isinstance(raw_key, (bytes, bytearray)) else str(raw_key)
            raw_value = await redis_client.get(raw_key)
            if not raw_value:
                continue
            if isinstance(raw_value, (bytes, bytearray)):
                raw_value = raw_value.decode("utf-8")
            try:
                record = json.loads(raw_value)
            except json.JSONDecodeError:
                continue

            cve_id = str(record.get("cve_id") or key.removeprefix("nvd:"))
            text = _join_parts(
                cve_id,
                record.get("description"),
                record.get("cvss_v3_score"),
                record.get("cvss_v3_vector"),
                ", ".join(record.get("affected_products", [])) if isinstance(record.get("affected_products"), list) else record.get("affected_products"),
                record.get("published_date"),
                record.get("last_modified_date"),
            )
            documents.append(_to_document(cve_id, "NVD", text, record))
    except Exception as exc:
        print(f"NVD document collection failed: {exc}")

    return documents


async def _collect_candidate_nvd_ids(nvd_client) -> list[str]:
    configured = [item.strip() for item in os.getenv("NVD_SYNC_CVE_IDS", "").split(",") if item.strip()]
    if configured:
        return configured

    redis_client = getattr(nvd_client, "redis_client", None)
    if redis_client is None:
        return []

    ids: list[str] = []
    limit = int(os.getenv("NVD_SYNC_MAX_IDS", "500"))
    try:
        async for raw_key in redis_client.scan_iter(match="nvd:*"):
            key = raw_key.decode("utf-8") if isinstance(raw_key, (bytes, bytearray)) else str(raw_key)
            ids.append(key.removeprefix("nvd:"))
            if len(ids) >= limit:
                break
    except Exception as exc:
        print(f"NVD candidate discovery failed: {exc}")

    return ids


async def _rebuild_faiss_index(documents: list[dict[str, str]]) -> dict[str, Any]:
    if not documents:
        return {"rebuilt": False, "document_count": 0, "reason": "no_documents"}

    from services.rag_pipeline.faiss_index import get_faiss_index

    index = get_faiss_index()
    rebuilt = await asyncio.to_thread(index.build_index, documents)
    return {
        "rebuilt": bool(rebuilt),
        "document_count": len(documents),
        "index_stats": index.get_index_stats() if rebuilt else {},
    }


async def _refresh_index_snapshot(nvd_client=None, attack_client=None, kev_client=None) -> dict[str, Any]:
    documents: list[dict[str, str]] = []

    if nvd_client is not None:
        documents.extend(await _collect_nvd_documents(nvd_client))
    if attack_client is not None:
        documents.extend(await _collect_attack_documents(attack_client))
    if kev_client is not None:
        documents.extend(await _collect_kev_documents(kev_client))

    deduplicated: dict[str, dict[str, str]] = {}
    for document in documents:
        deduplicated[document["id"]] = document

    return await _rebuild_faiss_index(list(deduplicated.values()))


async def _sync_kev_task() -> dict[str, Any]:
    from services.rag_pipeline.attack_client import get_attack_client
    from services.rag_pipeline.kev_client import get_kev_client
    from services.rag_pipeline.nvd_client import get_nvd_client

    kev_client = await get_kev_client()
    attack_client = await get_attack_client()
    nvd_client = await get_nvd_client()

    synced = await kev_client.sync_data()
    index_refresh = await _refresh_index_snapshot(
        nvd_client=nvd_client,
        attack_client=attack_client,
        kev_client=kev_client,
    )

    return {
        "status": "success" if synced else "partial",
        "source": "KEV",
        "synced": synced,
        "kev_entries": len(kev_client.kev_data),
        "index_refresh": index_refresh,
    }


async def _sync_nvd_delta_task() -> dict[str, Any]:
    from services.rag_pipeline.attack_client import get_attack_client
    from services.rag_pipeline.kev_client import get_kev_client
    from services.rag_pipeline.nvd_client import get_nvd_client

    nvd_client = await get_nvd_client()
    attack_client = await get_attack_client()
    kev_client = await get_kev_client()

    candidate_ids = await _collect_candidate_nvd_ids(nvd_client)
    refreshed = 0
    if candidate_ids:
        results = await nvd_client.get_cves_batch(candidate_ids)
        refreshed = sum(1 for record in results.values() if record is not None)

    index_refresh = await _refresh_index_snapshot(
        nvd_client=nvd_client,
        attack_client=attack_client,
        kev_client=kev_client,
    )

    return {
        "status": "success",
        "source": "NVD",
        "refreshed_cves": refreshed,
        "candidate_ids": len(candidate_ids),
        "index_refresh": index_refresh,
    }


async def _sync_attack_task() -> dict[str, Any]:
    from services.rag_pipeline.attack_client import get_attack_client
    from services.rag_pipeline.kev_client import get_kev_client
    from services.rag_pipeline.nvd_client import get_nvd_client

    attack_client = await get_attack_client()
    kev_client = await get_kev_client()
    nvd_client = await get_nvd_client()

    synced = await attack_client.sync_data()
    index_refresh = await _refresh_index_snapshot(
        nvd_client=nvd_client,
        attack_client=attack_client,
        kev_client=kev_client,
    )

    return {
        "status": "success" if synced else "partial",
        "source": "ATTACK",
        "synced": synced,
        "techniques": len(attack_client.techniques),
        "tactics": len(attack_client.tactics),
        "index_refresh": index_refresh,
    }


def _run_async(coro):
    return asyncio.run(coro)


@celery_app.task(base=CallbackTask, bind=True)
def sync_kev(self):
    """Sync CISA Known Exploited Vulnerabilities and refresh the vector index."""
    try:
        return _run_async(_sync_kev_task())
    except Exception as exc:
        print(f"KEV sync failed: {exc}")
        raise


@celery_app.task(base=CallbackTask, bind=True)
def sync_nvd_delta(self):
    """Sync a configurable NVD delta set and refresh the vector index."""
    try:
        return _run_async(_sync_nvd_delta_task())
    except Exception as exc:
        print(f"NVD sync failed: {exc}")
        raise


@celery_app.task(base=CallbackTask, bind=True)
def sync_attack(self):
    """Sync MITRE ATT&CK and refresh the vector index."""
    try:
        return _run_async(_sync_attack_task())
    except Exception as exc:
        print(f"ATT&CK sync failed: {exc}")
        raise


celery_app.conf.beat_schedule = {
    "sync-kev-daily": {
        "task": "sync_jobs.sync_kev",
        "schedule": crontab(hour=23, minute=0),
    },
    "sync-nvd-weekly": {
        "task": "sync_jobs.sync_nvd_delta",
        "schedule": crontab(day_of_week=6, hour=2, minute=0),
    },
    "sync-attack-monthly": {
        "task": "sync_jobs.sync_attack",
        "schedule": crontab(day_of_month=1, hour=3, minute=0),
    },
}


if __name__ == "__main__":
    celery_app.start()
