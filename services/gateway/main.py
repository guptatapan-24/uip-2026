"""
FastAPI application entry point.

Orchestrates all microservices (claim extraction, RAG retrieval, validation,
decision engine) into a unified validation pipeline. Handles CORS,
and metrics collection.
"""

import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Histogram, generate_latest

from config import get_config, setup_logging

# Import route modules
from routes import extract, validate, decide, health

# Configure logging and get config
config = get_config()
logger = logging.getLogger(__name__)

# Prometheus metrics
validation_counter = Counter(
    "validation_requests_total", "Total validation requests", ["endpoint"]
)
validation_latency = Histogram(
    "validation_latency_ms", "Validation pipeline latency in milliseconds"
)
http_requests = Counter(
    "http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"]
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown lifecycle.

    Startup: Initialize connections and verify configuration
    Shutdown: Gracefully close connections
    """
    # Startup
    logger.info("Starting LLM Hallucination Firewall gateway...")
    try:
        # Verify core services are importable
        from services.claim_extractor.extractor import extract_claims
        from services.validation_engine.deterministic import cve_exists_in_nvd
        from services.decision_engine.engine import decide
        from services.common.config import load_profile

        logger.info("Core services verified")

        # Load default policy profile
        default_profile = load_profile("default")
        logger.info(f"Default policy profile loaded with {len(default_profile.get('weights', {}))} signal weights")

        logger.info("Gateway initialization complete")
    except Exception as e:
        logger.error(f"Startup failed: {e}", exc_info=True)
        raise

    yield

    # Shutdown
    logger.info("Shutting down gateway...")
    try:
        logger.info("Gateway shutdown complete")
    except Exception as e:
        logger.error(f"Shutdown error: {e}")


# Initialize FastAPI app
app = FastAPI(
    title="LLM Hallucination Firewall",
    description="Enterprise-grade LLM validation middleware for SOC environments",
    version="1.0.0",
    lifespan=lifespan,
)

# Configure CORS
cors_origins = config.get_cors_origins()
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Middleware for request logging and metrics
@app.middleware("http")
async def log_and_metrics_middleware(request: Request, call_next):
    """Log all requests and track Prometheus metrics."""
    start_time = time.time()
    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000

    http_requests.labels(
        method=request.method, endpoint=request.url.path, status=response.status_code
    ).inc()

    logger.info(
        f"{request.method} {request.url.path} - {response.status_code} - {process_time:.2f}ms"
    )

    return response


# Include routers
app.include_router(health.router, tags=["Health"])
app.include_router(extract.router, prefix="/api/v1", tags=["Extraction"])
app.include_router(validate.router, prefix="/api/v1", tags=["Validation"])
app.include_router(decide.router, prefix="/api/v1", tags=["Decision"])


# Metrics endpoint
@app.get("/metrics", include_in_schema=False)
async def metrics():
    """Prometheus metrics endpoint."""
    return JSONResponse(content={"metrics": "Use Prometheus scraper"})


# Root endpoint
@app.get("/", tags=["System"])
async def root():
    """API root endpoint with service information."""
    return {
        "service": "llm-hallucination-firewall",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "health": "/health",
            "extract": "/api/v1/extract",
            "validate": "/api/v1/validate",
            "decide": "/api/v1/decide",
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=config.HOST,
        port=config.PORT,
        reload=config.DEBUG,
        log_level=config.LOG_LEVEL.lower(),
    )

