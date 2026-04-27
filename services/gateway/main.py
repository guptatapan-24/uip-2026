# services/gateway/main.py
"""
FastAPI application entry point.

Orchestrates all microservices (claim extraction, RAG retrieval, validation,
decision engine) into a unified validation pipeline. Handles JWT auth, CORS,
and metrics collection.

TODO: Integrate Tanushree's claim_extractor module via async calls
TODO: Integrate Tapan's decision_engine module for final outcome determination
TODO: Integrate Dhruv's rag_pipeline and audit modules
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Histogram, generate_latest

# Import route modules
from routes import audit, decisions, metrics, policy, validate

# Configure logging
logging.basicConfig(level=os.getenv("API_LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

# Prometheus metrics
validation_counter = Counter(
    "validation_requests_total", "Total validation requests", ["outcome"]
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

    Startup: Initialize connections (Redis, DB, FAISS index)
    Shutdown: Gracefully close connections
    """
    # Startup
    logger.info("Starting LLM Hallucination Firewall gateway...")
    try:
        # TODO: Initialize Redis connection pool
        # TODO: Load FAISS indexes into memory
        # TODO: Verify PostgreSQL connectivity
        logger.info("Gateway initialization complete")
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        raise

    yield

    # Shutdown
    logger.info("Shutting down gateway...")
    try:
        # TODO: Close Redis connections
        # TODO: Flush metrics
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
cors_origins = os.getenv("CORS_ORIGINS", '["http://localhost:3000"]')
try:
    # Parse JSON array from env
    import json

    origins = json.loads(cors_origins)
except (json.JSONDecodeError, TypeError):
    origins = ["http://localhost:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Middleware for request logging and metrics
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Record HTTP request metrics."""
    response = await call_next(request)

    http_requests.labels(
        method=request.method, endpoint=request.url.path, status=response.status_code
    ).inc()

    return response


# Error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle uncaught exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# Health check endpoint
@app.get("/health", tags=["System"])
async def health_check():
    """
    System health check endpoint.

    Returns:
        {"status": "healthy", "service": "gateway"}
    """
    return {"status": "healthy", "service": "gateway", "version": "1.0.0"}


# Ready check endpoint (K8s readiness probe)
@app.get("/ready", tags=["System"])
async def ready_check():
    """
    Readiness check endpoint (dependencies must be healthy).

    Returns:
        {"status": "ready"} if all dependencies accessible

    Raises:
        500 if any dependency unavailable
    """
    # TODO: Check Redis connectivity
    # TODO: Check PostgreSQL connectivity
    # TODO: Check FAISS index loaded
    return {"status": "ready"}


# Metrics endpoint (Prometheus)
@app.get("/metrics", tags=["Monitoring"])
async def metrics():
    """
    Prometheus metrics endpoint.

    Returns:
        Prometheus-format metrics
    """
    return generate_latest()


# Include route modules
app.include_router(validate.router, prefix="/v1", tags=["Validation"])
app.include_router(decisions.router, prefix="/v1", tags=["Decisions"])
app.include_router(audit.router, prefix="/v1", tags=["Audit"])
app.include_router(metrics.router, prefix="/v1", tags=["Metrics"])
app.include_router(policy.router, prefix="/v1", tags=["Policy"])


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
            "ready": "/ready",
            "metrics": "/metrics",
            "validate": "/v1/validate",
            "decisions": "/v1/decisions",
            "audit": "/v1/audit/log",
            "policy": "/v1/policy",
        },
    }


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("API_HOST", "0.0.0.0")
    port = int(os.getenv("API_PORT", "8000"))

    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=os.getenv("API_ENV", "production") == "development",
    )
