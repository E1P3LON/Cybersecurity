# backend/api-gateway/src/main.py
"""
CyberShield AI Platform - API Gateway
Main application entry point with FastAPI
"""

from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
import uvicorn
import time
import logging
from typing import Optional
import httpx
import asyncio
from datetime import datetime, timedelta
import jwt
import redis
import os
from pathlib import Path

# Local imports
from config.settings import Settings
from middleware.rate_limiter import RateLimiterMiddleware
from middleware.security import SecurityMiddleware
from middleware.logging import LoggingMiddleware
from routes.auth import auth_router
from routes.soc import soc_router
from routes.threats import threats_router
from routes.vulnerabilities import vulnerabilities_router
from routes.admin import admin_router
from utils.auth import verify_token, get_current_user
from utils.metrics import MetricsCollector
from utils.health_check import HealthChecker

# Initialize settings
settings = Settings()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="CyberShield AI Platform - API Gateway",
    description="Unified API Gateway for CyberShield AI cybersecurity platform",
    version="1.0.0",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    openapi_url="/api/v1/openapi.json"
)

# Security
security = HTTPBearer()

# Initialize Redis for caching and rate limiting
redis_client = redis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    password=settings.REDIS_PASSWORD,
    decode_responses=True
)

# Initialize metrics collector
metrics = MetricsCollector()

# Initialize health checker
health_checker = HealthChecker()

# Middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS
)

app.add_middleware(RateLimiterMiddleware, redis_client=redis_client)
app.add_middleware(SecurityMiddleware)
app.add_middleware(LoggingMiddleware)

# Service endpoints mapping
SERVICES = {
    "soc-intelligence": f"http://{settings.SOC_SERVICE_HOST}:{settings.SOC_SERVICE_PORT}",
    "threat-detection": f"http://{settings.THREAT_SERVICE_HOST}:{settings.THREAT_SERVICE_PORT}",
    "vulnerability-management": f"http://{settings.VULN_SERVICE_HOST}:{settings.VULN_SERVICE_PORT}",
    "anti-phishing": f"http://{settings.PHISHING_SERVICE_HOST}:{settings.PHISHING_SERVICE_PORT}",
    "honeypot-network": f"http://{settings.HONEYPOT_SERVICE_HOST}:{settings.HONEYPOT_SERVICE_PORT}",
    "incident-response": f"http://{settings.INCIDENT_SERVICE_HOST}:{settings.INCIDENT_SERVICE_PORT}",
    "threat-intelligence": f"http://{settings.INTEL_SERVICE_HOST}:{settings.INTEL_SERVICE_PORT}",
}

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info("🚀 Starting CyberShield AI Platform API Gateway...")
    
    # Test Redis connection
    try:
        await asyncio.to_thread(redis_client.ping)
        logger.info("✅ Redis connection established")
    except Exception as e:
        logger.error(f"❌ Redis connection failed: {e}")
        
    # Test service connections
    for service_name, service_url in SERVICES.items():
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{service_url}/health", timeout=5.0)
                if response.status_code == 200:
                    logger.info(f"✅ {service_name} service is healthy")
                else:
                    logger.warning(f"⚠️ {service_name} service returned {response.status_code}")
        except Exception as e:
            logger.warning(f"⚠️ {service_name} service not available: {e}")
    
    logger.info("🛡️ CyberShield API Gateway is ready!")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("🔄 Shutting down CyberShield API Gateway...")
    redis_client.close()
    logger.info("✅ Shutdown complete")

# Health check endpoints
@app.get("/health", tags=["Health"])
async def health_check():
    """Basic health check"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.get("/api/v1/health", tags=["Health"])
async def detailed_health_check():
    """Detailed health check with service status"""
    health_status = await health_checker.check_all_services(SERVICES)
    
    return {
        "status": "healthy" if health_status["all_healthy"] else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "services": health_status["services"],
        "redis": health_status["redis"],
        "uptime": health_status["uptime"]
    }

# Metrics endpoint
@app.get("/api/v1/metrics", tags=["Monitoring"])
async def get_metrics(current_user: dict = Depends(get_current_user)):
    """Get system metrics (requires authentication)"""
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    return await metrics.get_all_metrics()

# Proxy function for microservices
async def proxy_request(
    service_name: str,
    path: str,
    request: Request,
    current_user: Optional[dict] = None
):
    """Proxy requests to microservices"""
    
    if service_name not in SERVICES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service {service_name} not found"
        )
    
    service_url = SERVICES[service_name]
    target_url = f"{service_url}/{path}"
    
    # Get request body
    body = await request.body() if request.method in ["POST", "PUT", "PATCH"] else None
    
    # Prepare headers
    headers = dict(request.headers)
    if current_user:
        headers["X-User-ID"] = str(current_user["user_id"])
        headers["X-User-Roles"] = ",".join(current_user.get("roles", []))
    
    # Remove hop-by-hop headers
    hop_by_hop = [
        "connection", "keep-alive", "proxy-authenticate",
        "proxy-authorization", "te", "trailers", "upgrade"
    ]
    for header in hop_by_hop:
        headers.pop(header, None)
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                params=dict(request.query_params)
            )
            
            # Record metrics
            await metrics.record_request(
                service_name, request.method, response.status_code
            )
            
            return JSONResponse(
                content=response.json() if response.content else {},
                status_code=response.status_code,
                headers=dict(response.headers)
            )
            
    except httpx.TimeoutException:
        logger.error(f"Timeout calling {service_name} service")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"Service {service_name} timeout"
        )
    except Exception as e:
        logger.error(f"Error calling {service_name} service: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Service {service_name} error"
        )

# Include routers
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(admin_router, prefix="/api/v1/admin", tags=["Administration"])

# SOC Intelligence routes
@app.api_route("/api/v1/soc/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def soc_proxy(
    path: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Proxy to SOC Intelligence service"""
    return await proxy_request("soc-intelligence", path, request, current_user)

# Threat Detection routes
@app.api_route("/api/v1/threats/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def threats_proxy(
    path: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Proxy to Threat Detection service"""
    return await proxy_request("threat-detection", path, request, current_user)

# Vulnerability Management routes
@app.api_route("/api/v1/vulnerabilities/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def vulnerabilities_proxy(
    path: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Proxy to Vulnerability Management service"""
    return await proxy_request("vulnerability-management", path, request, current_user)

# Anti-Phishing routes
@app.api_route("/api/v1/phishing/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def phishing_proxy(
    path: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Proxy to Anti-Phishing service"""
    return await proxy_request("anti-phishing", path, request, current_user)

# Honeypot Network routes
@app.api_route("/api/v1/honeypots/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def honeypots_proxy(
    path: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Proxy to Honeypot Network service"""
    return await proxy_request("honeypot-network", path, request, current_user)

# Incident Response routes
@app.api_route("/api/v1/incidents/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def incidents_proxy(
    path: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Proxy to Incident Response service"""
    return await proxy_request("incident-response", path, request, current_user)

# Threat Intelligence routes
@app.api_route("/api/v1/intelligence/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def intelligence_proxy(
    path: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Proxy to Threat Intelligence service"""
    return await proxy_request("threat-intelligence", path, request, current_user)

# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """Welcome message"""
    return {
        "message": "🛡️ Welcome to CyberShield AI Platform API Gateway",
        "version": "1.0.0",
        "documentation": "/api/v1/docs",
        "health": "/api/v1/health",
        "services": list(SERVICES.keys())
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    logger.warning(f"HTTP {exc.status_code}: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "message": "Internal server error",
            "status_code": 500,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# Run the application
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info" if not settings.DEBUG else "debug"
    )