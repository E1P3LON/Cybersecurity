# backend/api-gateway/middleware/security.py
"""
CyberShield AI Platform - Security Middleware
Security headers, request validation, and protection measures
"""

from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import time
import hashlib
import hmac
import logging
import re
from typing import Optional, List
import ipaddress
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware for API Gateway"""
    
    def __init__(self, app, config: Optional[dict] = None):
        super().__init__(app)
        self.config = config or {}
        
        # Security configuration
        self.max_request_size = self.config.get("max_request_size", 10 * 1024 * 1024)  # 10MB
        self.blocked_ips = set(self.config.get("blocked_ips", []))
        self.allowed_ips = set(self.config.get("allowed_ips", []))  # Empty = all allowed
        self.enable_csrf_protection = self.config.get("enable_csrf_protection", True)
        self.enable_xss_protection = self.config.get("enable_xss_protection", True)
        self.enable_sql_injection_protection = self.config.get("enable_sql_injection_protection", True)
        
        # Security patterns
        self.xss_patterns = [
            re.compile(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', re.IGNORECASE),
            re.compile(r'javascript:', re.IGNORECASE),
            re.compile(r'on\w+\s*=', re.IGNORECASE),
            re.compile(r'<iframe\b', re.IGNORECASE),
            re.compile(r'<object\b', re.IGNORECASE),
            re.compile(r'<embed\b', re.IGNORECASE),
        ]
        
        self.sql_injection_patterns = [
            re.compile(r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)', re.IGNORECASE),
            re.compile(r'(\b(OR|AND)\s+\d+\s*=\s*\d+)', re.IGNORECASE),
            re.compile(r'(\;|\-\-|\/\*|\*\/)', re.IGNORECASE),
            re.compile(r'(\b(SCRIPT|JAVASCRIPT|VBSCRIPT)\b)', re.IGNORECASE),
        ]
        
        # Rate limiting storage (in-memory for simplicity)
        self.request_counts = {}
        self.blocked_until = {}
    
    async def dispatch(self, request: Request, call_next):
        """Process security checks for each request"""
        start_time = time.time()
        
        try:
            # Check IP blocking
            client_ip = self._get_client_ip(request)
            if not self._is_ip_allowed(client_ip):
                logger.warning(f"Blocked request from IP: {client_ip}")
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"error": "Access denied", "code": "IP_BLOCKED"}
                )
            
            # Check request size
            if not await self._check_request_size(request):
                logger.warning(f"Request too large from IP: {client_ip}")
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={"error": "Request too large", "code": "REQUEST_TOO_LARGE"}
                )
            
            # Check for malicious content
            if not await self._check_malicious_content(request):
                logger.warning(f"Malicious content detected from IP: {client_ip}")
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "Malicious content detected", "code": "MALICIOUS_CONTENT"}
                )
            
            # Process request
            response = await call_next(request)
            
            # Add security headers
            response = self._add_security_headers(response)
            
            # Log request
            process_time = time.time() - start_time
            self._log_request(request, response, process_time, client_ip)
            
            return response
            
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"error": "Internal security error", "code": "SECURITY_ERROR"}
            )
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        # Check X-Forwarded-For header first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in case of multiple proxies
            return forwarded_for.split(",")[0].strip()
        
        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        
        # Fall back to direct connection IP
        return request.client.host if request.client else "unknown"
    
    def _is_ip_allowed(self, ip: str) -> bool:
        """Check if IP is allowed"""
        if ip == "unknown":
            return False
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if IP is blocked
            if ip in self.blocked_ips:
                return False