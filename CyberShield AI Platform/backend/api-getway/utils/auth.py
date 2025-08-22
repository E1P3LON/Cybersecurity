# backend/api-gateway/utils/auth.py
"""
CyberShield AI Platform - Authentication Utilities
JWT token management and user authentication
"""

import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import redis
import json
import uuid
import logging
from config.settings import Settings

logger = logging.getLogger(__name__)
settings = Settings()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security scheme
security = HTTPBearer()

# Redis client for token management
try:
    redis_client = redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD,
        decode_responses=True
    )
except Exception as e:
    logger.warning(f"Redis connection failed: {e}")
    redis_client = None

class AuthManager:
    """Authentication and authorization manager"""
    
    def __init__(self):
        self.secret_key = settings.JWT_SECRET_KEY
        self.algorithm = settings.JWT_ALGORITHM
        self.access_token_expire = settings.JWT_EXPIRE_MINUTES
        self.refresh_token_expire = settings.JWT_REFRESH_EXPIRE_DAYS
        
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Hash a password"""
        return pwd_context.hash(password)
    
    def create_access_token(self, data: Dict[Any, Any], 
                          expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access",
            "jti": str(uuid.uuid4())  # JWT ID for token tracking
        })
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        
        # Store token in Redis if available
        if redis_client:
            try:
                token_key = f"token:{to_encode['jti']}"
                redis_client.setex(
                    token_key, 
                    int(expires_delta.total_seconds()) if expires_delta else self.access_token_expire * 60,
                    json.dumps({
                        "user_id": data.get("sub"),
                        "roles": data.get("roles", []),
                        "created_at": datetime.utcnow().isoformat()
                    })
                )
            except Exception as e:
                logger.error(f"Failed to store token in Redis: {e}")
        
        return encoded_jwt
    
    def create_refresh_token(self, data: Dict[Any, Any]) -> str:
        """Create JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh",
            "jti": str(uuid.uuid4())
        })
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        
        # Store refresh token in Redis
        if redis_client:
            try:
                token_key = f"refresh_token:{to_encode['jti']}"
                redis_client.setex(
                    token_key,
                    self.refresh_token_expire * 24 * 60 * 60,  # days to seconds
                    json.dumps({
                        "user_id": data.get("sub"),
                        "created_at": datetime.utcnow().isoformat()
                    })
                )
            except Exception as e:
                logger.error(f"Failed to store refresh token in Redis: {e}")
        
        return encoded_jwt
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check token type
            if payload.get("type") not in ["access", "refresh"]:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type"
                )
            
            # Check if token is blacklisted
            jti = payload.get("jti")
            if jti and redis_client:
                try:
                    blacklisted = redis_client.get(f"blacklist:{jti}")
                    if blacklisted:
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Token has been revoked"
                        )
                except Exception as e:
                    logger.error(f"Failed to check token blacklist: {e}")
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}"
            )
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a token by adding it to blacklist"""
        try:
            payload = self.verify_token(token)
            jti = payload.get("jti")
            
            if jti and redis_client:
                # Calculate remaining TTL
                exp = payload.get("exp")
                if exp:
                    remaining_time = exp - datetime.utcnow().timestamp()
                    if remaining_time > 0:
                        redis_client.setex(
                            f"blacklist:{jti}",
                            int(remaining_time),
                            "revoked"
                        )
                        return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
            return False
    
    def refresh_access_token(self, refresh_token: str) -> str:
        """Create new access token from refresh token"""
        payload = self.verify_token(refresh_token)
        
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Create new access token
        access_token_data = {
            "sub": payload.get("sub"),
            "roles": payload.get("roles", []),
            "email": payload.get("email"),
            "permissions": payload.get("permissions", [])
        }
        
        return self.create_access_token(access_token_data)

# Initialize auth manager
auth_manager = AuthManager()

# User database (in production, this would be a proper database)
USERS_DB = {
    "admin": {
        "user_id": "admin_001",
        "username": "admin",
        "email": "admin@cybershield.local",
        "hashed_password": auth_manager.get_password_hash("admin123"),
        "roles": ["admin", "analyst", "user"],
        "permissions": ["read", "write", "delete", "admin"],
        "is_active": True,
        "created_at": datetime.utcnow().isoformat(),
        "last_login": None
    },
    "analyst": {
        "user_id": "analyst_001",
        "username": "analyst",
        "email": "analyst@cybershield.local",
        "hashed_password": auth_manager.get_password_hash("analyst123"),
        "roles": ["analyst", "user"],
        "permissions": ["read", "write"],
        "is_active": True,
        "created_at": datetime.utcnow().isoformat(),
        "last_login": None
    },
    "viewer": {
        "user_id": "viewer_001",
        "username": "viewer",
        "email": "viewer@cybershield.local",
        "hashed_password": auth_manager.get_password_hash("viewer123"),
        "roles": ["user"],
        "permissions": ["read"],
        "is_active": True,
        "created_at": datetime.utcnow().isoformat(),
        "last_login": None
    }
}

def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate user credentials"""
    user = USERS_DB.get(username)
    if not user:
        return None
    
    if not user["is_active"]:
        return None
    
    if not auth_manager.verify_password(password, user["hashed_password"]):
        return None
    
    # Update last login
    user["last_login"] = datetime.utcnow().isoformat()
    
    return user

def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Get user by ID"""
    for user in USERS_DB.values():
        if user["user_id"] == user_id:
            return user
    return None

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Dependency to verify JWT token"""
    token = credentials.credentials
    return auth_manager.verify_token(token)

async def get_current_user(token_payload: Dict[str, Any] = Depends(verify_token)) -> Dict[str, Any]:
    """Get current user from token"""
    user_id = token_payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )
    
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled"
        )
    
    return user

async def get_admin_user(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Dependency for admin-only endpoints"""
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

async def get_analyst_user(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Dependency for analyst-level endpoints"""
    user_roles = current_user.get("roles", [])
    if not any(role in user_roles for role in ["admin", "analyst"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst access required"
        )
    return current_user

def check_permission(user: Dict[str, Any], required_permission: str) -> bool:
    """Check if user has required permission"""
    user_permissions = user.get("permissions", [])
    return required_permission in user_permissions or "admin" in user.get("roles", [])

def require_permission(permission: str):
    """Decorator to require specific permission"""
    def permission_dependency(current_user: Dict[str, Any] = Depends(get_current_user)):
        if not check_permission(current_user, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required"
            )
        return current_user
    return permission_dependency

# Role-based access control
class RoleChecker:
    """Role-based access control checker"""
    
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles
    
    def __call__(self, current_user: Dict[str, Any] = Depends(get_current_user)):
        user_roles = current_user.get("roles", [])
        if not any(role in user_roles for role in self.allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {', '.join(self.allowed_roles)}"
            )
        return current_user

# Predefined role checkers
require_admin = RoleChecker(["admin"])
require_analyst = RoleChecker(["admin", "analyst"])
require_user = RoleChecker(["admin", "analyst", "user"])

# Session management
class SessionManager:
    """Manage user sessions"""
    
    def __init__(self):
        self.session_timeout = 3600  # 1 hour
    
    def create_session(self, user_id: str, token_jti: str) -> str:
        """Create a new session"""
        session_id = str(uuid.uuid4())
        
        if redis_client:
            try:
                session_data = {
                    "user_id": user_id,
                    "token_jti": token_jti,
                    "created_at": datetime.utcnow().isoformat(),
                    "last_activity": datetime.utcnow().isoformat()
                }
                
                redis_client.setex(
                    f"session:{session_id}",
                    self.session_timeout,
                    json.dumps(session_data)
                )
                
                return session_id
            except Exception as e:
                logger.error(f"Failed to create session: {e}")
        
        return session_id
    
    def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Validate and refresh session"""
        if not redis_client:
            return None
        
        try:
            session_data = redis_client.get(f"session:{session_id}")
            if not session_data:
                return None
            
            data = json.loads(session_data)
            
            # Update last activity
            data["last_activity"] = datetime.utcnow().isoformat()
            redis_client.setex(
                f"session:{session_id}",
                self.session_timeout,
                json.dumps(data)
            )
            
            return data
        except Exception as e:
            logger.error(f"Failed to validate session: {e}")
            return None
    
    def revoke_session(self, session_id: str) -> bool:
        """Revoke a session"""
        if not redis_client:
            return False
        
        try:
            return bool(redis_client.delete(f"session:{session_id}"))
        except Exception as e:
            logger.error(f"Failed to revoke session: {e}")
            return False

# Initialize session manager
session_manager = SessionManager()