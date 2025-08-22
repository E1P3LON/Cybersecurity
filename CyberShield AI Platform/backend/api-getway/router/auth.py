# backend/api-gateway/routes/auth.py
"""
CyberShield AI Platform - Authentication Routes
Login, logout, token refresh, and user management endpoints
"""

from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, validator
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import logging
import json
from utils.auth import (
    auth_manager, authenticate_user, get_current_user, 
    get_admin_user, session_manager, USERS_DB,
    require_permission
)
from config.settings import Settings

logger = logging.getLogger(__name__)
settings = Settings()

# Create router
auth_router = APIRouter()

# Pydantic models for request/response
class LoginRequest(BaseModel):
    username: str
    password: str
    remember_me: bool = False
    
    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters long')
        return v.strip().lower()
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        return v

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_info: Dict[str, Any]
    session_id: str

class TokenRefreshRequest(BaseModel):
    refresh_token: str

class TokenRefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class UserCreateRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    roles: List[str] = ["user"]
    permissions: List[str] = ["read"]
    
    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters long')
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username can only contain letters, numbers, hyphens, and underscores')
        return v.strip().lower()
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v
    
    @validator('roles')
    def validate_roles(cls, v):
        valid_roles = ["admin", "analyst", "user"]
        for role in v:
            if role not in valid_roles:
                raise ValueError(f'Invalid role: {role}. Valid roles: {valid_roles}')
        return v
    
    @validator('permissions')
    def validate_permissions(cls, v):
        valid_permissions = ["read", "write", "delete", "admin"]
        for perm in v:
            if perm not in valid_permissions:
                raise ValueError(f'Invalid permission: {perm}. Valid permissions: {valid_permissions}')
        return v

class UserUpdateRequest(BaseModel):
    email: Optional[EmailStr] = None
    roles: Optional[List[str]] = None
    permissions: Optional[List[str]] = None
    is_active: Optional[bool] = None

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

class UserResponse(BaseModel):
    user_id: str
    username: str
    email: str
    roles: List[str]
    permissions: List[str]
    is_active: bool
    created_at: str
    last_login: Optional[str]

# Authentication endpoints
@auth_router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, http_request: Request):
    """User login endpoint"""
    try:
        # Authenticate user
        user = authenticate_user(request.username, request.password)
        if not user:
            # Log failed login attempt
            logger.warning(
                f"Failed login attempt for username: {request.username} "
                f"from IP: {http_request.client.host if http_request.client else 'unknown'}"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Create tokens
        token_data = {
            "sub": user["user_id"],
            "email": user["email"],
            "roles": user["roles"],
            "permissions": user["permissions"]
        }
        
        # Set token expiration based on remember_me
        access_expire = timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES * (7 if request.remember_me else 1)
        )
        
        access_token = auth_manager.create_access_token(token_data, access_expire)
        refresh_token = auth_manager.create_refresh_token(token_data)
        
        # Create session
        token_payload = auth_manager.verify_token(access_token)
        session_id = session_manager.create_session(user["user_id"], token_payload.get("jti"))
        
        # Update last login
        user["last_login"] = datetime.utcnow().isoformat()
        
        # Log successful login
        logger.info(
            f"Successful login for user: {user['username']} "
            f"from IP: {http_request.client.host if http_request.client else 'unknown'}"
        )
        
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=int(access_expire.total_seconds()),
            user_info={
                "user_id": user["user_id"],
                "username": user["username"],
                "email": user["email"],
                "roles": user["roles"],
                "permissions": user["permissions"]
            },
            session_id=session_id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@auth_router.post("/refresh", response_model=TokenRefreshResponse)
async def refresh_token(request: TokenRefreshRequest):
    """Refresh access token"""
    try:
        new_access_token = auth_manager.refresh_access_token(request.refresh_token)
        
        return TokenRefreshResponse(
            access_token=new_access_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )

@auth_router.post("/logout")
async def logout(
    current_user: Dict[str, Any] = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(auth_manager.verify_token)
):
    """User logout endpoint"""
    try:
        # Revoke access token
        token_revoked = auth_manager.revoke_token(credentials.credentials)
        
        # Log logout
        logger.info(f"User {current_user['username']} logged out")
        
        return {
            "message": "Successfully logged out",
            "token_revoked": token_revoked
        }
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return {"message": "Logout completed with errors"}

@auth_router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user information"""
    return UserResponse(**current_user)

@auth_router.post("/change-password")
async def change_password(
    request: PasswordChangeRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Change user password"""
    try:
        # Verify current password
        if not auth_manager.verify_password(request.current_password, current_user["hashed_password"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Update password
        new_password_hash = auth_manager.get_password_hash(request.new_password)
        current_user["hashed_password"] = new_password_hash
        
        # Log password change
        logger.info(f"Password changed for user: {current_user['username']}")
        
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )

# User management endpoints (Admin only)
@auth_router.get("/users", response_model=List[UserResponse])
async def list_users(current_user: Dict[str, Any] = Depends(get_admin_user)):
    """List all users (Admin only)"""
    users = []
    for user_data in USERS_DB.values():
        user_response = UserResponse(**user_data)
        users.append(user_response)
    return users

@auth_router.post("/users", response_model=UserResponse)
async def create_user(
    request: UserCreateRequest,
    current_user: Dict[str, Any] = Depends(get_admin_user)
):
    """Create new user (Admin only)"""
    try:
        # Check if username already exists
        if request.username in USERS_DB:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists"
            )
        
        # Check if email already exists
        for user in USERS_DB.values():
            if user["email"] == request.email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already exists"
                )
        
        # Create new user
        user_id = f"{request.username}_{len(USERS_DB) + 1:03d}"
        new_user = {
            "user_id": user_id,
            "username": request.username,
            "email": request.email,
            "hashed_password": auth_manager.get_password_hash(request.password),
            "roles": request.roles,
            "permissions": request.permissions,
            "is_active": True,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": None
        }
        
        # Add to users database
        USERS_DB[request.username] = new_user
        
        # Log user creation
        logger.info(f"User created: {request.username} by {current_user['username']}")
        
        return UserResponse(**new_user)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User creation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User creation failed"
        )

@auth_router.get("/users/{username}", response_model=UserResponse)
async def get_user(
    username: str,
    current_user: Dict[str, Any] = Depends(get_admin_user)
):
    """Get user by username (Admin only)"""
    user = USERS_DB.get(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(**user)

@auth_router.put("/users/{username}", response_model=UserResponse)
async def update_user(
    username: str,
    request: UserUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_admin_user)
):
    """Update user (Admin only)"""
    try:
        user = USERS_DB.get(username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Update user fields
        if request.email is not None:
            # Check if email already exists (for other users)
            for other_username, other_user in USERS_DB.items():
                if other_username != username and other_user["email"] == request.email:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Email already exists"
                    )
            user["email"] = request.email
        
        if request.roles is not None:
            user["roles"] = request.roles
        
        if request.permissions is not None:
            user["permissions"] = request.permissions
        
        if request.is_active is not None:
            user["is_active"] = request.is_active
        
        # Log user update
        logger.info(f"User updated: {username} by {current_user['username']}")
        
        return UserResponse(**user)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User update error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User update failed"
        )

@auth_router.delete("/users/{username}")
async def delete_user(
    username: str,
    current_user: Dict[str, Any] = Depends(get_admin_user)
):
    """Delete user (Admin only)"""
    try:
        if username not in USERS_DB:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Prevent self-deletion
        if username == current_user["username"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete your own account"
            )
        
        # Delete user
        deleted_user = USERS_DB.pop(username)
        
        # Log user deletion
        logger.info(f"User deleted: {username} by {current_user['username']}")
        
        return {"message": f"User {username} deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User deletion error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User deletion failed"
        )

# Session management endpoints
@auth_router.get("/sessions")
async def list_user_sessions(current_user: Dict[str, Any] = Depends(get_current_user)):
    """List current user's active sessions"""
    # This would query Redis for active sessions
    # For now, return a placeholder
    return {
        "message": "Session management not fully implemented",
        "user_id": current_user["user_id"]
    }

@auth_router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Revoke a specific session"""
    try:
        success = session_manager.revoke_session(session_id)
        
        if success:
            logger.info(f"Session {session_id} revoked by {current_user['username']}")
            return {"message": "Session revoked successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Session revocation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Session revocation failed"
        )

# Health check and validation endpoints
@auth_router.get("/validate")
async def validate_token(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Validate current token and return user info"""
    return {
        "valid": True,
        "user": {
            "user_id": current_user["user_id"],
            "username": current_user["username"],
            "roles": current_user["roles"],
            "permissions": current_user["permissions"]
        }
    }

@auth_router.get("/permissions")
async def get_user_permissions(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user's permissions"""
    return {
        "user_id": current_user["user_id"],
        "username": current_user["username"],
        "roles": current_user["roles"],
        "permissions": current_user["permissions"],
        "has_admin": "admin" in current_user.get("roles", []),
        "has_analyst": any(role in current_user.get("roles", []) for role in ["admin", "analyst"])
    }

@auth_router.get("/roles")
async def get_available_roles(current_user: Dict[str, Any] = Depends(get_admin_user)):
    """Get all available roles and permissions (Admin only)"""
    return {
        "roles": {
            "admin": {
                "description": "Full system administration access",
                "permissions": ["read", "write", "delete", "admin"]
            },
            "analyst": {
                "description": "Security analyst access",
                "permissions": ["read", "write"]
            },
            "user": {
                "description": "Basic user access",
                "permissions": ["read"]
            }
        },
        "permissions": {
            "read": "View data and dashboards",
            "write": "Create and modify data",
            "delete": "Delete data and configurations",
            "admin": "System administration functions"
        }
    }