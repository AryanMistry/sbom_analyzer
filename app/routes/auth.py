from datetime import datetime, timedelta
from typing import List
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from app.models.schemas import (
    UserCreate, 
    UserResponse, 
    Token, 
    APIKeyCreate, 
    APIKeyResponse
)
from app.core.database import get_db, User, APIKey, generate_uuid
from app.core.security import (
    hash_password, 
    verify_password, 
    create_access_token,
    generate_api_key,
    hash_api_key,
    require_auth
)
from app.core.config import settings

router = APIRouter()


@router.post("/register", response_model=UserResponse)
async def register(
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    # Check if email already exists
    existing = db.query(User).filter(User.email == user_data.email).first()
    if existing:
        raise HTTPException(400, "Email already registered")
    
    # Create user
    user = User(
        id=generate_uuid(),
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        full_name=user_data.full_name,
        is_active=True,
        created_at=datetime.utcnow()
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        created_at=user.created_at
    )


@router.post("/login", response_model=Token)
async def login(
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    # Find user
    user = db.query(User).filter(User.email == user_data.email).first()
    
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(401, "Invalid email or password")
    
    if not user.is_active:
        raise HTTPException(403, "Account is disabled")
    
    # Create token
    access_token = create_access_token(user.id)
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.JWT_EXPIRATION_HOURS * 3600
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: dict = Depends(require_auth),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    
    if not user:
        raise HTTPException(404, "User not found")
    
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        created_at=user.created_at
    )


@router.post("/api-keys", response_model=APIKeyResponse)
async def create_api_key_endpoint(
    key_data: APIKeyCreate,
    current_user: dict = Depends(require_auth),
    db: Session = Depends(get_db)
):
    # Generate key
    full_key, hashed_key = generate_api_key()
    key_prefix = full_key[:8]
    
    # Calculate expiration
    expires_at = datetime.utcnow() + timedelta(days=key_data.expires_days)
    
    # Create record
    api_key = APIKey(
        id=generate_uuid(),
        user_id=current_user["user_id"],
        name=key_data.name,
        key_hash=hashed_key,
        key_prefix=key_prefix,
        created_at=datetime.utcnow(),
        expires_at=expires_at,
        is_active=True
    )
    
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    
    # Return the full key ONLY THIS ONE TIME
    return {
        "id": api_key.id,
        "name": api_key.name,
        "key_prefix": key_prefix,
        "full_key": full_key, 
        "created_at": api_key.created_at,
        "expires_at": api_key.expires_at,
        "last_used": None
    }


@router.get("/api-keys", response_model=List[APIKeyResponse])
async def list_api_keys(
    current_user: dict = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """List all API keys for current user"""
    keys = db.query(APIKey).filter(
        APIKey.user_id == current_user["user_id"],
        APIKey.is_active == True
    ).all()
    
    return [
        APIKeyResponse(
            id=k.id,
            name=k.name,
            key_prefix=k.key_prefix,
            created_at=k.created_at,
            expires_at=k.expires_at,
            last_used=k.last_used
        )
        for k in keys
    ]


@router.delete("/api-keys/{key_id}")
async def delete_api_key(
    key_id: str,
    current_user: dict = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Delete an API key"""
    api_key = db.query(APIKey).filter(
        APIKey.id == key_id,
        APIKey.user_id == current_user["user_id"]
    ).first()
    
    if not api_key:
        raise HTTPException(404, "API key not found")
    
    api_key.is_active = False
    db.commit()
    
    return {"message": "API key deleted successfully"}

