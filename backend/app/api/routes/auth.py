from fastapi import APIRouter, HTTPException, status, Depends
from datetime import datetime
from bson import ObjectId
from app.schemas.user import UserRegister, UserLogin, Token, UserOut
from app.core.security import hash_password, verify_password, create_access_token
from app.core.dependencies import get_current_user
from app.db.database import get_db

router = APIRouter()

@router.post("/register", response_model=Token)
async def register(user: UserRegister):
    db = get_db()

    # Check if email exists
    existing = await db.users.find_one({"email": user.email})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Create user
    new_user = {
        "full_name": user.full_name,
        "email": user.email,
        "password": hash_password(user.password),
        "created_at": datetime.utcnow()
    }

    result = await db.users.insert_one(new_user)
    user_id = str(result.inserted_id)

    token = create_access_token({"sub": user_id, "email": user.email})

    return Token(
        access_token=token,
        user=UserOut(
            id=user_id,
            full_name=user.full_name,
            email=user.email,
            created_at=new_user["created_at"]
        )
    )

@router.post("/login", response_model=Token)
async def login(credentials: UserLogin):
    db = get_db()

    user = await db.users.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    user_id = str(user["_id"])
    token = create_access_token({"sub": user_id, "email": user["email"]})

    return Token(
        access_token=token,
        user=UserOut(
            id=user_id,
            full_name=user["full_name"],
            email=user["email"],
            created_at=user["created_at"]
        )
    )

@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    db = get_db()
    user = await db.users.find_one({"_id": ObjectId(current_user["sub"])})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": str(user["_id"]),
        "full_name": user["full_name"],
        "email": user["email"],
        "created_at": user["created_at"]
    }
