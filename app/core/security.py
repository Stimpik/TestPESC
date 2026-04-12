import bcrypt
import jwt
import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.models.users import User as UserModel
from sqlalchemy import select

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from .config import settings
from .redis import redis_client
from app.db_depends import get_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/token")


def hash_password(password: str) -> str:
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(plain: str, hashed: str) -> bool:
    plain_bytes = plain.encode('utf-8')
    hashed_bytes = hashed.encode('utf-8')
    return bcrypt.checkpw(plain_bytes, hashed_bytes)


def generate_jti() -> str:
    return str(uuid.uuid4())


def create_access_token(user_id: int, role: str) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "role": role,
        "jti": generate_jti(),
        "type": "access",
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(user_id: int, role: str) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": str(user_id),
        "role": role,
        "jti": generate_jti(),
        "type": "refresh",
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Invalid token")
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "access":
            raise credentials_exception
        user_id = payload.get("sub")
        role = payload.get("role")
        jti = payload.get("jti")
        if not user_id or not role or not jti:
            raise credentials_exception

        user = db.scalar(select(UserModel).where(UserModel.id == int(user_id)))
        if not user or user.role != role:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail='The user has been deleted or the role has changed')

        if redis_client.exists(f"blacklist:{jti}"):
            raise HTTPException(status_code=401, detail="Token revoked")

        return {"user_id": int(user_id), "role": role, "jti": jti}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise credentials_exception
