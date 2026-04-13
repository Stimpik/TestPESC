from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.redis import redis_client
from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    oauth2_scheme,
    verify_password,
)
from app.db_depends import get_db
from app.models.users import User as UserModel
from app.schemas import RefreshTokenRequest, User as UserSchema, UserCreate

router = APIRouter(prefix="/users", tags=["users"])


@router.post('/', response_model=UserSchema, status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    """Создание пользователя"""

    result = db.scalars(select(UserModel).where(UserModel.email == user.email))
    if result.first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Email already registered')

    db_user = UserModel(email=user.email,
                        password=hash_password(user.password),
                        role=user.role,
                        name=user.name,
                        )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@router.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Аутентификация и выдача токенов"""
    result = db.scalars(
        select(UserModel).where(
            UserModel.email == form_data.username)
    )
    user = result.first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    access_token = create_access_token(user.id, user.role)
    refresh_token = create_refresh_token(user.id, user.role)

    refresh_payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    ttl = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
    redis_client.setex(f"refresh:{refresh_payload['jti']}", ttl, str(user.id))

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/logout", status_code=status.HTTP_200_OK)
def logout(token: str = Depends(oauth2_scheme)):
    """Завершение сессии и добавление refresh-токена в blacklist"""

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        if payload.get("type") != "access":
            raise HTTPException(status_code=400, detail="Invalid token type")

        jti = payload.get("jti")
        exp = payload.get("exp")

        if not jti or not exp:
            raise HTTPException(status_code=401, detail="Invalid token")

        ttl = max(0, int(exp) - int(datetime.now(timezone.utc).timestamp()))

        if ttl > 0:
            redis_client.setex(f"blacklist:{jti}", ttl, "1")

        return {"msg": "Logged out"}

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")

    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@router.post('/refresh-token')
def refresh_token(body: RefreshTokenRequest, db: Session = Depends(get_db)):
    """Обновление пары токенов с ротацией refresh-токена"""

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    old_refresh_token = body.refresh_token

    try:
        payload = jwt.decode(old_refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
        token_type = payload.get("type")
        jti = payload.get("jti")

        if not user_id or token_type != "refresh" or not jti:
            raise credentials_exception

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

    except jwt.PyJWTError:
        raise credentials_exception

    if not redis_client.exists(f"refresh:{jti}"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked")

    user = db.get(UserModel, int(user_id))
    if user is None:
        raise credentials_exception

    new_access_token = create_access_token(user.id, user.role)
    new_refresh_token = create_refresh_token(user.id, user.role)

    redis_client.delete(f"refresh:{jti}")

    new_payload = jwt.decode(new_refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    new_jti = new_payload["jti"]
    new_exp = new_payload["exp"]
    ttl = max(0, new_exp - int(datetime.now(timezone.utc).timestamp()))
    redis_client.setex(f"refresh:{new_jti}", ttl, str(user.id))

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }

