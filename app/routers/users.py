import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select
from fastapi.security import OAuth2PasswordRequestForm
from app.models.users import User as UserModel
from app.schemas import UserCreate, User as UserSchema
from app.db_depends import get_db
from app.core.security import hash_password, verify_password, create_access_token, create_refresh_token
from app.core.redis import redis_client
from app.core.config import settings


router = APIRouter(prefix="/users", tags=["users"])


@router.post('/', response_model=UserSchema, status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
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
def login(form_data: OAuth2PasswordRequestForm = Depends(),
          db: Session = Depends(get_db)):
    result = db.scalars(
        select(UserModel).where(
            UserModel.email == form_data.username)
    )
    user = result.first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")


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


@router.get("/", response_model=list[UserSchema])
def get_all_users(
    db: Session = Depends(get_db),
):
    users = db.query(UserModel).all()
    return users