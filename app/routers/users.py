from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models.users import User as UserModel
from app.schemas import UserCreate, User as UserSchema
from app.db_depends import get_db
from app.auth.core.security import hash_password

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
