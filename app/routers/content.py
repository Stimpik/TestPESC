from app.core.security import get_current_user
from fastapi import APIRouter, Depends, HTTPException, status

router = APIRouter(prefix="/content", tags=["content"])


@router.get('/common_content')
def common_content(user: dict = Depends(get_current_user)):
    if user['role'] in ('user', 'super_user'):
        return {'message': 'common_content'}
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Unauthorized')


@router.get('/super_content')
def super_content(user: dict = Depends(get_current_user)):
    if user['role'] == 'super_user':
        return {'message': 'super_content'}
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='super_user only!')
