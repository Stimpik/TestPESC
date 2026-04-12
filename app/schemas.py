from pydantic import BaseModel, Field, ConfigDict, EmailStr


class UserCreate(BaseModel):
    email: EmailStr = Field(description="Email пользователя")
    password: str = Field(min_length=8, description="Пароль (минимум 8 символов)")
    role: str = Field(default="user", pattern="^(user|super_user)$",
                      description="Роль: 'user' или 'super_user'")  # тоже для простоты, лучше убрать и для создания супер-юзера использовать другой ендпоинт
    name: str | None = None


class User(BaseModel):
    id: int
    email: EmailStr
    name: str
    role: str
    model_config = ConfigDict(from_attributes=True)
