from fastapi import FastAPI
from app.routers import users

app = FastAPI(title="Тестовое для ПЭСК", summary="Реализация авторизации и аутентификации")
app.include_router(users.router)


@app.get("/")
async def check():
    return {"status": "ok"}
