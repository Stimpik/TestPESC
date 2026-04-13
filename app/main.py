from fastapi import FastAPI
from app.routers import users, content

app = FastAPI(title="Тестовое для ПЭСК", summary="Реализация авторизации и аутентификации")


app.include_router(users.router, prefix="/users")
app.include_router(content.router, prefix="/content")


@app.get("/")
def check():
    return {"status": "ok"}
