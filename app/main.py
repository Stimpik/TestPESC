from fastapi import FastAPI
from app.routers import users, content

app = FastAPI(title="Тестовое для ПЭСК", summary="Реализация авторизации и аутентификации")


app.include_router(users.router)
app.include_router(content.router)


@app.get("/")
def check():
    return {"status": "ok"}
