from fastapi import FastAPI

app = FastAPI(
    title="Тестовое для ПЭСК",
    summary="Реализация авторизации и аутентификации"
)


@app.get("/api/v1/health")
async def health_check():
    return {"status": "ok"}