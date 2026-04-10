from fastapi import FastAPI

from app.database import Base, engine
from app.auth import router as auth_router
from app.accounts import router as accounts_router
from app.admin import router as admin_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Guardrail CI — Mock Banking API",
    description="A deliberately vulnerable banking API for DevSecOps pipeline demonstration",
    version="1.0.0",
)

app.include_router(auth_router)
app.include_router(accounts_router)
app.include_router(admin_router)


@app.get("/health")
def health_check():
    return {"status": "healthy"}
