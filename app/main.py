from fastapi import FastAPI

from app.database import Base, engine
from app.auth import router as auth_router
from app.accounts import router as accounts_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Skyline Banking API",
    description="Mock banking API for Operation Aegis DevSecOps demonstration",
    version="1.0.0",
)

app.include_router(auth_router)
app.include_router(accounts_router)


@app.get("/health")
def health_check():
    return {"status": "healthy"}
