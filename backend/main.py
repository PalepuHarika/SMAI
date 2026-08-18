import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.db.database import init_db
from backend.api.auth import router as auth_router
from backend.api.analysis import router as analysis_router
from backend.api.admin import router as admin_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    await init_db()
    yield

app = FastAPI(
    title="Smart Contract Vulnerability Scanner API",
    description="AI-Assisted Static Analysis and RAG-driven Solidity Security Scanner",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(analysis_router)
app.include_router(admin_router)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}
