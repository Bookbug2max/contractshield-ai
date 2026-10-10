from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import analysis, health
from app.core.config import settings

app = FastAPI(
    title="ContractShield API",
    description=(
        "Limited rule-based Solidity source screening with remediation recommendations. "
        "This is not a compiler-backed or complete security audit."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix=settings.api_v1_prefix, tags=["health"])
app.include_router(analysis.router, prefix=f"{settings.api_v1_prefix}/analysis", tags=["analysis"])
