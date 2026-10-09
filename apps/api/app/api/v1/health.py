from fastapi import APIRouter
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    service: str
    environment: str


router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    from app.core.config import settings
    return HealthResponse(
        status="ok",
        service="contractshield-api",
        environment=settings.app_env,
    )