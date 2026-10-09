from pydantic import BaseModel, Field, field_validator
from fastapi import APIRouter

from app.schemas.analysis import SolidityAnalysisResponse
from app.services.solidity_analyzer import analyze_solidity

MAX_SOURCE_LENGTH = 200_000


class SolidityAnalysisRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    source: str = Field(min_length=1, max_length=MAX_SOURCE_LENGTH)

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, filename: str) -> str:
        if "/" in filename or "\\" in filename:
            raise ValueError("filename must not include a directory path")
        if not filename.lower().endswith(".sol"):
            raise ValueError("only Solidity (.sol) files are supported")
        return filename

    @field_validator("source")
    @classmethod
    def validate_source(cls, source: str) -> str:
        if not source.strip():
            raise ValueError("source code must not be empty")
        return source


router = APIRouter()


@router.post("/solidity", response_model=SolidityAnalysisResponse)
async def analyze_solidity_source(request: SolidityAnalysisRequest) -> SolidityAnalysisResponse:
    return analyze_solidity(request.source, request.filename)
