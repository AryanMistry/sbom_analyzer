from fastapi import FastAPI
from app.routes import sbom

app = FastAPI(
    title="SBOM Analysis API",
    description="API for Software Bill of Materials analysis",
    version="0.1.0"
)

app.include_router(sbom.router, prefix="/api/v1/sbom", tags=["SBOM"])

@app.get("/health")
def health_check():
    return {"status": "ok"}