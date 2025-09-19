from fastapi import APIRouter, UploadFile, HTTPException, File
from sbom_parser.cyclonedx_parser import _parse_cyclonedx_json, _parse_cyclonedx_xml
from sbom_parser.spdx_parser import parse_spdx
from utils.vulnerability_lookup import check_vulnerabilities
from app.models.schemas import SBOMAnalysis

router = APIRouter()

@router.get("/")
async def root():
    return {"message": "SBOM Analysis API"}

@router.post("/analyze", response_model=SBOMAnalysis)
async def analyze_sbom(file: UploadFile = File(...)):
    content_bytes = await file.read()
    content = content_bytes.decode('utf-8')
    ext = file.filename.lower()

    try:
        if ext.endswith(".json") and "spdx" in ext:
            analysis = parse_spdx(content)
        elif ext.endswith(".json") or ext.endswith(".xml"):
            if ext.endswith(".json"):
                analysis = _parse_cyclonedx_json(content)
            else:
                analysis = _parse_cyclonedx_xml(content)
        else:
            raise HTTPException(400, "Unsupported file format")

        # Add vulnerabilities
        for component in analysis["components"]:
            component["vulnerabilities"] = check_vulnerabilities(
                component["name"],
                component["version"],
                purl=component.get("purl")
            )

        return analysis

    except Exception as e:
        raise HTTPException(500, f"Analysis failed: {str(e)}")
