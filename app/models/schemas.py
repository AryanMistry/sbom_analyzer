from pydantic import BaseModel, HttpUrl
from typing import List, Optional

class VulnerabilityReference(BaseModel):
    type: Optional[str] = None
    url: HttpUrl

class Vulnerability(BaseModel):
    id: str
    summary: Optional[str] = None
    details: Optional[str] = None
    severity: Optional[str] = None
    references: List[VulnerabilityReference] = []

class Component(BaseModel):
    name: str
    version: str
    license: Optional[str] = None
    vulnerabilities: List[Vulnerability] = []
    purl: Optional[str] = None

class SBOMAnalysis(BaseModel):
    format: str
    components: List[Component]
    creation_date: str
    risk_score: float = 0.0