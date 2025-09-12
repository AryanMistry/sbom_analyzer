from pydantic import BaseModel
from typing import List, Optional

class Component(BaseModel):
    name: str
    version: str
    license: Optional[str] = None
    vulnerabilities: List[str] = []
    purl: Optional[str] = None

class SBOMAnalysis(BaseModel):
    format: str
    components: List[Component]
    creation_date: str
    risk_score: float = 0.0