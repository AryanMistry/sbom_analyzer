from pydantic import BaseModel, Field, HttpUrl, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class LicenseRisk(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


# Vulnerability Models

class VulnerabilityReference(BaseModel):
    type: Optional[str] = None
    url: str

    model_config = ConfigDict(extra="ignore")


class Vulnerability(BaseModel):
    id: str
    cve_id: Optional[str] = None
    summary: Optional[str] = None
    details: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    nvd_description: Optional[str] = None
    references: List[VulnerabilityReference] = []
    fixed_version: Optional[str] = None
    source: Optional[str] = "OSV"

    model_config = ConfigDict(extra="ignore")


# Component Models

class LicenseInfo(BaseModel):
    name: str
    spdx_id: Optional[str] = None
    risk_level: LicenseRisk = LicenseRisk.NONE
    is_copyleft: bool = False
    requires_attribution: bool = False


class Component(BaseModel):
    name: str
    version: str
    license: Optional[str] = None
    license_info: Optional[LicenseInfo] = None
    purl: Optional[str] = None
    vulnerabilities: List[Vulnerability] = []
    risk_score: float = 0.0
    ecosystem: Optional[str] = None
    description: Optional[str] = None

    model_config = ConfigDict(extra="ignore")


# SBOM Metadata Models

class SBOMMetadata(BaseModel):
    format: str
    spec_version: Optional[str] = None
    serial_number: Optional[str] = None
    creation_date: str
    creator_tool: Optional[str] = None
    creator_organization: Optional[str] = None
    document_name: Optional[str] = None


# Risk Analysis Models

class RiskBreakdown(BaseModel):
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    total_vulnerabilities: int = 0
    components_with_vulns: int = 0
    total_components: int = 0
    avg_cvss: float = 0.0
    max_cvss: float = 0.0
    avg_epss: float = 0.0
    max_epss: float = 0.0


class LicenseConflict(BaseModel):
    component1: str
    component2: str
    license1: str
    license2: str
    conflict_type: str
    description: str


# AI Insights Models

class RemediationStep(BaseModel):
    priority: int
    component: str
    current_version: str
    recommended_version: Optional[str] = None
    vulnerability_id: str
    action: str
    rationale: str


class AIRiskReport(BaseModel):
    executive_summary: str
    risk_level: str
    top_critical_issues: List[Dict[str, Any]]
    remediation_plan: List[RemediationStep]
    dependency_upgrade_paths: List[Dict[str, Any]]
    license_warnings: List[str]
    impacted_services: List[str]
    generated_at: datetime = Field(default_factory=datetime.utcnow)


# Main Analysis Models

class SBOMAnalysis(BaseModel):
    id: Optional[str] = None
    format: str
    components: List[Component]
    creation_date: str
    risk_score: float = 0.0
    risk_breakdown: Optional[RiskBreakdown] = None
    metadata: Optional[SBOMMetadata] = None
    license_conflicts: List[LicenseConflict] = []
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = ConfigDict(extra="ignore")


class SBOMAnalysisWithAI(SBOMAnalysis):
    ai_insights: Optional[AIRiskReport] = None


# ==================== Request/Response Models ====================

class AnalyzeRequest(BaseModel):
    include_ai_insights: bool = True
    software_domain: Optional[str] = None  # e.g., "web app", "backend service"


class AnalysisHistoryItem(BaseModel):
    id: str
    filename: str
    format: str
    components_count: int
    vulnerabilities_count: int
    risk_score: float
    analyzed_at: datetime
    status: str = "completed"


class AnalysisHistoryResponse(BaseModel):
    items: List[AnalysisHistoryItem]
    total: int
    page: int
    page_size: int


# Authentication Models

class UserCreate(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    is_active: bool = True
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenPayload(BaseModel):
    sub: str
    exp: int


class APIKeyCreate(BaseModel):
    name: str
    expires_days: int = 365


class APIKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    created_at: datetime
    expires_at: datetime
    last_used: Optional[datetime] = None


# Dashboard Stats Models

class DashboardStats(BaseModel):
    total_analyses: int
    total_components_scanned: int
    total_vulnerabilities_found: int
    critical_vulnerabilities: int
    avg_risk_score: float
    analyses_this_week: int
    top_vulnerable_components: List[Dict[str, Any]]
    severity_distribution: Dict[str, int]
    recent_analyses: List[AnalysisHistoryItem]
