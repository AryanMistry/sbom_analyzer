import json
import uuid
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, UploadFile, HTTPException, File, Form, Depends, Query, BackgroundTasks
from sqlalchemy.orm import Session

from sbom_parser.cyclonedx_parser import parse_cyclonedx_json, parse_cyclonedx_xml
from sbom_parser.spdx_parser import parse_spdx
from app.models.schemas import (
    SBOMAnalysis, 
    SBOMAnalysisWithAI, 
    Component,
    AnalysisHistoryItem,
    AnalysisHistoryResponse,
    DashboardStats,
    RiskBreakdown,
    SBOMMetadata
)
from app.services.vulnerability_service import vuln_service
from app.services.risk_calculator import risk_calculator
from app.services.ai_insights import ai_service
from app.core.database import get_db, Analysis
from app.core.security import get_current_user

router = APIRouter()

@router.get("/")
async def root():
    return {"message": "SBOM Analysis API", "version": "1.0.0"}


@router.post("/analyze", response_model=SBOMAnalysisWithAI)
async def analyze_sbom(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    include_ai_insights: bool = Form(True),
    software_domain: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: Optional[dict] = Depends(get_current_user)
):
    # Validate file size
    content_bytes = await file.read()
    if len(content_bytes) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(400, "File too large. Maximum size is 10MB.")
    
    content = content_bytes.decode('utf-8')
    filename = file.filename.lower() if file.filename else ""
    
    try:
        # Detect and parse format
        analysis_data = _detect_and_parse(content, filename)
        
        # Enrich with vulnerabilities
        components = analysis_data["components"]
        components = await vuln_service.batch_check_vulnerabilities(components, concurrency=3)
        analysis_data["components"] = components
        
        # Calculate risk scores
        overall_risk, breakdown = risk_calculator.calculate_risk_score(components)
        analysis_data["risk_score"] = overall_risk
        analysis_data["risk_breakdown"] = breakdown.model_dump()
        
      
        for comp in components:
            comp["risk_score"] = risk_calculator.calculate_component_risk(comp)
        
       
        license_conflicts = risk_calculator.detect_license_conflicts(components)
        analysis_data["license_conflicts"] = [c.model_dump() for c in license_conflicts]
        
        # Build metadata
        metadata = SBOMMetadata(
            format=analysis_data["format"],
            spec_version=analysis_data.get("spec_version"),
            serial_number=analysis_data.get("serial_number"),
            creation_date=analysis_data["creation_date"],
            creator_tool=analysis_data.get("creator_tool"),
            creator_organization=analysis_data.get("creator_organization"),
            document_name=analysis_data.get("document_name")
        )
        analysis_data["metadata"] = metadata.model_dump()
        
        # Generate analysis ID
        analysis_id = str(uuid.uuid4())
        analysis_data["id"] = analysis_id
        analysis_data["analyzed_at"] = datetime.utcnow().isoformat()
        
        # Generate AI insights if requested
        ai_insights = None
        if include_ai_insights:
            ai_insights = await ai_service.generate_insights(
                analysis_data, 
                software_domain
            )
            analysis_data["ai_insights"] = ai_insights.model_dump()
        
        # Count vulnerabilities
        total_vulns = sum(len(c.get("vulnerabilities", [])) for c in components)
        
        # Save to database
        background_tasks.add_task(
            _save_analysis_to_db,
            db=db,
            analysis_id=analysis_id,
            user_id=current_user.get("user_id") if current_user else None,
            filename=file.filename or "unknown",
            analysis_data=analysis_data,
            ai_insights=ai_insights,
            components_count=len(components),
            vulnerabilities_count=total_vulns,
            risk_score=overall_risk
        )
        
        return SBOMAnalysisWithAI(
            id=analysis_id,
            format=analysis_data["format"],
            components=[Component(**c) for c in components],
            creation_date=analysis_data["creation_date"],
            risk_score=overall_risk,
            risk_breakdown=RiskBreakdown(**breakdown.model_dump()),
            metadata=metadata,
            license_conflicts=license_conflicts,
            analyzed_at=datetime.fromisoformat(analysis_data["analyzed_at"]),
            ai_insights=ai_insights
        )
        
    except ValueError as e:
        raise HTTPException(400, f"Parse error: {str(e)}")
    except Exception as e:
        raise HTTPException(500, f"Analysis failed: {str(e)}")


def _detect_and_parse(content: str, filename: str) -> dict:
    """Detect SBOM format and parse accordingly"""
    content_stripped = content.strip()
    
    # Try to detect by filename first
    if "spdx" in filename:
        return parse_spdx(content)
    
    # Detect by content
    if content_stripped.startswith("{"):
        try:
            data = json.loads(content)
            if data.get("bomFormat", "").lower() == "cyclonedx":
                return parse_cyclonedx_json(content)
            elif "spdxVersion" in data or "SPDXID" in data or "packages" in data:
                return parse_spdx(content)
            else:
                # Default to CycloneDX JSON if components exist
                if "components" in data:
                    return parse_cyclonedx_json(content)
                raise ValueError("Cannot determine SBOM format from JSON")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {str(e)}")
    
    elif content_stripped.startswith("<"):
        if "cyclonedx" in content.lower() or "bom" in content[:500].lower():
            return parse_cyclonedx_xml(content)
        elif "spdx" in content.lower():
            return parse_spdx(content)
        else:
            # Try CycloneDX first, then SPDX
            try:
                return parse_cyclonedx_xml(content)
            except:
                return parse_spdx(content)
    
    raise ValueError("Unsupported file format. Expected JSON or XML SBOM.")


def _save_analysis_to_db(
    db: Session,
    analysis_id: str,
    user_id: Optional[str],
    filename: str,
    analysis_data: dict,
    ai_insights,
    components_count: int,
    vulnerabilities_count: int,
    risk_score: float
):
    try:
        analysis = Analysis(
            id=analysis_id,
            user_id=user_id,
            filename=filename,
            format=analysis_data["format"],
            components_count=components_count,
            vulnerabilities_count=vulnerabilities_count,
            risk_score=risk_score,
            status="completed",
            result_json=json.dumps(analysis_data, default=str),
            ai_insights_json=json.dumps(ai_insights.model_dump(), default=str) if ai_insights else None
        )
        db.add(analysis)
        db.commit()
    except Exception as e:
        print(f"Failed to save analysis to database: {e}")
        db.rollback()


@router.get("/analysis/{analysis_id}", response_model=SBOMAnalysisWithAI)
async def get_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[dict] = Depends(get_current_user)
):
    """Retrieve a previous analysis by ID"""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    
    if not analysis:
        raise HTTPException(404, "Analysis not found")

    result_data = json.loads(analysis.result_json) if analysis.result_json else {}
    ai_data = json.loads(analysis.ai_insights_json) if analysis.ai_insights_json else None
    
    return SBOMAnalysisWithAI(
        id=analysis.id,
        format=analysis.format,
        components=[Component(**c) for c in result_data.get("components", [])],
        creation_date=result_data.get("creation_date", "unknown"),
        risk_score=analysis.risk_score,
        risk_breakdown=RiskBreakdown(**result_data.get("risk_breakdown", {})) if result_data.get("risk_breakdown") else None,
        metadata=SBOMMetadata(**result_data.get("metadata", {})) if result_data.get("metadata") else None,
        license_conflicts=result_data.get("license_conflicts", []),
        analyzed_at=analysis.analyzed_at,
        ai_insights=ai_data
    )


@router.get("/history", response_model=AnalysisHistoryResponse)
async def get_analysis_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: Optional[dict] = Depends(get_current_user)
):
    query = db.query(Analysis)
    
    if current_user:
        query = query.filter(Analysis.user_id == current_user.get("user_id"))
    
    total = query.count()
    
    analyses = query.order_by(Analysis.analyzed_at.desc())\
        .offset((page - 1) * page_size)\
        .limit(page_size)\
        .all()
    
    items = [
        AnalysisHistoryItem(
            id=a.id,
            filename=a.filename,
            format=a.format,
            components_count=a.components_count,
            vulnerabilities_count=a.vulnerabilities_count,
            risk_score=a.risk_score,
            analyzed_at=a.analyzed_at,
            status=a.status
        )
        for a in analyses
    ]
    
    return AnalysisHistoryResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size
    )


@router.delete("/analysis/{analysis_id}")
async def delete_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    if not current_user:
        raise HTTPException(401, "Authentication required")
    
    analysis = db.query(Analysis).filter(
        Analysis.id == analysis_id,
        Analysis.user_id == current_user.get("user_id")
    ).first()
    
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    db.delete(analysis)
    db.commit()
    
    return {"message": "Analysis deleted successfully"}


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: Optional[dict] = Depends(get_current_user)
):
    from datetime import timedelta
    from sqlalchemy import func
    
    query = db.query(Analysis)
    
    if current_user:
        query = query.filter(Analysis.user_id == current_user.get("user_id"))
    
    total_analyses = query.count()
    
    stats = query.with_entities(
        func.sum(Analysis.components_count).label("total_components"),
        func.sum(Analysis.vulnerabilities_count).label("total_vulns"),
        func.avg(Analysis.risk_score).label("avg_risk")
    ).first()
    
    week_ago = datetime.utcnow() - timedelta(days=7)
    analyses_this_week = query.filter(Analysis.analyzed_at >= week_ago).count()
    
    # Recent analyses
    recent = query.order_by(Analysis.analyzed_at.desc()).limit(5).all()
    recent_items = [
        AnalysisHistoryItem(
            id=a.id,
            filename=a.filename,
            format=a.format,
            components_count=a.components_count,
            vulnerabilities_count=a.vulnerabilities_count,
            risk_score=a.risk_score,
            analyzed_at=a.analyzed_at,
            status=a.status
        )
        for a in recent
    ]
    
    # For now, estimate based on risk score
    critical_estimate = sum(
        1 for a in recent 
        if a.risk_score >= 70 and a.vulnerabilities_count > 0
    )
    
    return DashboardStats(
        total_analyses=total_analyses,
        total_components_scanned=stats.total_components or 0,
        total_vulnerabilities_found=stats.total_vulns or 0,
        critical_vulnerabilities=critical_estimate,
        avg_risk_score=round(stats.avg_risk or 0, 1),
        analyses_this_week=analyses_this_week,
        top_vulnerable_components=[],  
        severity_distribution={
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        },
        recent_analyses=recent_items
    )


@router.post("/reanalyze/{analysis_id}", response_model=SBOMAnalysisWithAI)
async def reanalyze_sbom(
    analysis_id: str,
    background_tasks: BackgroundTasks,
    include_ai_insights: bool = True,
    software_domain: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Optional[dict] = Depends(get_current_user)
):
    original = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    
    if not original:
        raise HTTPException(404, "Analysis not found")
    
    original_data = json.loads(original.result_json) if original.result_json else {}
    components = original_data.get("components", [])
    
    for comp in components:
        comp["vulnerabilities"] = []
    
    components = await vuln_service.batch_check_vulnerabilities(components, concurrency=3)
    
    overall_risk, breakdown = risk_calculator.calculate_risk_score(components)
    
    for comp in components:
        comp["risk_score"] = risk_calculator.calculate_component_risk(comp)
    
    license_conflicts = risk_calculator.detect_license_conflicts(components)

    analysis_data = {
        **original_data,
        "components": components,
        "risk_score": overall_risk,
        "risk_breakdown": breakdown.model_dump(),
        "license_conflicts": [c.model_dump() for c in license_conflicts],
        "analyzed_at": datetime.utcnow().isoformat()
    }
    

    ai_insights = None
    if include_ai_insights:
        ai_insights = await ai_service.generate_insights(analysis_data, software_domain)
        analysis_data["ai_insights"] = ai_insights.model_dump()
    
    # Update database
    total_vulns = sum(len(c.get("vulnerabilities", [])) for c in components)
    
    original.result_json = json.dumps(analysis_data, default=str)
    original.ai_insights_json = json.dumps(ai_insights.model_dump(), default=str) if ai_insights else None
    original.risk_score = overall_risk
    original.vulnerabilities_count = total_vulns
    original.analyzed_at = datetime.utcnow()
    db.commit()
    
    return SBOMAnalysisWithAI(
        id=original.id,
        format=original.format,
        components=[Component(**c) for c in components],
        creation_date=original_data.get("creation_date", "unknown"),
        risk_score=overall_risk,
        risk_breakdown=RiskBreakdown(**breakdown.model_dump()),
        metadata=SBOMMetadata(**original_data.get("metadata", {})) if original_data.get("metadata") else None,
        license_conflicts=license_conflicts,
        analyzed_at=datetime.utcnow(),
        ai_insights=ai_insights
    )
