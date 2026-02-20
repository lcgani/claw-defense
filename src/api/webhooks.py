from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Dict, Any, Optional
from src.orchestrator import AgentOrchestrator
from src.elasticsearch_client import ESClient

router = APIRouter(prefix="/webhook", tags=["webhooks"])

es_client = ESClient()
orchestrator = AgentOrchestrator(es_client)


class RuntimeLogWebhook(BaseModel):
    instance_id: str
    action: str
    user_input: str
    response_code: Optional[int] = 200


class SkillInstallWebhook(BaseModel):
    instance_id: str
    skill_id: str
    skill_name: str
    author: str
    code: str
    imports: list[str]


class ConfigChangeWebhook(BaseModel):
    instance_id: str
    config_data: Dict[str, Any]


@router.post("/runtime-log")
async def runtime_log_webhook(
    payload: RuntimeLogWebhook,
    x_openclaw_token: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """
    Real-time runtime monitoring webhook.
    OpenClaw instances call this before executing actions.
    Returns: {"allowed": bool, "reason": str, "threats": [...]}
    """
    
    result = await orchestrator.process_event("runtime_log", {
        "log_entry": {
            "instance_id": payload.instance_id,
            "action": payload.action,
            "user_input": payload.user_input,
            "response_code": payload.response_code
        }
    })
    
    agent_result = result["agent_results"][0]["result"]
    blocked = agent_result.get("blocked", False)
    threats = agent_result.get("threats", [])
    
    return {
        "allowed": not blocked,
        "reason": threats[0]["type"] if threats else "safe",
        "threats": threats,
        "recommendation": "Block execution" if blocked else "Proceed"
    }


@router.post("/skill-install")
async def skill_install_webhook(
    payload: SkillInstallWebhook,
    x_openclaw_token: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """
    Pre-installation skill scanning webhook.
    OpenClaw calls this before installing skills from ClawHub.
    Returns: {"allowed": bool, "malware_probability": float, "threats": [...]}
    """
    
    result = await orchestrator.process_event("skill_upload", {
        "skill_manifest": {
            "id": payload.skill_id,
            "name": payload.skill_name,
            "author": payload.author,
            "code": payload.code,
            "imports": payload.imports
        }
    })
    
    agent_result = result["agent_results"][0]["result"]
    blocked = agent_result.get("blocked", False)
    threats = agent_result.get("threats", [])
    
    return {
        "allowed": not blocked,
        "malware_probability": len(threats) * 0.3,
        "threats": threats,
        "recommendation": "Quarantine" if blocked else "Safe to install"
    }


@router.post("/config-change")
async def config_change_webhook(
    payload: ConfigChangeWebhook,
    x_openclaw_token: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """
    Configuration validation webhook.
    OpenClaw calls this before applying config changes.
    Returns: {"allowed": bool, "vulnerabilities": [...], "risk_score": float}
    """
    
    import tempfile
    import json
    import os
    
    config_path = os.path.join(tempfile.gettempdir(), f"{payload.instance_id}_config.json")
    with open(config_path, 'w') as f:
        json.dump(payload.config_data, f)
    
    result = await orchestrator.process_event("config_change", {
        "config_path": config_path,
        "instance_id": payload.instance_id
    })
    
    agent_result = result["agent_results"][0]["result"]
    vulnerabilities = agent_result.get("vulnerabilities", [])
    
    os.remove(config_path)
    
    return {
        "allowed": len(vulnerabilities) == 0,
        "vulnerabilities": vulnerabilities,
        "risk_score": len(vulnerabilities) * 2.5,
        "recommendation": "Fix vulnerabilities before applying" if vulnerabilities else "Config is secure"
    }
