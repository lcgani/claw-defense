from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
from src.elasticsearch_client import ESClient
from src.orchestrator import AgentOrchestrator
from src.config import settings
from src.api.webhooks import router as webhook_router

app = FastAPI(title="Claw Defense API", version="1.0.0")

app.include_router(webhook_router)

es_client = ESClient()
orchestrator = AgentOrchestrator(es_client)


class EventRequest(BaseModel):
    event_type: str
    event_data: Dict[str, Any]


class MetricsResponse(BaseModel):
    threats_blocked: int
    instances_monitored: int
    malicious_skills_quarantined: int
    config_vulnerabilities_fixed: int


@app.get("/")
async def root() -> Dict[str, str]:
    return {"status": "operational", "service": "Claw Defense"}


@app.post("/events")
async def process_event(request: EventRequest) -> Dict[str, Any]:
    try:
        result = await orchestrator.process_event(request.event_type, request.event_data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/metrics")
async def get_metrics() -> MetricsResponse:
    runtime_blocked = es_client.search(
        "openclaw-runtime",
        {"query": {"term": {"blocked": True}}}
    )
    skills_blocked = es_client.search(
        "openclaw-skills",
        {"query": {"term": {"blocked": True}}}
    )
    
    return MetricsResponse(
        threats_blocked=runtime_blocked["hits"]["total"]["value"],
        instances_monitored=5,
        malicious_skills_quarantined=skills_blocked["hits"]["total"]["value"],
        config_vulnerabilities_fixed=0
    )
