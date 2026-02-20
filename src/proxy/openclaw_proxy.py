"""
OpenClaw Security Proxy - Routes OpenClaw traffic through Claw Defense
"""
import asyncio
import json
import httpx
from fastapi import FastAPI, Request, Response, WebSocket
from fastapi.responses import JSONResponse
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="OpenClaw Security Proxy")

OPENCLAW_GATEWAY = "http://127.0.0.1:18789"
CLAW_DEFENSE_API = "http://localhost:8000"


@app.get("/health")
async def health():
    return {"status": "proxy_operational", "service": "OpenClaw Security Proxy"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_request(path: str, request: Request):
    """Proxy HTTP requests through Claw Defense validation"""
    
    body = await request.body()
    
    if request.method == "POST" and body:
        try:
            data = json.loads(body)
            
            # Check for agent actions
            if "action" in data or "command" in data or "prompt" in data:
                user_input = data.get("prompt", data.get("command", data.get("action", "")))
                
                # Validate through Claw Defense
                async with httpx.AsyncClient() as client:
                    validation = await client.post(
                        f"{CLAW_DEFENSE_API}/webhook/runtime-log",
                        json={
                            "instance_id": "openclaw-proxy",
                            "action": data.get("action", "unknown"),
                            "user_input": str(user_input),
                            "response_code": 200
                        },
                        headers={"X-OpenClaw-Token": "proxy-token"}
                    )
                    
                    result = validation.json()
                    
                    if not result.get("allowed", True):
                        logger.warning(f"BLOCKED: {result.get('reason')} - Threats: {result.get('threats')}")
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": "Security violation detected",
                                "reason": result.get("reason"),
                                "threats": result.get("threats"),
                                "blocked_by": "Claw Defense"
                            }
                        )
        except Exception as e:
            logger.error(f"Validation error: {e}")
    
    # Forward to OpenClaw Gateway
    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(
                method=request.method,
                url=f"{OPENCLAW_GATEWAY}/{path}",
                headers=dict(request.headers),
                content=body,
                params=request.query_params
            )
            
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers)
            )
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            return JSONResponse(
                status_code=502,
                content={"error": "Gateway unreachable", "detail": str(e)}
            )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
