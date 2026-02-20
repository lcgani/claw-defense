from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from src.agents.base_agent import BaseAgent


class BreachDetectorAgent(BaseAgent):
    def __init__(self, es_client, agent_id: str = "breach_detector") -> None:
        super().__init__(es_client, agent_id)
        self.auth_failure_threshold = 50
        self.time_window_minutes = 5
    
    async def execute(self, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        compromised_instances = await self.detect_breaches()
        
        for instance in compromised_instances:
            self.es_client.index_document(
                index="claw-defense-breaches",
                document={
                    "instance_id": instance["instance_id"],
                    "indicators": instance["indicators"],
                    "confidence": instance["confidence"],
                    "recommended_action": "quarantine"
                }
            )
        
        self.log_action("breach_detection", {"compromised_count": len(compromised_instances)})
        return {"status": "completed", "compromised_instances": compromised_instances}
    
    async def detect_breaches(self) -> List[Dict[str, Any]]:
        query = f"""
        FROM openclaw-runtime-*
        | WHERE action == "api_call" AND response_code == 401
        | STATS auth_failures = COUNT(*) BY instance_id
        | WHERE auth_failures > {self.auth_failure_threshold}
        """
        
        try:
            results = self.es_client.esql_query(query)
        except Exception:
            return []
        
        compromised: List[Dict[str, Any]] = []
        
        for row in results:
            instance_id = row[1] if len(row) > 1 else "unknown"
            auth_failures = row[0] if len(row) > 0 else 0
            
            compromised.append({
                "instance_id": instance_id,
                "indicators": ["excessive_auth_failures"],
                "confidence": min(auth_failures / 100.0, 1.0),
                "auth_failure_count": auth_failures
            })
        
        return compromised
