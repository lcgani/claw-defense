from typing import Dict, Any, List, Optional
import re
from src.agents.base_agent import BaseAgent


class RuntimeMonitorAgent(BaseAgent):
    def __init__(self, es_client, agent_id: str = "runtime_monitor") -> None:
        super().__init__(es_client, agent_id)
        self.injection_patterns = [
            r"ignore\s+previous\s+instructions",
            r"disregard\s+all\s+prior",
            r"forget\s+everything",
            r"new\s+instructions:",
            r"system\s+prompt\s+override"
        ]
        self.exfiltration_patterns = [
            r"send.*to.*@.*\.(com|net|org)",
            r"upload.*to.*http",
            r"post.*credentials"
        ]
    
    async def execute(self, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        log_entry = context.get("log_entry") if context else {}
        threats = await self.analyze_log(log_entry)
        
        if threats:
            self.es_client.index_document(
                index="openclaw-runtime",
                document={
                    "instance_id": log_entry.get("instance_id", "unknown"),
                    "action": log_entry.get("action"),
                    "threat_indicators": [t["type"] for t in threats],
                    "anomaly_score": self.calculate_anomaly_score(threats),
                    "blocked": True,
                    "reason": threats[0]["type"] if threats else None,
                    "details": log_entry
                }
            )
        
        self.log_action("runtime_analysis", {"threats_detected": len(threats)})
        return {"status": "completed", "threats": threats, "blocked": len(threats) > 0}

    async def analyze_log(self, log_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        threats: List[Dict[str, Any]] = []
        user_input = log_entry.get("user_input", "")
        action = log_entry.get("action", "")
        
        for pattern in self.injection_patterns:
            if re.search(pattern, user_input, re.IGNORECASE):
                threats.append({
                    "type": "prompt_injection",
                    "severity": "critical",
                    "pattern": pattern,
                    "recommendation": "Block execution and alert security team"
                })
        
        for pattern in self.exfiltration_patterns:
            if re.search(pattern, user_input, re.IGNORECASE):
                threats.append({
                    "type": "data_exfiltration",
                    "severity": "critical",
                    "pattern": pattern,
                    "recommendation": "Quarantine instance immediately"
                })
        
        if log_entry.get("response_code") == 401 and action == "api_call":
            threats.append({
                "type": "unauthorized_access",
                "severity": "high",
                "recommendation": "Monitor for breach indicators"
            })
        
        return threats
    
    def calculate_anomaly_score(self, threats: List[Dict[str, Any]]) -> float:
        severity_scores = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 2.0}
        total = sum(severity_scores.get(t["severity"], 0) for t in threats)
        return min(total, 10.0)
