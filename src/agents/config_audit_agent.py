from typing import Dict, Any, List, Optional
import json
import re
from pathlib import Path
from src.agents.base_agent import BaseAgent


class ConfigAuditAgent(BaseAgent):
    def __init__(self, es_client, agent_id: str = "config_audit") -> None:
        super().__init__(es_client, agent_id)
        self.vulnerability_patterns = {
            "exposed_token": r'(api[_-]?key|token|secret)["\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
            "weak_auth": r'"auth":\s*false|"authentication":\s*"none"',
            "wildcard_permissions": r'"permissions":\s*\["?\*"?\]',
            "disabled_security": r'"security":\s*false|"securityEnabled":\s*false'
        }
    
    async def execute(self, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        config_path = context.get("config_path") if context else "openclaw.json"
        vulnerabilities = await self.scan_config(config_path)
        
        if vulnerabilities:
            self.es_client.index_document(
                index="openclaw-configs",
                document={
                    "instance_id": context.get("instance_id", "unknown"),
                    "config_path": config_path,
                    "vulnerabilities": [v["type"] for v in vulnerabilities],
                    "risk_score": self.calculate_risk_score(vulnerabilities),
                    "remediated": False,
                    "details": vulnerabilities
                }
            )
        
        self.log_action("config_scan", {"vulnerabilities_found": len(vulnerabilities)})
        return {"status": "completed", "vulnerabilities": vulnerabilities}

    async def scan_config(self, config_path: str) -> List[Dict[str, Any]]:
        vulnerabilities: List[Dict[str, Any]] = []
        
        try:
            with open(config_path, 'r') as f:
                config_content = f.read()
                config_data = json.loads(config_content)
            
            for vuln_type, pattern in self.vulnerability_patterns.items():
                matches = re.finditer(pattern, config_content, re.IGNORECASE)
                for match in matches:
                    vulnerabilities.append({
                        "type": vuln_type,
                        "severity": self.get_severity(vuln_type),
                        "location": match.group(0)[:50],
                        "recommendation": self.get_recommendation(vuln_type)
                    })
        except FileNotFoundError:
            pass
        
        return vulnerabilities
    
    def calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        severity_weights = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 2.0}
        total = sum(severity_weights.get(v["severity"], 0) for v in vulnerabilities)
        return min(total, 10.0)
    
    def get_severity(self, vuln_type: str) -> str:
        severity_map = {
            "exposed_token": "critical",
            "weak_auth": "high",
            "wildcard_permissions": "high",
            "disabled_security": "critical"
        }
        return severity_map.get(vuln_type, "medium")
    
    def get_recommendation(self, vuln_type: str) -> str:
        recommendations = {
            "exposed_token": "Move tokens to environment variables",
            "weak_auth": "Enable authentication mechanisms",
            "wildcard_permissions": "Use principle of least privilege",
            "disabled_security": "Enable security features"
        }
        return recommendations.get(vuln_type, "Review configuration")
