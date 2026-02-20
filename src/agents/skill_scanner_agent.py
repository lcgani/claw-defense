from typing import Dict, Any, List, Optional
import json
import re
from src.agents.base_agent import BaseAgent


class SkillScannerAgent(BaseAgent):
    def __init__(self, es_client, agent_id: str = "skill_scanner") -> None:
        super().__init__(es_client, agent_id)
        self.malware_indicators = [
            r"eval\s*\(",
            r"exec\s*\(",
            r"__import__",
            r"base64\.b64decode",
            r"subprocess\.call",
            r"os\.system"
        ]
        self.suspicious_imports = [
            "socket", "urllib", "requests", "subprocess", "os.system"
        ]
    
    async def execute(self, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        skill_manifest = context.get("skill_manifest") if context else {}
        threats = await self.scan_skill(skill_manifest)
        
        malware_probability = self.calculate_malware_probability(threats)
        blocked = malware_probability > 0.7
        
        self.es_client.index_document(
            index="openclaw-skills",
            document={
                "skill_id": skill_manifest.get("id", "unknown"),
                "author": skill_manifest.get("author", "unknown"),
                "threat_indicators": [t["type"] for t in threats],
                "malware_probability": malware_probability,
                "blocked": blocked
            }
        )
        
        self.log_action("skill_scan", {"threats_found": len(threats), "blocked": blocked})
        return {"status": "completed", "threats": threats, "blocked": blocked}

    async def scan_skill(self, skill_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        threats: List[Dict[str, Any]] = []
        code = skill_manifest.get("code", "")
        
        for pattern in self.malware_indicators:
            if re.search(pattern, code):
                threats.append({
                    "type": "malicious_code",
                    "severity": "critical",
                    "pattern": pattern,
                    "recommendation": "Quarantine skill"
                })
        
        imports = skill_manifest.get("imports", [])
        for suspicious in self.suspicious_imports:
            if suspicious in imports:
                threats.append({
                    "type": "suspicious_import",
                    "severity": "high",
                    "module": suspicious,
                    "recommendation": "Review skill permissions"
                })
        
        if "token" in code.lower() and "send" in code.lower():
            threats.append({
                "type": "token_exfiltration",
                "severity": "critical",
                "recommendation": "Block installation"
            })
        
        return threats
    
    def calculate_malware_probability(self, threats: List[Dict[str, Any]]) -> float:
        if not threats:
            return 0.0
        
        critical_count = sum(1 for t in threats if t["severity"] == "critical")
        high_count = sum(1 for t in threats if t["severity"] == "high")
        
        score = (critical_count * 0.4) + (high_count * 0.2)
        return min(score, 1.0)
