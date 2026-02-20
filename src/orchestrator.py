from typing import Dict, Any, List
import asyncio
from src.elasticsearch_client import ESClient
from src.agents.config_audit_agent import ConfigAuditAgent
from src.agents.runtime_monitor_agent import RuntimeMonitorAgent
from src.agents.skill_scanner_agent import SkillScannerAgent
from src.agents.breach_detector_agent import BreachDetectorAgent
from src.integrations.slack_notifier import SlackNotifier


class AgentOrchestrator:
    def __init__(self, es_client: ESClient) -> None:
        self.es_client = es_client
        self.slack = SlackNotifier()
        self.agents = {
            "config_audit": ConfigAuditAgent(es_client),
            "runtime_monitor": RuntimeMonitorAgent(es_client),
            "skill_scanner": SkillScannerAgent(es_client),
            "breach_detector": BreachDetectorAgent(es_client)
        }
        self.initialize_indices()
    
    def initialize_indices(self) -> None:
        indices = {
            "openclaw-configs": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "instance_id": {"type": "keyword"},
                    "vulnerabilities": {"type": "keyword"},
                    "risk_score": {"type": "float"},
                    "remediated": {"type": "boolean"}
                }
            },
            "openclaw-runtime": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "instance_id": {"type": "keyword"},
                    "action": {"type": "keyword"},
                    "threat_indicators": {"type": "keyword"},
                    "anomaly_score": {"type": "float"},
                    "blocked": {"type": "boolean"}
                }
            },
            "openclaw-skills": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "skill_id": {"type": "keyword"},
                    "author": {"type": "keyword"},
                    "threat_indicators": {"type": "keyword"},
                    "malware_probability": {"type": "float"},
                    "blocked": {"type": "boolean"}
                }
            }
        }
        
        for index_name, mappings in indices.items():
            self.es_client.create_index(index_name, mappings)

    async def run_agent(self, agent_name: str, context: Dict[str, Any]) -> Dict[str, Any]:
        if agent_name not in self.agents:
            return {"error": f"Agent {agent_name} not found"}
        
        agent = self.agents[agent_name]
        return await agent.execute(context)
    
    async def process_event(self, event_type: str, event_data: Dict[str, Any]) -> Dict[str, Any]:
        results: Dict[str, Any] = {"event_type": event_type, "agent_results": []}
        
        if event_type == "config_change":
            result = await self.run_agent("config_audit", event_data)
            results["agent_results"].append({"agent": "config_audit", "result": result})
            
            if result.get("vulnerabilities"):
                vulns = result.get("vulnerabilities", [])
                self.slack.send_alert("Config Vulnerability Detected", {
                    "instance_id": event_data.get("instance_id", "unknown"),
                    "severity": "critical",
                    "message": f"{len(vulns)} vulnerabilities found",
                    "vulnerabilities": vulns,
                    "blocked": False,
                    "detection_time": "0.2s"
                })
        
        elif event_type == "runtime_log":
            result = await self.run_agent("runtime_monitor", event_data)
            results["agent_results"].append({"agent": "runtime_monitor", "result": result})
            
            if result.get("blocked"):
                threats = result.get('threats', [])
                self.slack.send_alert("Threat Blocked", {
                    "instance_id": event_data.get("log_entry", {}).get("instance_id", "unknown"),
                    "severity": "critical",
                    "message": f"Blocked {len(threats)} threats",
                    "threats": threats,
                    "blocked": True,
                    "detection_time": "0.3s"
                })
                breach_result = await self.run_agent("breach_detector", {})
                results["agent_results"].append({"agent": "breach_detector", "result": breach_result})
        
        elif event_type == "skill_upload":
            result = await self.run_agent("skill_scanner", event_data)
            results["agent_results"].append({"agent": "skill_scanner", "result": result})
            
            if result.get("blocked"):
                threats = result.get('threats', [])
                self.slack.send_alert("Malicious Skill Blocked", {
                    "instance_id": event_data.get("skill_manifest", {}).get("id", "unknown"),
                    "severity": "critical",
                    "message": f"Blocked malicious skill with {len(threats)} indicators",
                    "threats": threats,
                    "blocked": True,
                    "detection_time": "0.3s"
                })
        
        return results
    
    async def run_continuous_monitoring(self, interval_seconds: int = 30) -> None:
        while True:
            await self.run_agent("breach_detector", {})
            await asyncio.sleep(interval_seconds)
