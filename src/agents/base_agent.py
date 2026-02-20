from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from src.elasticsearch_client import ESClient


class BaseAgent(ABC):
    def __init__(self, es_client: ESClient, agent_id: str) -> None:
        self.es_client = es_client
        self.agent_id = agent_id
    
    @abstractmethod
    async def execute(self, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        pass
    
    def log_action(self, action: str, details: Dict[str, Any]) -> None:
        self.es_client.index_document(
            index="claw-defense-agent-logs",
            document={
                "agent_id": self.agent_id,
                "action": action,
                "details": details
            }
        )
