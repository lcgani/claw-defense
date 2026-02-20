from elasticsearch import Elasticsearch
from typing import Dict, List, Any
from datetime import datetime
from src.config import settings


class ESClient:
    def __init__(self) -> None:
        self.client = Elasticsearch([settings.elasticsearch_url])
    
    def create_index(self, index_name: str, mappings: Dict[str, Any]) -> None:
        try:
            if not self.client.indices.exists(index=index_name):
                self.client.indices.create(index=index_name, mappings=mappings)
        except Exception as e:
            print(f"Warning: Could not create index {index_name}: {e}")
    
    def index_document(self, index: str, document: Dict[str, Any]) -> Dict[str, Any]:
        document["timestamp"] = datetime.utcnow().isoformat()
        return self.client.index(index=index, document=document)
    
    def search(self, index: str, query: Dict[str, Any]) -> Dict[str, Any]:
        return self.client.search(index=index, **query)
    
    def esql_query(self, query: str) -> List[Dict[str, Any]]:
        response = self.client.esql.query(query=query)
        return response.get("values", [])
    
    def close(self) -> None:
        self.client.close()
