import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.elasticsearch_client import ESClient
from src.orchestrator import AgentOrchestrator
from src.simulation.openclaw_simulator import OpenClawSimulator


async def run_demo() -> None:
    print("Starting Claw Defense Demo...")
    
    es_client = ESClient()
    orchestrator = AgentOrchestrator(es_client)
    simulator = OpenClawSimulator(num_instances=5)
    
    print("\n=== Prompt Injection Attack ===")
    attack = simulator.simulate_attack_scenario("prompt_injection")
    result = await orchestrator.process_event("runtime_log", {"log_entry": attack["log"]})
    print(f"Result: {result}")
    
    print("\n=== Malicious Skill Upload ===")
    attack = simulator.simulate_attack_scenario("malicious_skill")
    result = await orchestrator.process_event("skill_upload", {"skill_manifest": attack["skill"]})
    print(f"Result: {result}")
    
    print("\n=== Config Vulnerability ===")
    attack = simulator.simulate_attack_scenario("config_vulnerability")
    import tempfile
    import json
    import os
    config_path = os.path.join(tempfile.gettempdir(), f"{attack['instance_id']}_config.json")
    with open(config_path, 'w') as f:
        json.dump(attack["config"], f)
    
    result = await orchestrator.process_event("config_change", {
        "config_path": config_path,
        "instance_id": attack["instance_id"]
    })
    print(f"Result: {result}")
    
    print("\nDemo complete!")
    es_client.close()


if __name__ == "__main__":
    asyncio.run(run_demo())
