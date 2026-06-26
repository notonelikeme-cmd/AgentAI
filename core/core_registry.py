"""CoreRegistry — singleton that tracks system state and registered agents."""
import json
from datetime import datetime
from pathlib import Path

from core.models import CURATED_MODELS, model_profile

ROOT = Path(__file__).parent.parent

DEFAULT_AGENTS = [
    # DeFi security agents
    "defi-security-auditor",
    "web3-defi-analyst",
    "onchain-surveillance-sentinel",
    "conservation-breaker",
    "freeze-hunter",
    "upgrade-storage-collision",
    "cross-contract-invariant",
    "cache-tier-reviewer",
    "token-optimizer",
    "defi-vuln-scout",
    # Verification agents
    "verification-adversary",
    "vuln-finding-verifier",
    "gatekeeper-hallucination-enforcer",
    "source-verified-auditor",
    "Veritas-security-auditor",
    # Recon agents
    "recon-surface-mapper",
    "attack-vector-mapper",
    "code-risk-analyzer",
    # Workflow agents
    "agent-router-reviewer",
    "research-engine-reviewer",
    "issue-duplicate-role-validator",
]

MODULES = [
    "solidity_analyzer",
    "evm_simulator",
    "findingsdb",
    "cfg_builder",
    "defi_kg",
    "rao_brain",
    "rao_loop",
    "verification_loop",
]


class CoreRegistry:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def initialize(self):
        if self._initialized:
            return
        self._agents = list(DEFAULT_AGENTS)
        self._modules = {}
        self._initialized = True
        self._init_time = datetime.utcnow()

        # Try loading optional modules
        for mod in MODULES:
            try:
                __import__(f"core.analysis.{mod}")
                self._modules[mod] = "loaded"
            except ImportError:
                try:
                    __import__(f"core.gates.{mod}")
                    self._modules[mod] = "loaded"
                except ImportError:
                    self._modules[mod] = "not_found"

    def status(self) -> dict:
        self.initialize()
        default_model = CURATED_MODELS[0]
        return {
            "system": {
                "initialized": True,
                "timestamp": self._init_time.isoformat() if hasattr(self, "_init_time") else None,
                "version": "2.0.0-mac",
                "mode": "Sovereign",
                "platform": "macOS-M5",
            },
            "models": {
                "default": default_model,
                "curated": CURATED_MODELS,
                "default_profile": model_profile(default_model),
            },
            "agents": {
                "total": len(self._agents),
                "registered": self._agents,
            },
            "modules": self._modules,
            "paths": {
                "root": str(ROOT),
                "agents": str(Path.home() / ".claude" / "agents"),
                "findingsdb": str(ROOT / ".claude" / "defi_kg.db"),
            },
        }

    def register_agent(self, name: str):
        if name not in self._agents:
            self._agents.append(name)

    def list_agents(self) -> list:
        return list(self._agents)

    def get_module(self, name: str):
        return self._modules.get(name)
