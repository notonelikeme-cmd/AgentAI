"""AgentFramework — base class and routing for Nexus Trinity agents."""
import abc
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class AgentStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class GateStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    PENDING = "PENDING"


@dataclass
class GateResult:
    gate: int
    status: GateStatus
    reason: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def passed(self) -> bool:
        return self.status == GateStatus.PASS


@dataclass
class AgentTask:
    task_id: str
    agent_name: str
    input: Dict[str, Any]
    output: Optional[Dict[str, Any]] = None
    status: AgentStatus = AgentStatus.IDLE
    gate_results: List[GateResult] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "agent": self.agent_name,
            "status": self.status.value,
            "gate_results": [
                {"gate": g.gate, "status": g.status.value, "reason": g.reason}
                for g in self.gate_results
            ],
            "output": self.output,
            "error": self.error,
        }


class Agent(abc.ABC):
    """Base class for all Nexus Trinity agents."""

    def __init__(self):
        self.name = self.__class__.__name__
        self.status = AgentStatus.IDLE
        self._task: Optional[AgentTask] = None

    def on_initialize(self) -> None:
        """Called once when agent starts a task."""

    @abc.abstractmethod
    def on_task(self, task: AgentTask) -> AgentTask:
        """Main agent logic. Must return the task with output set."""

    def run(self, task: AgentTask) -> AgentTask:
        self._task = task
        task.status = AgentStatus.RUNNING
        self.on_initialize()
        try:
            result = self.on_task(task)
            if result.status == AgentStatus.RUNNING:
                result.status = AgentStatus.COMPLETED
            return result
        except Exception as e:
            task.status = AgentStatus.FAILED
            task.error = str(e)
            return task

    def _gate_pass(self, gate: int, data: dict = None, reason: str = "") -> GateResult:
        return GateResult(gate=gate, status=GateStatus.PASS, reason=reason, data=data or {})

    def _gate_fail(self, gate: int, reason: str, data: dict = None) -> GateResult:
        return GateResult(gate=gate, status=GateStatus.FAIL, reason=reason, data=data or {})


class AgentFramework:
    """Routes tasks to registered agents."""

    def __init__(self):
        self._agents: Dict[str, type] = {}

    def register(self, name: str, agent_class: type):
        self._agents[name] = agent_class

    def get(self, name: str) -> Optional[type]:
        return self._agents.get(name)

    def run(self, name: str, task: AgentTask) -> AgentTask:
        cls = self._agents.get(name)
        if not cls:
            task.status = AgentStatus.FAILED
            task.error = f"Agent not found: {name}"
            return task
        agent = cls()
        return agent.run(task)

    def list_agents(self) -> List[str]:
        return list(self._agents.keys())
