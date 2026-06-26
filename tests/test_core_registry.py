"""Tests for CoreRegistry — system status and agent registry."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from core.core_registry import CoreRegistry, DEFAULT_AGENTS


@pytest.fixture(autouse=True)
def reset_singleton():
    # CoreRegistry is a singleton — reset between tests
    CoreRegistry._instance = None
    yield
    CoreRegistry._instance = None


@pytest.fixture
def registry():
    r = CoreRegistry()
    r.initialize()
    return r


class TestInitialization:
    def test_singleton_pattern(self):
        a = CoreRegistry()
        b = CoreRegistry()
        assert a is b

    def test_initialize_idempotent(self, registry):
        registry.initialize()
        registry.initialize()  # second call should not reset state
        assert len(registry.list_agents()) == len(DEFAULT_AGENTS)

    def test_all_default_agents_registered(self, registry):
        agents = registry.list_agents()
        for agent in DEFAULT_AGENTS:
            assert agent in agents


class TestStatus:
    def test_status_returns_dict(self, registry):
        s = registry.status()
        assert isinstance(s, dict)

    def test_status_has_required_sections(self, registry):
        s = registry.status()
        assert "system" in s
        assert "agents" in s
        assert "modules" in s
        assert "paths" in s
        assert "models" in s

    def test_system_section(self, registry):
        s = registry.status()["system"]
        assert s["initialized"] is True
        assert s["version"] == "2.0.0-mac"
        assert s["platform"] == "macOS-M5"

    def test_models_section_has_fable5_default(self, registry):
        models = registry.status()["models"]
        assert models["default"] == "claude-fable-5"
        assert "claude-fable-5" in models["curated"]

    def test_models_section_has_profile(self, registry):
        profile = registry.status()["models"]["default_profile"]
        assert profile["adaptive_thinking"] is True
        assert profile["xhigh_effort"] is True
        assert profile["max_output_tokens"] == 128_000

    def test_agents_count_matches(self, registry):
        s = registry.status()
        assert s["agents"]["total"] == len(DEFAULT_AGENTS)

    def test_paths_include_agents_dir(self, registry):
        paths = registry.status()["paths"]
        assert ".claude" in paths["agents"]
        assert "agents" in paths["agents"]

    def test_timestamp_present(self, registry):
        s = registry.status()
        assert s["system"]["timestamp"] is not None


class TestAgentManagement:
    def test_register_new_agent(self, registry):
        registry.register_agent("my-custom-agent")
        assert "my-custom-agent" in registry.list_agents()

    def test_register_duplicate_no_double_entry(self, registry):
        registry.register_agent("defi-security-auditor")  # already in DEFAULT_AGENTS
        agents = registry.list_agents()
        assert agents.count("defi-security-auditor") == 1

    def test_list_agents_returns_list(self, registry):
        assert isinstance(registry.list_agents(), list)
