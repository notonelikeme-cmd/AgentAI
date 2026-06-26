#!/usr/bin/env python3
"""AgentAI MCP Server — exposes Trinity tools via Model Context Protocol."""
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

try:
    from mcp.server import Server
    from mcp.server.models import InitializationOptions
    import mcp.server.stdio
    import mcp.types as types
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

from core.core_registry import CoreRegistry
from core.analysis.findingsdb import FindingsDB
from core.analysis.solidity_analyzer import SolidityAnalyzer
from core.gates.gate0_novelty import Gate0Novelty
from core.models import CURATED_MODELS, model_profile


def main_stdio():
    if not MCP_AVAILABLE:
        print("ERROR: mcp package not installed. Run: pip install mcp", file=sys.stderr)
        sys.exit(1)

    server = Server("agentai-trinity")
    registry = CoreRegistry()
    registry.initialize()

    @server.list_tools()
    async def handle_list_tools():
        return [
            types.Tool(
                name="trinity_status",
                description="Get Nexus Trinity system status and registered agents",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            types.Tool(
                name="gate0_novelty_check",
                description="Gate 0: Check if a vulnerability hypothesis is novel (MANDATORY FIRST STEP)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "hypothesis": {"type": "string", "description": "The vulnerability hypothesis to check"},
                    },
                    "required": ["hypothesis"],
                },
            ),
            types.Tool(
                name="scan_solidity",
                description="Scan Solidity source for vulnerability patterns",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path to .sol file or directory"},
                    },
                    "required": ["path"],
                },
            ),
            types.Tool(
                name="add_finding",
                description="Add a vulnerability finding to the findings database",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"]},
                        "contract": {"type": "string"},
                        "hypothesis": {"type": "string"},
                        "net_profit": {"type": "number"},
                        "platform": {"type": "string"},
                        "notes": {"type": "string"},
                    },
                    "required": ["title", "severity"],
                },
            ),
            types.Tool(
                name="list_findings",
                description="List findings from the database",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "enum": ["pending", "verified", "rejected", "submitted"]},
                        "severity": {"type": "string"},
                    },
                },
            ),
            types.Tool(
                name="search_findings",
                description="Search findings by keyword",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                    },
                    "required": ["query"],
                },
            ),
            types.Tool(
                name="list_models",
                description="List curated Claude models with capability profiles (adaptive thinking, output limits, effort levels). claude-fable-5 is default.",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            types.Tool(
                name="model_info",
                description="Get capability profile for a specific Claude model",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "model": {"type": "string", "description": "Model ID e.g. claude-fable-5"},
                    },
                    "required": ["model"],
                },
            ),
        ]

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict):
        if name == "trinity_status":
            status = registry.status()
            return [types.TextContent(type="text", text=json.dumps(status, indent=2))]

        elif name == "gate0_novelty_check":
            gate = Gate0Novelty()
            result = gate.check(arguments["hypothesis"])
            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "scan_solidity":
            analyzer = SolidityAnalyzer()
            findings = analyzer.scan(arguments["path"])
            return [types.TextContent(type="text", text=json.dumps(findings, indent=2))]

        elif name == "add_finding":
            db = FindingsDB()
            fid = db.add(
                title=arguments["title"],
                severity=arguments["severity"],
                contract=arguments.get("contract", ""),
                hypothesis=arguments.get("hypothesis", ""),
                net_profit=arguments.get("net_profit", 0.0),
                platform=arguments.get("platform", ""),
                notes=arguments.get("notes", ""),
            )
            db.close()
            return [types.TextContent(type="text", text=json.dumps({"id": fid, "status": "added"}))]

        elif name == "list_findings":
            db = FindingsDB()
            findings = db.list_findings(
                status=arguments.get("status"),
                severity=arguments.get("severity"),
            )
            db.close()
            return [types.TextContent(type="text", text=json.dumps(findings, indent=2))]

        elif name == "search_findings":
            db = FindingsDB()
            findings = db.search(arguments["query"])
            db.close()
            return [types.TextContent(type="text", text=json.dumps(findings, indent=2))]

        elif name == "list_models":
            profiles = [model_profile(m) for m in CURATED_MODELS]
            return [types.TextContent(type="text", text=json.dumps(profiles, indent=2))]

        elif name == "model_info":
            profile = model_profile(arguments["model"])
            return [types.TextContent(type="text", text=json.dumps(profile, indent=2))]

        raise ValueError(f"Unknown tool: {name}")

    async def run():
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            init_opts = server.create_initialization_options()
            await server.run(read_stream, write_stream, init_opts)

    asyncio.run(run())


if __name__ == "__main__":
    main_stdio()
