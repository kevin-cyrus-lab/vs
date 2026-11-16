from __future__ import annotations

import sys
from typing import Any, Dict, Optional

from vibesecurity.core.service import VibeSecurityService
from vibesecurity.mcp.prompts import McpPromptsRegistry
from vibesecurity.mcp.protocol import McpProtocolHandler
from vibesecurity.mcp.resources import McpResourcesRegistry
from vibesecurity.mcp.tools import McpToolsRegistry


class VibeSecurityMcpServer:
    """Universal MCP Server running over standard I/O for Claude Code, Cursor, Windsurf, etc."""

    def __init__(self, service: Optional[VibeSecurityService] = None):
        self.service = service or VibeSecurityService()
        self.tools = McpToolsRegistry(self.service)
        self.resources = McpResourcesRegistry()
        self.prompts = McpPromptsRegistry()

    def run(self) -> None:
        """Main stdio loop listening for JSON-RPC messages."""
        while True:
            msg = McpProtocolHandler.read_message()
            if msg is None:
                break

            req_id = msg.get("id")
            method = msg.get("method")
            params = msg.get("params", {})

            # Notification (no id)
            if req_id is None:
                continue

            try:
                if method == "initialize":
                    res = {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {},
                            "resources": {},
                            "prompts": {},
                        },
                        "serverInfo": {
                            "name": "vibesecurity",
                            "version": "1.0.0",
                        },
                    }
                    McpProtocolHandler.send_response(req_id, res)

                elif method == "tools/list":
                    res = {"tools": self.tools.list_tools()}
                    McpProtocolHandler.send_response(req_id, res)

                elif method == "tools/call":
                    tool_name = params.get("name", "")
                    arguments = params.get("arguments", {})
                    res = self.tools.call_tool(tool_name, arguments)
                    McpProtocolHandler.send_response(req_id, res)

                elif method == "resources/list":
                    res = {"resources": self.resources.list_resources()}
                    McpProtocolHandler.send_response(req_id, res)

                elif method == "resources/read":
                    uri = params.get("uri", "")
                    res = self.resources.read_resource(uri)
                    McpProtocolHandler.send_response(req_id, res)

                elif method == "prompts/list":
                    res = {"prompts": self.prompts.list_prompts()}
                    McpProtocolHandler.send_response(req_id, res)

                elif method == "prompts/get":
                    name = params.get("name", "")
                    arguments = params.get("arguments", {})
                    res = self.prompts.get_prompt(name, arguments)
                    McpProtocolHandler.send_response(req_id, res)

                elif method == "ping":
                    McpProtocolHandler.send_response(req_id, {})

                else:
                    McpProtocolHandler.send_error(req_id, -32601, f"Method '{method}' not found")

            except Exception as e:
                McpProtocolHandler.send_error(req_id, -32603, f"Internal server error: {str(e)}")

