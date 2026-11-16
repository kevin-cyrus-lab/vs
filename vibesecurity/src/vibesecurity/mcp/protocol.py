from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional


class McpProtocolHandler:
    """Handles JSON-RPC 2.0 communication over standard input / output."""

    @staticmethod
    def read_message() -> Optional[Dict[str, Any]]:
        line = sys.stdin.readline()
        if not line:
            return None
        line_str = line.strip()
        if not line_str:
            return None
        try:
            return json.loads(line_str)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def send_response(req_id: Any, result: Any) -> None:
        msg = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result,
        }
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()

    @staticmethod
    def send_error(req_id: Any, code: int, message: str, data: Any = None) -> None:
        msg: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": code,
                "message": message,
            },
        }
        if data is not None:
            msg["error"]["data"] = data
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()

