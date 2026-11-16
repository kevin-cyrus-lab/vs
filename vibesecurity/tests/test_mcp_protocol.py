import unittest
from vibesecurity.core.service import VibeSecurityService
from vibesecurity.mcp.tools import McpToolsRegistry
from vibesecurity.mcp.resources import McpResourcesRegistry
from vibesecurity.mcp.prompts import McpPromptsRegistry

class TestMcpProtocol(unittest.TestCase):
    def setUp(self):
        self.service = VibeSecurityService()
        self.tools = McpToolsRegistry(self.service)
        self.resources = McpResourcesRegistry()
        self.prompts = McpPromptsRegistry()

    def test_tools_enumeration(self):
        tool_list = self.tools.list_tools()
        names = [t["name"] for t in tool_list]
        self.assertIn("breakdown_project", names)
        self.assertIn("scan_repository", names)
        self.assertIn("auto_remediate_project", names)
        self.assertIn("generate_security_patch", names)

    def test_resources_enumeration(self):
        res_list = self.resources.list_resources()
        uris = [r["uri"] for r in res_list]
        self.assertIn("vibesecurity://policies/current", uris)
        self.assertIn("vibesecurity://security/owasp", uris)

    def test_prompts_enumeration(self):
        p_list = self.prompts.list_prompts()
        names = [p["name"] for p in p_list]
        self.assertIn("audit_entire_repository", names)
        self.assertIn("auto_repair_vulnerabilities", names)

if __name__ == "__main__":
    unittest.main()

