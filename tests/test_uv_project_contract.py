from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
EXAMPLE_DIR = ROOT / "examples" / "claude_desktop_config"
EXAMPLE_FILES = (
    "claude_desktop_config_example.json",
    "claude_config_development.json",
    "claude_config_production.json",
    "claude_config_windows.json",
)


class UvProjectContractTests(unittest.TestCase):
    def test_uv_is_the_only_dependency_installation_contract(self) -> None:
        self.assertTrue((ROOT / "pyproject.toml").is_file())
        self.assertTrue((ROOT / "uv.lock").is_file())

        for legacy_path in ("requirements.txt", "setup.bat", "setup.sh"):
            with self.subTest(path=legacy_path):
                self.assertFalse((ROOT / legacy_path).exists())

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(
            encoding="utf-8"
        )
        for text in (readme, workflow):
            self.assertNotIn("pip install", text)
            self.assertNotIn("requirements.txt", text)
        self.assertIn("uv sync --locked", readme)
        self.assertIn("uv sync --locked", workflow)

    def test_mcp_client_examples_use_locked_uv_launches(self) -> None:
        for filename in EXAMPLE_FILES:
            with self.subTest(filename=filename):
                payload = json.loads((EXAMPLE_DIR / filename).read_text(encoding="utf-8"))
                servers = payload["mcpServers"]
                self.assertEqual(len(servers), 1)
                server = next(iter(servers.values()))
                args = server["args"]

                self.assertEqual(server["command"], "uv")
                self.assertEqual(args[0], "--directory")
                self.assertTrue(args[1])
                self.assertEqual(args[2:6], ["run", "--locked", "python", "cs_mcp.py"])
                self.assertNotIn("cwd", server)


if __name__ == "__main__":
    unittest.main()
