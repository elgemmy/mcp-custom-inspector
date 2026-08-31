from __future__ import annotations

import json
import unittest
from pathlib import Path

from mcp_probe_core.scenario import SCENARIO_SCHEMA, load_scenario


ROOT = Path(__file__).resolve().parents[1]


class ExampleFileTests(unittest.TestCase):
    def test_initialize_examples_are_json_objects(self) -> None:
        init_files = sorted((ROOT / "examples").glob("init-*.json"))
        self.assertTrue(init_files)
        for path in init_files:
            with self.subTest(path=path.name):
                value = json.loads(path.read_text(encoding="utf-8"))
                self.assertIsInstance(value, dict)

    def test_scenarios_use_current_small_schema(self) -> None:
        scenario_files = sorted((ROOT / "examples").glob("scenario-*.json"))
        self.assertTrue(scenario_files)
        for path in scenario_files:
            with self.subTest(path=path.name):
                scenario = load_scenario(path)
                self.assertEqual(scenario.schema, SCENARIO_SCHEMA)
                self.assertEqual(scenario.actions[0]["action"], "connect")
                self.assertEqual(scenario.actions[-1]["action"], "disconnect")

    def test_active_tool_example_names_its_exact_fixture_allow_list_target(self) -> None:
        scenario = load_scenario(ROOT / "examples" / "scenario-tool-call.json")
        tool_call = next(
            action
            for action in scenario.actions
            if action.get("method") == "tools/call"
        )
        self.assertEqual(tool_call["params"]["name"], "fixture_echo")


if __name__ == "__main__":
    unittest.main()
