#!/usr/bin/env python3
"""AUTO-EXEC model selection: registry route, message override, loud fallback."""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import stat
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

RELAY = Path(__file__).resolve().parent.parent / "relay.py"
spec = importlib.util.spec_from_file_location("relay_under_test", RELAY)
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


def _executable(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class _RouteCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="relay-route-")
        self.root = Path(self.temp.name)
        self.fallback_log = self.root / "routing-fallback.jsonl"
        patches = [
            mock.patch.object(relay, "ROUTING_FALLBACK_LOG", self.fallback_log),
            mock.patch.object(relay, "play_exec_alert", lambda *_: None),
            mock.patch.object(relay, "play_done_alert", lambda *_: None),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(self.temp.cleanup)
        self.logger = logging.getLogger("relay-route-test")

    def helper(self, payload, exit_code=0):
        script = _executable(self.root / "session-route.py", textwrap.dedent(f"""\
            import json, sys
            assert sys.argv[1:3] == ["--consumer", "background-claude"], sys.argv
            assert "--json" in sys.argv
            sys.stdout.write({json.dumps(json.dumps(payload))})
            raise SystemExit({exit_code})
            """))
        return mock.patch.dict(os.environ, {"SHELBY_SESSION_ROUTE": str(script)})

    def fallback_records(self):
        if not self.fallback_log.exists():
            return []
        return [json.loads(line) for line in self.fallback_log.read_text().splitlines()]



class BackgroundRouteTests(_RouteCase):
    def test_live_route_without_level(self):
        with self.helper({"kind": "claude", "model": "claude-sonnet-5", "effort": None, "revision": 74,
                          "route_source": "live", "fallbacks": []}):
            route = relay.resolve_background_route(self.logger)
        self.assertEqual((route["model"], route["effort"], route["fallback_model"]),
                         ("claude-sonnet-5", None, None))
        self.assertEqual(self.fallback_records(), [])

    def test_route_level_and_first_claude_fallback_are_used(self):
        with self.helper({"kind": "claude", "model": "claude-opus-5-5", "effort": "high", "revision": 74,
                          "route_source": "cache",
                          "fallbacks": [{"kind": "claude", "model": "claude-opus-5", "effort": "high"}]}):
            route = relay.resolve_background_route(self.logger)
        self.assertEqual((route["model"], route["effort"], route["fallback_model"]),
                         ("claude-opus-5-5", "high", "claude-opus-5"))

    def test_default_route_runs_compiled_fallback_loudly(self):
        with self.helper({"kind": "claude", "model": "claude-sonnet-5", "effort": None,
                          "route_source": "default", "fallbacks": []}), \
                self.assertLogs(self.logger, "WARNING"):
            route = relay.resolve_background_route(self.logger)
        self.assertEqual((route["model"], route["source"]), (relay.ROUTE_FALLBACK_MODEL, "compiled-fallback"))
        [record] = self.fallback_records()
        self.assertEqual(record["consumer"], "background-claude")
        self.assertEqual(record["chain"], [relay.ROUTE_FALLBACK_MODEL])
        self.assertRegex(record["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertIn("compiled default", record["reason"])
        self.assertTrue(record["host"])

    def test_missing_helper_runs_compiled_fallback_loudly(self):
        with mock.patch.dict(os.environ, {"SHELBY_SESSION_ROUTE": str(self.root / "absent.py")}):
            route = relay.resolve_background_route(self.logger)
        self.assertEqual(route["model"], relay.ROUTE_FALLBACK_MODEL)
        self.assertIn("session-route exit", self.fallback_records()[0]["reason"])

    def test_rejected_route_is_refused_not_replaced(self):
        with self.helper({"source": "rejected", "route_source": "rejected",
                          "reason": "resolver answer cannot be honoured: x"}, exit_code=3):
            with self.assertRaises(relay.RouteRefused):
                relay.resolve_background_route(self.logger)
        self.assertEqual(self.fallback_records(), [])

    def test_non_claude_route_is_refused(self):
        with self.helper({"kind": "codex", "model": "gpt-6-astra", "effort": "medium",
                          "route_source": "live", "fallbacks": []}):
            with self.assertRaises(relay.RouteRefused):
                relay.resolve_background_route(self.logger)

    def test_build_claude_cmd(self):
        self.assertEqual(relay.build_claude_cmd("claude", "claude-sonnet-5", 1.0, "t"),
                         ["claude", "--model", "claude-sonnet-5", "--max-budget-usd", "1.0", "-p", "t"])
        self.assertEqual(relay.build_claude_cmd("claude", "m", 2.0, "t", "low", "f"),
                         ["claude", "--model", "m", "--effort", "low", "--fallback-model", "f",
                          "--max-budget-usd", "2.0", "-p", "t"])


class AutoExecutorModelTests(_RouteCase):
    """End to end through AutoExecutor._run with a fake claude binary."""

    def run_message(self, msg):
        home = self.root / "home"
        argv_file = self.root / "claude-argv.json"
        _executable(home / ".local" / "bin" / "claude", textwrap.dedent(f"""\
            #!/usr/bin/env python3
            import json, sys
            json.dump(sys.argv[1:], open({str(argv_file)!r}, "w"))
            print("done")
            """))
        config = SimpleNamespace(default_budget=1.0, max_budget=5.0, exec_timeout=30,
                                 allowed_models=["sonnet", "opus", "haiku"], vault_path=None,
                                 log_dir=self.root / "logs", platform="test", max_concurrent=2)
        executor = relay.AutoExecutor(config, self.logger)
        executor.active = 1
        with mock.patch.dict(os.environ, {"HOME": str(home)}):
            executor._run(msg)
        self.assertEqual(executor.active, 0)
        return json.loads(argv_file.read_text()) if argv_file.exists() else None

    def test_unnamed_model_uses_registry_route(self):
        with self.helper({"kind": "claude", "model": "claude-sonnet-5", "effort": None, "revision": 74,
                          "route_source": "live", "fallbacks": []}):
            argv = self.run_message({"body": "hello", "from": "dawn"})
        self.assertEqual(argv[:2], ["--model", "claude-sonnet-5"])
        self.assertNotIn("--effort", argv)

    def test_named_model_is_a_manual_override(self):
        with self.helper({"kind": "claude", "model": "claude-sonnet-5", "effort": None, "revision": 74,
                          "route_source": "live", "fallbacks": []}):
            argv = self.run_message({"body": "hello", "from": "dawn", "model": "opus"})
        self.assertEqual(argv[:2], ["--model", "opus"])

    def test_refused_route_never_launches_claude(self):
        with self.helper({"reason": "resolver answer cannot be honoured: x"}, exit_code=3):
            argv = self.run_message({"body": "hello", "from": "dawn"})
        self.assertIsNone(argv)


if __name__ == "__main__":
    unittest.main()
