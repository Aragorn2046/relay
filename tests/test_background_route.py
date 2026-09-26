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
    LIVE = {"kind": "claude", "model": "claude-opus-5-5", "effort": "high", "revision": 74,
            "route_source": "live",
            "fallbacks": [{"kind": "codex", "model": "gpt-6-astra", "effort": "medium"},
                          {"kind": "claude", "model": "claude-sonnet-5", "effort": "low"}]}

    def test_live_route_rows_are_the_cards_claude_rows(self):
        with self.helper(self.LIVE):
            route = relay.resolve_background_route(self.logger)
        self.assertEqual(route["rows"], [("claude-opus-5-5", "high"), ("claude-sonnet-5", "low")])
        self.assertEqual(relay.pick_route_row(route), ("claude-opus-5-5", "high", "claude-sonnet-5"))

    def test_a_named_model_must_be_a_row_and_runs_at_that_rows_effort(self):
        with self.helper(self.LIVE):
            route = relay.resolve_background_route(self.logger)
        self.assertEqual(relay.pick_route_row(route, "claude-sonnet-5"),
                         ("claude-sonnet-5", "low", "claude-opus-5-5"))
        for bad in ("opus", "sonnet", "claude-fable-5-1", "gpt-6-astra"):
            with self.subTest(bad=bad), self.assertRaises(relay.RouteRefused):
                relay.pick_route_row(route, bad)

    def test_an_unreadable_registry_uses_session_routes_logged_default(self):
        with self.helper({"kind": "claude", "model": "claude-sonnet-5", "effort": None,
                          "route_source": "default", "fallbacks": []}):
            route = relay.resolve_background_route(self.logger)
        self.assertEqual(route["rows"], [("claude-sonnet-5", None)])
        self.assertIn("compiled default", route["source"])
        self.assertFalse(hasattr(relay, "ROUTE_FALLBACK_MODEL"))  # the relay has no model of its own

    def test_session_route_failures_refuse_never_guess(self):
        with mock.patch.dict(os.environ, {"SHELBY_SESSION_ROUTE": str(self.root / "absent.py")}):
            with self.assertRaises(relay.RouteRefused):
                relay.resolve_background_route(self.logger)
        with self.helper({"kind": "claude"}, exit_code=2):
            with self.assertRaises(relay.RouteRefused):
                relay.resolve_background_route(self.logger)

    def test_rejected_or_non_claude_route_is_refused(self):
        with self.helper({"source": "rejected", "reason": "paused"}, exit_code=3):
            with self.assertRaises(relay.RouteRefused):
                relay.resolve_background_route(self.logger)
        with self.helper({"kind": "codex", "model": "gpt-6-astra", "effort": "medium",
                          "route_source": "live", "fallbacks": []}):
            with self.assertRaises(relay.RouteRefused):
                relay.resolve_background_route(self.logger)

    def test_unlaunchable_rows_and_malformed_answers_refuse(self):
        with self.helper({"kind": "claude", "model": "sonnet", "effort": "ultracode", "route_source": "live",
                          "fallbacks": []}):
            with self.assertRaises(relay.RouteRefused):
                relay.resolve_background_route(self.logger)
        with self.helper({"kind": "claude", "model": "claude-sonnet-5", "effort": None, "route_source": "live",
                          "fallbacks": 7}):
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
                                 vault_path=None,
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

    def test_a_named_model_outside_the_card_is_refused(self):
        with self.helper({"kind": "claude", "model": "claude-sonnet-5", "effort": None, "revision": 74,
                          "route_source": "live", "fallbacks": []}):
            argv = self.run_message({"body": "hello", "from": "dawn", "model": "opus"})
        self.assertIsNone(argv)

    def test_a_named_model_never_beats_a_paused_card(self):
        with self.helper({"reason": "paused"}, exit_code=3):
            argv = self.run_message({"body": "hello", "from": "dawn", "model": "claude-sonnet-5"})
        self.assertIsNone(argv)

    def test_an_unexpected_resolver_error_never_wedges_auto_exec(self):
        with mock.patch.object(relay, "resolve_background_route", side_effect=TypeError("boom")):
            argv = self.run_message({"body": "hello", "from": "dawn"})
        self.assertIsNone(argv)  # run_message asserts active went back to 0

    def test_refused_route_never_launches_claude(self):
        with self.helper({"reason": "resolver answer cannot be honoured: x"}, exit_code=3):
            argv = self.run_message({"body": "hello", "from": "dawn"})
        self.assertIsNone(argv)


if __name__ == "__main__":
    unittest.main()
