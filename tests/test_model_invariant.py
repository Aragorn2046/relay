import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import relay


class ModelNormalizationTests(unittest.TestCase):
    def test_current_names_remain_canonical(self):
        self.assertEqual(relay.normalize_model("claude-fable-5-1"), relay.PRIMARY_MODEL)
        self.assertEqual(relay.normalize_model("claude-opus-5"), relay.FALLBACK_MODEL)

    def test_legacy_fable_sonnet_and_haiku_upgrade_to_fable_5_1(self):
        aliases = (
            "fable",
            "claude-fable-5",
            "sonnet",
            "claude-sonnet-5",
            "haiku",
            "claude-haiku-4-5-20251001",
            "anthropic:claude-sonnet-5",
            "anthropic/claude-sonnet-5",
        )
        for alias in aliases:
            with self.subTest(alias=alias):
                self.assertEqual(relay.normalize_model(alias), relay.PRIMARY_MODEL)

    def test_legacy_opus_names_upgrade_to_opus_5(self):
        aliases = (
            "opus",
            "claude-opus-4-1",
            "anthropic:claude-opus-4",
            "anthropic/claude-opus-4",
        )
        for alias in aliases:
            with self.subTest(alias=alias):
                self.assertEqual(relay.normalize_model(alias), relay.FALLBACK_MODEL)

    def test_unknown_and_non_string_names_are_rejected(self):
        for value in ("gpt-5.6", "claude", "", None, 5):
            with self.subTest(value=value):
                self.assertIsNone(relay.normalize_model(value))


class ConfigModelInvariantTests(unittest.TestCase):
    def test_stale_config_is_canonicalized_to_the_only_supported_pair(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            secret = root / "relay-secret"
            secret.write_text("test-only-secret")
            secret.chmod(0o600)
            config_path = root / "config.json"
            config_path.write_text(json.dumps({
                "machine": "test",
                "secret_file": str(secret),
                "log_dir": str(root / "logs"),
                "auto_execute": {
                    "default_model": "sonnet",
                    "allowed_models": ["sonnet", "haiku", "gpt-5.6"],
                },
            }))

            with mock.patch.object(relay, "detect_tailscale_ip", return_value=None):
                config = relay.Config(config_path)

        self.assertEqual(config.default_model, relay.PRIMARY_MODEL)
        self.assertEqual(config.allowed_models, list(relay.ALLOWED_MODELS))


class AutoExecutorModelInvariantTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.config = SimpleNamespace(
            default_model=relay.PRIMARY_MODEL,
            default_budget=1.0,
            max_budget=5.0,
            allowed_models=list(relay.ALLOWED_MODELS),
            max_concurrent=2,
            platform="linux",
            exec_timeout=30,
            vault_path=None,
            log_dir=Path(self.tmpdir.name),
        )
        self.logger = mock.Mock()
        self.executor = relay.AutoExecutor(self.config, self.logger)
        self.executor._log_to_vault = mock.Mock()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_legacy_request_launches_fable_5_1_at_xhigh_with_opus_5_subagents(self):
        self.executor.active = 1
        completed = subprocess.CompletedProcess([], 0, stdout="done", stderr="")

        with mock.patch.object(relay, "play_exec_alert"), \
                mock.patch.object(relay, "play_done_alert"), \
                mock.patch.object(relay.shutil, "which", return_value="/test/claude"), \
                mock.patch.object(relay.subprocess, "run", return_value=completed) as run:
            self.executor._run({"body": "test task", "model": "sonnet", "from": "dawn"})

        cmd = run.call_args.args[0]
        env = run.call_args.kwargs["env"]
        self.assertEqual(cmd[cmd.index("--model") + 1], relay.PRIMARY_MODEL)
        self.assertEqual(cmd[cmd.index("--effort") + 1], "xhigh")
        self.assertEqual(cmd[cmd.index("--settings") + 1], '{"ultracode":true}')
        self.assertEqual(cmd[cmd.index("--fallback-model") + 1], relay.FALLBACK_MODEL)
        self.assertEqual(env["CLAUDE_CODE_SUBAGENT_MODEL"], relay.FALLBACK_MODEL)
        self.assertEqual(self.executor.active, 0)

    def test_unknown_request_is_rejected_before_launch(self):
        self.executor.active = 1

        with mock.patch.object(relay.subprocess, "run") as run:
            self.executor._run({"body": "test task", "model": "gpt-5.6", "from": "dawn"})

        run.assert_not_called()
        self.logger.warning.assert_called_once()
        self.assertEqual(self.executor.active, 0)

    def test_opus_5_request_has_no_additional_fallback(self):
        self.executor.active = 1
        completed = subprocess.CompletedProcess([], 0, stdout="done", stderr="")

        with mock.patch.object(relay, "play_exec_alert"), \
                mock.patch.object(relay, "play_done_alert"), \
                mock.patch.object(relay.shutil, "which", return_value="/test/claude"), \
                mock.patch.object(relay.subprocess, "run", return_value=completed) as run:
            self.executor._run({"body": "test task", "model": "opus", "from": "dawn"})

        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("--model") + 1], relay.FALLBACK_MODEL)
        self.assertNotIn("--fallback-model", cmd)
        self.assertEqual(self.executor.active, 0)


class CliModelInvariantTests(unittest.TestCase):
    def test_legacy_cli_model_is_sent_as_canonical_model(self):
        with mock.patch.object(relay, "_uds_request", return_value={"delivery": {"method": "tcp"}}) as request:
            relay.cli_send_via_daemon(
                "/tmp/test-relay.sock",
                "day",
                "test task",
                "dawn",
                auto=True,
                model="opus",
            )

        message = request.call_args.args[1]["message"]
        self.assertEqual(message["model"], relay.FALLBACK_MODEL)

    def test_unknown_cli_model_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported model"):
            relay.cli_send_via_daemon(
                "/tmp/test-relay.sock",
                "day",
                "test task",
                "dawn",
                auto=True,
                model="gpt-5.6",
            )


if __name__ == "__main__":
    unittest.main()
