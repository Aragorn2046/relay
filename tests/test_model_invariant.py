import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import relay


def full_capability_report():
    return {
        "ok": True,
        "version": "test-version",
        "parser_smoke_ok": True,
        "supported_flags": [
            *relay.CLAUDE_REQUIRED_FLAGS,
            *relay.CLAUDE_OPTIONAL_FLAGS,
        ],
        "missing_required": [],
        "missing_optional": [],
        "error": None,
    }


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
            "claude-3-5-sonnet-20240620",
            "claude-3-7-sonnet-latest",
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
            "claude-3-opus-20240229",
            "CLAUDE_OPUS_5",
            " opus\n",
            "opus-x",
        )
        for alias in aliases:
            with self.subTest(alias=alias):
                self.assertEqual(relay.normalize_model(alias), relay.FALLBACK_MODEL)

    def test_unknown_and_non_string_names_are_rejected(self):
        for value in (
            "gpt-5.6",
            "claude",
            "anthropic:anthropic:claude-opus-5",
            "vendor-opus-x",
            "claude-sonnet-opus",
            "",
            None,
            5,
            True,
            ["opus"],
            {"model": "opus"},
        ):
            with self.subTest(value=value):
                self.assertIsNone(relay.normalize_model(value))


class ConfigModelInvariantTests(unittest.TestCase):
    def _load_config(self, auto_execute):
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
                "auto_execute": auto_execute,
            }))

            with mock.patch.object(relay, "detect_tailscale_ip", return_value=None):
                return relay.Config(config_path)

    def test_stale_config_is_normalized_without_widening(self):
        config = self._load_config({
            "default_model": "sonnet",
            "allowed_models": ["sonnet", "haiku", "gpt-5.6"],
        })

        self.assertEqual(config.default_model, relay.PRIMARY_MODEL)
        self.assertEqual(config.wire_default_model, "sonnet")
        self.assertEqual(config.allowed_models, [relay.PRIMARY_MODEL])
        self.assertTrue(any("gpt-5.6" in event for _, event in config.model_policy_events))

    def test_explicit_opus_only_allowlist_remains_narrow(self):
        config = self._load_config({
            "default_model": "sonnet",
            "allowed_models": ["claude-opus-5"],
        })

        self.assertEqual(config.allowed_models, [relay.FALLBACK_MODEL])
        self.assertEqual(config.default_model, relay.FALLBACK_MODEL)
        self.assertEqual(config.wire_default_model, "opus")
        self.assertTrue(config.auto_execute_enabled)
        self.assertTrue(any("outside allowed_models" in event for _, event in config.model_policy_events))

    def test_absent_allowlist_uses_the_canonical_pair(self):
        config = self._load_config({"default_model": "sonnet"})

        self.assertEqual(config.allowed_models, list(relay.ALLOWED_MODELS))
        self.assertTrue(config.auto_execute_enabled)

    def test_canonical_default_uses_legacy_wire_alias_until_receivers_are_ready(self):
        config = self._load_config({
            "default_model": relay.PRIMARY_MODEL,
            "allowed_models": list(relay.ALLOWED_MODELS),
        })

        self.assertEqual(config.default_model, relay.PRIMARY_MODEL)
        self.assertEqual(config.wire_default_model, "sonnet")
        self.assertFalse(config.canonical_wire_ready)

    def test_canonical_default_emits_only_after_receiver_readiness_gate(self):
        config = self._load_config({
            "canonical_wire_ready": True,
            "default_model": relay.PRIMARY_MODEL,
            "allowed_models": list(relay.ALLOWED_MODELS),
        })

        self.assertEqual(config.wire_default_model, relay.PRIMARY_MODEL)
        self.assertTrue(config.canonical_wire_ready)

    def test_explicit_empty_allowlist_disables_auto_execution(self):
        config = self._load_config({
            "default_model": "sonnet",
            "allowed_models": [],
        })

        self.assertEqual(config.allowed_models, [])
        self.assertFalse(config.auto_execute_enabled)

    def test_explicit_null_allowlist_disables_auto_execution(self):
        config = self._load_config({
            "default_model": "sonnet",
            "allowed_models": None,
        })

        self.assertEqual(config.allowed_models, [])
        self.assertFalse(config.auto_execute_enabled)

    def test_wholly_invalid_allowlist_disables_auto_execution_with_warning(self):
        config = self._load_config({
            "default_model": "sonnet",
            "allowed_models": ["gpt-5.6", None],
        })

        self.assertEqual(config.allowed_models, [])
        self.assertFalse(config.auto_execute_enabled)
        self.assertTrue(any(
            "auto-execution is disabled" in event
            for level, event in config.model_policy_events
            if level == "warning"
        ))


class ClaudeCapabilityProbeTests(unittest.TestCase):
    def test_probe_uses_only_local_version_and_help_commands(self):
        help_text = " ".join((*relay.CLAUDE_REQUIRED_FLAGS, *relay.CLAUDE_OPTIONAL_FLAGS))
        results = [
            subprocess.CompletedProcess([], 0, stdout="2.1.260 (Claude Code)\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=help_text, stderr=""),
            subprocess.CompletedProcess([], 0, stdout=help_text, stderr=""),
        ]

        with mock.patch.object(relay.subprocess, "run", side_effect=results) as run:
            report = relay.probe_claude_capabilities(
                "/test/claude",
                {
                    "PATH": "/test",
                    "CLAUDE_CODE_SUBAGENT_MODEL": relay.FALLBACK_MODEL,
                },
            )

        self.assertTrue(report["ok"])
        self.assertEqual(report["missing_required"], [])
        self.assertEqual(report["missing_optional"], [])
        self.assertTrue(report["parser_smoke_ok"])
        self.assertEqual(run.call_args_list[0].args[0], ["/test/claude", "--version"])
        self.assertEqual(run.call_args_list[1].args[0], ["/test/claude", "--help"])
        self.assertNotIn(
            "CLAUDE_CODE_SUBAGENT_MODEL",
            run.call_args_list[1].kwargs["env"],
        )
        smoke_cmd = run.call_args_list[2].args[0]
        self.assertEqual(
            run.call_args_list[2].kwargs["env"]["CLAUDE_CODE_SUBAGENT_MODEL"],
            relay.FALLBACK_MODEL,
        )
        self.assertEqual(smoke_cmd[-1], "--help")
        self.assertEqual(smoke_cmd[smoke_cmd.index("--effort") + 1], "xhigh")
        self.assertEqual(
            smoke_cmd[smoke_cmd.index("--fallback-model") + 1],
            relay.FALLBACK_MODEL,
        )
        self.assertEqual(run.call_count, 3)

    def test_missing_optional_flags_do_not_fail_the_probe(self):
        results = [
            subprocess.CompletedProcess([], 0, stdout="test-version", stderr=""),
            subprocess.CompletedProcess(
                [],
                0,
                stdout=" ".join(relay.CLAUDE_REQUIRED_FLAGS),
                stderr="",
            ),
            subprocess.CompletedProcess([], 0, stdout="help", stderr=""),
        ]

        with mock.patch.object(relay.subprocess, "run", side_effect=results) as run:
            report = relay.probe_claude_capabilities("/test/claude", {"PATH": "/test"})

        self.assertTrue(report["ok"])
        self.assertEqual(report["missing_optional"], list(relay.CLAUDE_OPTIONAL_FLAGS))
        smoke_cmd = run.call_args_list[2].args[0]
        self.assertEqual(smoke_cmd[smoke_cmd.index("--effort") + 1], "xhigh")
        self.assertNotIn("--fallback-model", smoke_cmd)

    def test_missing_required_flag_fails_the_probe(self):
        present_flags = [flag for flag in relay.CLAUDE_REQUIRED_FLAGS if flag != "--settings"]
        results = [
            subprocess.CompletedProcess([], 0, stdout="test-version", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=" ".join(present_flags), stderr=""),
            subprocess.CompletedProcess([], 0, stdout=" ".join(present_flags), stderr=""),
            subprocess.CompletedProcess([], 0, stdout=" ".join(present_flags), stderr=""),
            subprocess.CompletedProcess([], 0, stdout=" ".join(present_flags), stderr=""),
        ]

        with mock.patch.object(relay.subprocess, "run", side_effect=results):
            report = relay.probe_claude_capabilities("/test/claude", {"PATH": "/test"})

        self.assertFalse(report["ok"])
        self.assertEqual(report["missing_required"], ["--settings"])

    def test_missing_effort_fails_the_probe(self):
        present_flags = [
            flag for flag in relay.CLAUDE_REQUIRED_FLAGS if flag != "--effort"
        ]
        results = [
            subprocess.CompletedProcess([], 0, stdout="test-version", stderr=""),
            *[
                subprocess.CompletedProcess(
                    [], 0, stdout=" ".join(present_flags), stderr="",
                )
                for _ in range(4)
            ],
        ]

        with mock.patch.object(relay.subprocess, "run", side_effect=results):
            report = relay.probe_claude_capabilities(
                "/test/claude", {"PATH": "/test"},
            )

        self.assertFalse(report["ok"])
        self.assertEqual(report["missing_required"], ["--effort"])

    def test_transient_help_timeout_is_retried(self):
        help_text = " ".join((*relay.CLAUDE_REQUIRED_FLAGS, *relay.CLAUDE_OPTIONAL_FLAGS))
        results = [
            subprocess.CompletedProcess([], 0, stdout="test-version", stderr=""),
            subprocess.TimeoutExpired(["/test/claude", "--help"], 10),
            subprocess.CompletedProcess([], 0, stdout=help_text, stderr=""),
            subprocess.CompletedProcess([], 0, stdout=help_text, stderr=""),
        ]

        with mock.patch.object(relay.subprocess, "run", side_effect=results):
            report = relay.probe_claude_capabilities("/test/claude", {"PATH": "/test"})

        self.assertTrue(report["ok"])
        self.assertTrue(report["parser_smoke_ok"])

    def test_subagent_model_is_forced_to_opus_5(self):
        with mock.patch.dict(
            relay.os.environ,
            {"CLAUDE_CODE_SUBAGENT_MODEL": relay.PRIMARY_MODEL},
        ):
            env, _ = relay.build_claude_environment()

        self.assertEqual(env["CLAUDE_CODE_SUBAGENT_MODEL"], relay.FALLBACK_MODEL)

    def test_failed_capability_result_is_retried_then_success_is_cached(self):
        executor = relay.AutoExecutor(SimpleNamespace(), mock.Mock())
        failure = full_capability_report()
        failure.update({
            "ok": False,
            "parser_smoke_ok": False,
            "error": "transient parser failure",
        })
        success = full_capability_report()

        with mock.patch.object(
            relay,
            "probe_claude_capabilities",
            side_effect=[failure, success],
        ) as probe:
            first = executor._get_claude_capabilities("/test/claude", {"PATH": "/test"})
            second = executor._get_claude_capabilities("/test/claude", {"PATH": "/test"})
            third = executor._get_claude_capabilities("/test/claude", {"PATH": "/test"})

        self.assertFalse(first["ok"])
        self.assertTrue(second["ok"])
        self.assertIs(third, second)
        self.assertEqual(probe.call_count, 2)


class ModelPolicyAuditTests(unittest.TestCase):
    def test_daemon_emits_deferred_config_normalization_events(self):
        logger = mock.Mock()
        config = SimpleNamespace(
            log_dir=Path("/tmp"),
            model_policy_events=[("warning", "dropped unsupported model")],
        )

        with mock.patch.object(relay.RelayDaemon, "_setup_logging", return_value=logger):
            relay.RelayDaemon(config)

        logger.warning.assert_called_once_with(
            "MODEL POLICY: %s",
            "dropped unsupported model",
        )


class DisabledAutoExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_disabled_receiver_refuses_without_starting_worker(self):
        logger = mock.Mock()
        config = SimpleNamespace(
            log_dir=Path("/tmp"),
            model_policy_events=[],
            auto_execute_enabled=False,
        )
        with mock.patch.object(relay.RelayDaemon, "_setup_logging", return_value=logger):
            daemon = relay.RelayDaemon(config)
        daemon.executor = mock.Mock()

        message = {
            "from": "dawn",
            "body": "test task",
            "auto_execute": True,
            "reply_to": "dawn",
        }
        await daemon._process_message(message)

        daemon.executor.execute.assert_not_called()
        daemon.executor._send_result_back.assert_called_once_with(
            message,
            "Relay auto-execution is disabled by receiver policy",
            False,
        )


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
                mock.patch.object(
                    self.executor,
                    "_get_claude_capabilities",
                    return_value=full_capability_report(),
                ), \
                mock.patch.object(relay.subprocess, "run", return_value=completed) as run:
            self.executor._run({"body": "test task", "model": "sonnet", "from": "dawn"})

        cmd = run.call_args.args[0]
        env = run.call_args.kwargs["env"]
        self.assertEqual(cmd[cmd.index("--model") + 1], relay.PRIMARY_MODEL)
        self.assertEqual(cmd[cmd.index("--effort") + 1], "xhigh")
        self.assertEqual(cmd[cmd.index("--settings") + 1], relay.ULTRACODE_SETTINGS)
        self.assertEqual(cmd[cmd.index("--fallback-model") + 1], relay.FALLBACK_MODEL)
        self.assertEqual(env["CLAUDE_CODE_SUBAGENT_MODEL"], relay.FALLBACK_MODEL)
        self.assertNotIn("test task", cmd)
        self.assertEqual(run.call_args.kwargs["input"], "test task")
        self.logger.info.assert_any_call(
            "AUTO-EXEC model normalized from %r to %s for sender %s",
            "sonnet",
            relay.PRIMARY_MODEL,
            "dawn",
        )
        self.assertEqual(self.executor.active, 0)

    def test_unknown_request_is_rejected_before_launch(self):
        self.executor.active = 1
        self.executor._send_result_back = mock.Mock()

        with mock.patch.object(relay.subprocess, "run") as run:
            self.executor._run({
                "body": "test task",
                "model": "gpt-5.6",
                "from": "dawn",
                "reply_to": "dawn",
            })

        run.assert_not_called()
        self.logger.warning.assert_called_once()
        self.executor._send_result_back.assert_called_once()
        self.assertEqual(self.executor.active, 0)

    def test_opus_5_request_has_no_additional_fallback(self):
        self.executor.active = 1
        completed = subprocess.CompletedProcess([], 0, stdout="done", stderr="")

        with mock.patch.object(relay, "play_exec_alert"), \
                mock.patch.object(relay, "play_done_alert"), \
                mock.patch.object(relay.shutil, "which", return_value="/test/claude"), \
                mock.patch.object(
                    self.executor,
                    "_get_claude_capabilities",
                    return_value=full_capability_report(),
                ), \
                mock.patch.object(relay.subprocess, "run", return_value=completed) as run:
            self.executor._run({"body": "test task", "model": "opus", "from": "dawn"})

        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("--model") + 1], relay.FALLBACK_MODEL)
        self.assertNotIn("--fallback-model", cmd)
        self.assertEqual(self.executor.active, 0)

    def test_missing_optional_fallback_degrades_without_changing_models(self):
        self.executor.active = 1
        capabilities = full_capability_report()
        capabilities["missing_optional"] = list(relay.CLAUDE_OPTIONAL_FLAGS)
        completed = subprocess.CompletedProcess([], 0, stdout="done", stderr="")

        with mock.patch.object(relay, "play_exec_alert"), \
                mock.patch.object(relay, "play_done_alert"), \
                mock.patch.object(relay.shutil, "which", return_value="/test/claude"), \
                mock.patch.object(
                    self.executor,
                    "_get_claude_capabilities",
                    return_value=capabilities,
                ), \
                mock.patch.object(relay.subprocess, "run", return_value=completed) as run:
            self.executor._run({
                "body": "test task",
                "model": relay.PRIMARY_MODEL,
                "from": "dawn",
            })

        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("--effort") + 1], "xhigh")
        self.assertNotIn("--fallback-model", cmd)
        self.assertEqual(cmd[cmd.index("--settings") + 1], relay.ULTRACODE_SETTINGS)
        self.assertEqual(cmd[cmd.index("--model") + 1], relay.PRIMARY_MODEL)

    def test_missing_required_flag_fails_visibly_without_model_call(self):
        self.executor.active = 1
        capabilities = full_capability_report()
        capabilities.update({
            "ok": False,
            "missing_required": ["--settings"],
            "error": "missing required flags: --settings",
        })
        self.executor._send_result_back = mock.Mock()

        with mock.patch.object(relay.shutil, "which", return_value="/test/claude"), \
                mock.patch.object(
                    self.executor,
                    "_get_claude_capabilities",
                    return_value=capabilities,
                ), \
                mock.patch.object(relay.subprocess, "run") as run:
            self.executor._run({
                "body": "test task",
                "model": relay.PRIMARY_MODEL,
                "from": "dawn",
                "reply_to": "dawn",
            })

        run.assert_not_called()
        self.executor._send_result_back.assert_called_once()
        self.assertIn("CAPABILITY CHECK FAILED", self.executor._send_result_back.call_args.args[1])
        self.assertEqual(self.executor.active, 0)

    def test_fable_only_allowlist_does_not_enable_automatic_opus_fallback(self):
        self.executor.active = 1
        self.config.allowed_models = [relay.PRIMARY_MODEL]
        completed = subprocess.CompletedProcess([], 0, stdout="done", stderr="")

        with mock.patch.object(relay, "play_exec_alert"), \
                mock.patch.object(relay, "play_done_alert"), \
                mock.patch.object(relay.shutil, "which", return_value="/test/claude"), \
                mock.patch.object(
                    self.executor,
                    "_get_claude_capabilities",
                    return_value=full_capability_report(),
                ), \
                mock.patch.object(relay.subprocess, "run", return_value=completed) as run:
            self.executor._run({
                "body": "test task",
                "model": relay.PRIMARY_MODEL,
                "from": "dawn",
            })

        self.assertNotIn("--fallback-model", run.call_args.args[0])

    def test_option_shaped_task_bodies_are_inert_stdin_text(self):
        completed = subprocess.CompletedProcess([], 0, stdout="done", stderr="")

        for task in ("--version", "--model claude-opus-5"):
            with self.subTest(task=task):
                self.executor.active = 1
                with mock.patch.object(relay, "play_exec_alert"), \
                        mock.patch.object(relay, "play_done_alert"), \
                        mock.patch.object(relay.shutil, "which", return_value="/test/claude"), \
                        mock.patch.object(
                            self.executor,
                            "_get_claude_capabilities",
                            return_value=full_capability_report(),
                        ), \
                        mock.patch.object(
                            relay.subprocess,
                            "run",
                            return_value=completed,
                        ) as run:
                    self.executor._run({
                        "body": task,
                        "model": relay.PRIMARY_MODEL,
                        "from": "dawn",
                    })

                cmd = run.call_args.args[0]
                self.assertNotIn(task, cmd)
                self.assertEqual(run.call_args.kwargs["input"], task)
                self.assertEqual(cmd[cmd.index("--model") + 1], relay.PRIMARY_MODEL)


class CliModelInvariantTests(unittest.TestCase):
    def test_legacy_cli_model_is_validated_but_preserved_on_wire(self):
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
        self.assertEqual(message["model"], "opus")

    def test_explicit_canonical_model_uses_legacy_wire_alias_during_receiver_window(self):
        with mock.patch.object(
            relay,
            "_uds_request",
            return_value={"delivery": {"method": "tcp"}},
        ) as request:
            relay.cli_send_via_daemon(
                "/tmp/test-relay.sock",
                "day",
                "test task",
                "dawn",
                auto=True,
                model=relay.PRIMARY_MODEL,
                model_explicit=True,
            )

        message = request.call_args.args[1]["message"]
        self.assertEqual(message["model"], "sonnet")

    def test_accepted_model_spellings_collapse_to_safe_wire_aliases(self):
        cases = {
            " FABLE ": "sonnet",
            "Anthropic/Claude-Fable-5-1": "sonnet",
            " OPUS ": "opus",
            "anthropic:claude-opus-5": "opus",
        }
        for model, expected in cases.items():
            with self.subTest(model=model), mock.patch.object(
                relay,
                "_uds_request",
                return_value={"delivery": {"method": "tcp"}},
            ) as request:
                relay.cli_send_via_daemon(
                    "/tmp/test-relay.sock",
                    "day",
                    "test task",
                    "dawn",
                    auto=True,
                    model=model,
                    model_explicit=True,
                )
                message = request.call_args.args[1]["message"]
                self.assertEqual(message["model"], expected)

    def test_canonical_config_default_is_allowed_after_receivers_are_upgraded(self):
        with mock.patch.object(
            relay,
            "_uds_request",
            return_value={"delivery": {"method": "tcp"}},
        ) as request:
            relay.cli_send_via_daemon(
                "/tmp/test-relay.sock",
                "day",
                "test task",
                "dawn",
                auto=True,
                model=relay.PRIMARY_MODEL,
                model_explicit=False,
                canonical_wire_ready=True,
            )

        message = request.call_args.args[1]["message"]
        self.assertEqual(message["model"], relay.PRIMARY_MODEL)

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

    def test_main_marks_command_line_model_as_explicit(self):
        config = SimpleNamespace(
            socket_path="/tmp/test-relay.sock",
            default_budget=1.0,
            wire_default_model="sonnet",
            canonical_wire_ready=False,
            machine="dawn",
        )
        argv = [
            "relay.py",
            "send",
            "day",
            "--auto",
            "--model",
            relay.PRIMARY_MODEL,
            "test task",
        ]

        with mock.patch.object(relay, "Config", return_value=config), \
                mock.patch.object(relay, "ALL_MACHINES", ["day"]), \
                mock.patch.object(relay.sys, "argv", argv), \
                mock.patch.object(relay, "cli_send_via_daemon") as send:
            relay.main()

        self.assertTrue(send.call_args.kwargs["model_explicit"])
        self.assertFalse(send.call_args.kwargs["canonical_wire_ready"])


if __name__ == "__main__":
    unittest.main()
