"""Durability and replay-protection regressions for the relay daemon."""

import asyncio
import importlib.util
import json
import os
import re
import socket
import sqlite3
import stat
import struct
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

RELAY = Path(__file__).resolve().parent.parent / "relay.py"
SPEC = importlib.util.spec_from_file_location("relay_durability_under_test", RELAY)
relay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(relay)


SECRET = "test-relay-secret"


@pytest.fixture(autouse=True)
def reset_directory_fsync_warning_flag():
    previous = relay._UNSUPPORTED_DIRECTORY_FSYNC_LOGGED
    relay._UNSUPPORTED_DIRECTORY_FSYNC_LOGGED = False
    try:
        yield
    finally:
        relay._UNSUPPORTED_DIRECTORY_FSYNC_LOGGED = previous


class FakeConfig:
    def __init__(self, root, *, secret=SECRET, enabled=False):
        self.state_dir = Path(root) / "state"
        self.log_dir = Path(root) / "logs"
        self.file_root = Path(root) / "shared"
        self.file_root.mkdir(parents=True, exist_ok=True)
        self.machine = "test-host"
        self.platform = "test"
        self.secret = secret
        self.auto_execute_enabled = enabled
        self.max_concurrent = 2
        self.exec_timeout = 1
        self.max_queue_age = 3600
        self.default_budget = 1.0
        self.max_budget = 2.0
        self.vault_path = None
        self.tailscale_ip = None
        self.port = 7272
        self.socket_path = str(Path(root) / "relay.sock")
        self.other_machines = []

    def _get_file_root(self):
        return self.file_root

    def get_archive_dir(self):
        return self.file_root / "archive"

    def get_my_file_inbox(self):
        return self.file_root / "inbox-test-host"

    def get_file_inbox(self, target):
        return self.file_root / f"inbox-{target}"

    def get_peer_ip(self, target):
        return None

    def get_peer_ssh_user(self, target):
        return None

    def get_remote_relay_path(self, target):
        return None


class FakeReader:
    def __init__(self, data):
        self.data = bytearray(data)

    async def readexactly(self, count):
        if len(self.data) < count:
            raise asyncio.IncompleteReadError(bytes(self.data), count)
        result = bytes(self.data[:count])
        del self.data[:count]
        return result


class FakeWriter:
    def __init__(self):
        self.output = bytearray()
        self.closed = False

    def get_extra_info(self, key):
        return ("127.0.0.1", 12345) if key == "peername" else None

    def write(self, data):
        self.output.extend(data)

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


def decode_response(writer):
    size = struct.unpack("!I", writer.output[:4])[0]
    return json.loads(writer.output[4:4 + size].decode("utf-8"))


def make_daemon(tmp_path, *, secret=SECRET, enabled=False, open_store=True):
    config = FakeConfig(tmp_path, secret=secret, enabled=enabled)
    with mock.patch.object(relay.RelayDaemon, "_setup_logging", return_value=mock.Mock()):
        daemon = relay.RelayDaemon(config)
    if open_store:
        daemon.store = relay.RelayStore(config.state_dir)
        daemon.executor = relay.AutoExecutor(config, daemon.logger, store=daemon.store)
    return daemon


def enqueue_message(store, msg_id, body="hello", *, auto=False):
    message = {"msg_id": msg_id, "from": "sender", "body": body, "auto_execute": auto}
    assert store.enqueue(msg_id, message, "test")
    return message


def signed_message(body="hello"):
    return relay.sign_message({"from": "sender", "to": "test-host", "body": body}, SECRET)


def test_signed_replay_is_deduped_after_restart(tmp_path):
    message = signed_message()
    now = message["timestamp"] + 2
    assert relay.verify_message(message, SECRET, now=now)
    stored = dict(message)
    stored.pop("signature")

    first = relay.RelayStore(tmp_path / "state")
    assert first.enqueue(message["msg_id"], stored, "tcp")
    first.close()

    restarted = relay.RelayStore(tmp_path / "state")
    try:
        assert not restarted.enqueue(message["msg_id"], stored, "tcp")
        assert restarted.get(message["msg_id"])["state"] == "queued"
    finally:
        restarted.close()


def test_uds_cli_repeated_msg_id_is_stored_once(tmp_path, monkeypatch):
    sender = make_daemon(tmp_path / "sender", open_store=False)
    receiver = make_daemon(tmp_path / "receiver")
    receiver.config.machine = "receiver-host"
    sender.config.tailscale_ip = "127.0.0.1"
    sender.config.port = 0
    sender.config.socket_path = str(Path.cwd() / ".relay-test-uds-dedupe.sock")
    monkeypatch.setattr(sender, "watch_file_inbox", lambda: asyncio.Event().wait())
    monkeypatch.setattr(sender, "drain_queued", lambda: asyncio.Event().wait())

    async def send_to_receiver(_target, message):
        signed = relay.sign_message(dict(message), receiver.config.secret)
        writer = FakeWriter()
        request = relay.frame_message(json.dumps(signed).encode("utf-8"))
        await receiver.handle_tcp_client(FakeReader(request), writer)
        response = decode_response(writer)
        return {"method": "tcp", "msg_id": response.get("msg_id")}

    sender._send_to_target = send_to_receiver

    async def exercise():
        run_task = asyncio.create_task(sender.run())
        deadline = time.monotonic() + 3
        while not Path(sender.config.socket_path).exists():
            if time.monotonic() >= deadline:
                raise AssertionError("sender UDS socket did not start")
            await asyncio.sleep(0.01)
        for _ in range(2):
            await asyncio.to_thread(
                relay.cli_send_via_daemon,
                sender.config.socket_path,
                "receiver-host",
                "same message",
                sender.config.machine,
                False,
                1.0,
                None,
                "duplicate-uds-msg-id",
            )
        sender.shutdown_event.set()
        await asyncio.wait_for(run_task, timeout=4)

    try:
        asyncio.run(exercise())
        assert sum(receiver.store.counts().values()) == 1
        row = receiver.store.get("duplicate-uds-msg-id")
        assert row is not None
        assert row["msg_id"] == "duplicate-uds-msg-id"
    finally:
        if sender.store is not None:
            sender.store.close()
        receiver.store.close()


def test_store_full_log_flag_resets_after_successful_tcp_enqueue(tmp_path, monkeypatch):
    daemon = make_daemon(tmp_path)
    try:
        daemon._store_full_logged = True
        monkeypatch.setattr(relay, "play_alert", lambda _platform: None)
        message = signed_message()
        writer = FakeWriter()

        asyncio.run(daemon.handle_tcp_client(
            FakeReader(relay.frame_message(json.dumps(message).encode("utf-8"))), writer
        ))

        assert decode_response(writer)["status"] == "ok"
        assert daemon._store_full_logged is False
    finally:
        daemon.store.close()


def test_interrupted_execution_is_held_and_not_restarted(tmp_path):
    daemon = make_daemon(tmp_path, enabled=True)
    try:
        message = enqueue_message(daemon.store, "interrupted", auto=True)
        assert daemon.store.set_state("interrupted", "executing", expected_state="queued")
        daemon.executor.execute = mock.Mock(side_effect=AssertionError("must not rerun"))

        daemon.recover_interrupted()

        row = daemon.store.get("interrupted")
        assert row["state"] == "held"
        assert row["payload"] == message
        assert row["held_written"] == 1
        assert (daemon.config.state_dir / "held" / "interrupted.json").is_file()
        daemon.executor.execute.assert_not_called()
    finally:
        daemon.store.close()


@pytest.mark.parametrize("enabled", [False, None])
def test_missing_or_false_enabled_holds_auto_without_execution(tmp_path, enabled):
    daemon = make_daemon(tmp_path, enabled=bool(enabled))
    try:
        if enabled is None:
            del daemon.config.auto_execute_enabled
        enqueue_message(daemon.store, "disabled", auto=True)
        daemon._queue_logged.add("disabled")
        daemon.executor.execute = mock.Mock(side_effect=AssertionError("execution must stay disabled"))
        with mock.patch.object(relay.subprocess, "run") as run:
            daemon._dispatch("disabled")
        assert daemon.store.get("disabled")["state"] == "held"
        assert "disabled" not in daemon._queue_logged
        run.assert_not_called()
        daemon.executor.execute.assert_not_called()
    finally:
        daemon.store.close()


@pytest.mark.parametrize("secret", [SECRET, None])
def test_unsigned_file_or_missing_secret_is_rejected(tmp_path, secret):
    daemon = make_daemon(tmp_path, secret=secret)
    try:
        inbox = daemon.config.get_my_file_inbox()
        inbox.mkdir(parents=True, exist_ok=True)
        path = inbox / "unsigned.json"
        path.write_text(json.dumps({"body": "unsigned"}), encoding="utf-8")

        result = asyncio.run(daemon._process_file_message(path))

        assert result == "rejected"
        assert not path.exists()
        host_dir = re.sub(r"[^A-Za-z0-9._-]", "_", socket.gethostname()) or "unknown"
        assert list((daemon.config.file_root / "rejected" / host_dir).glob("unsigned*.json"))
        assert daemon.store.counts() == {}
    finally:
        daemon.store.close()


def test_tcp_and_uds_return_error_without_ack_when_enqueue_raises(tmp_path):
    daemon = make_daemon(tmp_path)
    message = signed_message()
    request = json.dumps(message).encode("utf-8")
    tcp_writer = FakeWriter()
    daemon.store.enqueue = mock.Mock(side_effect=RuntimeError("disk full"))

    asyncio.run(daemon.handle_tcp_client(FakeReader(relay.frame_message(request)), tcp_writer))

    response = decode_response(tcp_writer)
    assert response["status"] == "error"
    assert daemon.stats["tcp_received"] == 0
    assert daemon._queue_logged == set()

    async def enqueue_then_fail(_target, _message):
        daemon.store.enqueue("uds-message", {"body": "hello"}, "uds")

    daemon.store.enqueue = mock.Mock(side_effect=relay.StoreFullError("full"))
    daemon._send_to_target = enqueue_then_fail
    uds_writer = FakeWriter()
    uds_request = relay.frame_and_encode({"cmd": "send", "target": "peer", "message": {"body": "hello"}})
    asyncio.run(daemon.handle_uds_client(FakeReader(uds_request), uds_writer))
    uds_response = decode_response(uds_writer)
    assert uds_response["status"] == "error"
    assert "error" in uds_response
    daemon.store.close()


def test_uds_send_error_is_returned_as_error_response(tmp_path):
    daemon = make_daemon(tmp_path)
    try:
        async def send_error(_target, _message):
            return {"method": "error", "error": "no delivery path"}

        daemon._send_to_target = send_error
        writer = FakeWriter()
        request = relay.frame_and_encode({
            "cmd": "send",
            "target": "peer",
            "message": {"body": "hello"},
        })

        asyncio.run(daemon.handle_uds_client(FakeReader(request), writer))

        response = decode_response(writer)
        assert response["status"] == "error"
        assert response["error"] == "no delivery path"
        assert response["delivery"]["method"] == "error"
    finally:
        daemon.store.close()


def test_worker_start_failure_requeues_with_payload_intact(tmp_path):
    daemon = make_daemon(tmp_path, enabled=True)
    try:
        message = enqueue_message(daemon.store, "start-failure", auto=True)
        with mock.patch.object(relay.threading.Thread, "start", side_effect=RuntimeError("cannot start")):
            daemon._dispatch("start-failure")

        row = daemon.store.get("start-failure")
        assert row["state"] == "queued"
        assert row["payload"] == message
        assert daemon.executor.active == 0
        assert daemon.executor.workers == {}
        assert daemon._worker_start_attempts["start-failure"] == 1
        assert daemon._worker_retry_after["start-failure"] >= time.monotonic() + 4.9
    finally:
        daemon.store.close()


def test_worker_start_retry_uses_backoff_and_logs_once_until_success(tmp_path):
    daemon = make_daemon(tmp_path, enabled=True)
    try:
        enqueue_message(daemon.store, "retry-backoff", auto=True)
        with mock.patch.object(relay.threading.Thread, "start", side_effect=RuntimeError("cannot start")):
            daemon._dispatch("retry-backoff")
        first_retry = daemon._worker_retry_after["retry-backoff"]
        assert first_retry >= time.monotonic() + 4.8

        daemon._worker_retry_after["retry-backoff"] = 0
        with mock.patch.object(relay.threading.Thread, "start", side_effect=RuntimeError("still cannot start")):
            daemon._dispatch("retry-backoff")
        assert daemon._worker_start_attempts["retry-backoff"] == 2
        assert daemon._worker_retry_after["retry-backoff"] >= time.monotonic() + 9.8
        failure_logs = [call for call in daemon.logger.error.call_args_list
                        if "worker could not start for retry-backoff" in str(call)]
        assert len(failure_logs) == 1

        daemon._worker_retry_after["retry-backoff"] = 0
        daemon.executor.execute = mock.Mock(return_value=True)
        daemon._dispatch("retry-backoff")
        assert daemon.store.get("retry-backoff")["state"] == "executing"
        assert "retry-backoff" not in daemon._worker_retry_after
        assert "retry-backoff" not in daemon._worker_start_attempts
        assert "retry-backoff" not in daemon._worker_start_failure_logged
    finally:
        daemon.store.close()


def test_stopping_before_execution_popen_requeues_row(tmp_path):
    daemon = make_daemon(tmp_path, enabled=True)
    try:
        message = enqueue_message(daemon.store, "stopped-before-popen", auto=True)
        original_run = daemon.executor._run

        def stop_before_run(msg, on_done=None):
            daemon.executor.stop_dispatching()
            original_run(msg, on_done)

        daemon.executor._run = stop_before_run
        daemon._dispatch("stopped-before-popen")
        assert daemon.executor.wait_for_workers(2) == []

        row = daemon.store.get("stopped-before-popen")
        assert row["state"] == "queued"
        assert row["payload"] == message
        assert daemon.executor.processes == {}
    finally:
        daemon.store.close()


def test_execution_popen_none_requeues_row(tmp_path, monkeypatch):
    daemon = make_daemon(tmp_path, enabled=True)
    try:
        message = enqueue_message(daemon.store, "popen-none", auto=True)
        monkeypatch.setattr(relay, "resolve_background_route", lambda *_args, **_kwargs: {
            "rows": [("test-model", "")], "source": "test",
        })
        monkeypatch.setattr(relay, "pick_route_row", lambda *_args: ("test-model", "", None))
        monkeypatch.setattr(relay.shutil, "which", lambda *_args, **_kwargs: "/usr/bin/claude")
        monkeypatch.setattr(relay, "build_claude_cmd", lambda *_args, **_kwargs: ["stub-worker"])
        monkeypatch.setattr(relay, "play_exec_alert", lambda _platform: None)
        monkeypatch.setattr(relay.subprocess, "Popen", lambda *_args, **_kwargs: None)

        daemon._dispatch("popen-none")
        assert daemon.executor.wait_for_workers(2) == []
        row = daemon.store.get("popen-none")
        assert row["state"] == "queued"
        assert row["payload"] == message
        assert daemon.executor.processes == {}
    finally:
        daemon.store.close()


def test_dispatch_runtime_error_retries_then_holds_after_five_attempts(tmp_path):
    daemon = make_daemon(tmp_path, enabled=True)
    try:
        enqueue_message(daemon.store, "dispatch-runtime-error", auto=True)
        daemon.executor.execute = mock.Mock(side_effect=RuntimeError("executor bug"))

        for attempt in range(5):
            if attempt:
                with daemon._retry_lock:
                    daemon._worker_retry_after["dispatch-runtime-error"] = 0
            daemon._dispatch("dispatch-runtime-error")

        row = daemon.store.get("dispatch-runtime-error")
        assert row["state"] == "held"
        assert row["held_reason"] == "dispatch-error"
        assert row["payload"]["body"] == "hello"
        errors = [call for call in daemon.logger.error.call_args_list
                  if "dispatch failed for dispatch-runtime-error" in str(call)]
        assert len(errors) == 1
        assert "dispatch-runtime-error" not in daemon._worker_start_attempts
        assert "dispatch-runtime-error" not in daemon._worker_retry_after
        assert "dispatch-runtime-error" not in daemon._worker_start_failure_logged
    finally:
        daemon.store.close()


def test_operational_dispatch_exception_requeues_with_backoff(tmp_path):
    daemon = make_daemon(tmp_path, enabled=True)
    try:
        message = enqueue_message(daemon.store, "dispatch-operational-error", auto=True)
        daemon.executor.execute = mock.Mock(side_effect=sqlite3.OperationalError("database busy"))

        daemon._dispatch("dispatch-operational-error")

        row = daemon.store.get("dispatch-operational-error")
        assert row["state"] == "queued"
        assert row["payload"] == message
        assert daemon._worker_start_attempts["dispatch-operational-error"] == 1
        assert daemon._worker_retry_after["dispatch-operational-error"] >= time.monotonic() + 4.9
    finally:
        daemon.store.close()


def test_pruning_clears_retry_bookkeeping_for_removed_rows(tmp_path):
    daemon = make_daemon(tmp_path)
    try:
        enqueue_message(daemon.store, "pruned-retry")
        assert daemon.store.set_state("pruned-retry", "done", expected_state="queued")
        daemon._record_worker_start_failure("pruned-retry")
        with daemon.store.lock:
            daemon.store.connection.execute(
                "UPDATE messages SET received_at = ? WHERE msg_id = ?",
                (time.time() - relay.DEDUP_TTL - 1, "pruned-retry"),
            )
            daemon.store.connection.commit()

        daemon._prune_store()

        assert daemon.store.get("pruned-retry") is None
        assert "pruned-retry" not in daemon._worker_start_attempts
        assert "pruned-retry" not in daemon._worker_retry_after
        assert "pruned-retry" not in daemon._worker_start_failure_logged
    finally:
        daemon.store.close()


def test_shutdown_waits_for_worker_completion_callback(tmp_path):
    daemon = make_daemon(tmp_path, enabled=True)
    callback_started = threading.Event()
    finish_callback = threading.Event()

    def finish_worker(_message, on_done):
        callback_started.set()
        finish_callback.wait(timeout=2)
        on_done(True)

    try:
        enqueue_message(daemon.store, "finishing", auto=True)
        daemon.executor._run = finish_worker
        daemon._dispatch("finishing")
        assert callback_started.wait(timeout=1)

        daemon._closing = True
        daemon.executor.stop_dispatching()
        assert daemon.executor.wait_for_workers(0) == ["finishing"]

        finish_callback.set()
        assert daemon.executor.wait_for_workers(1) == []
        assert daemon.store.get("finishing")["state"] == "done"
    finally:
        finish_callback.set()
        daemon.store.close()


def test_killed_worker_stays_executing_for_startup_recovery(tmp_path, monkeypatch):
    daemon = make_daemon(tmp_path, enabled=True)
    try:
        message = enqueue_message(daemon.store, "killed-worker", auto=True)
        monkeypatch.setattr(relay, "resolve_background_route", lambda _logger, **_kwargs: {
            "rows": [("test-model", "")],
            "source": "test",
        })
        monkeypatch.setattr(relay, "pick_route_row", lambda _route, _model: ("test-model", "", None))
        monkeypatch.setattr(relay.shutil, "which", lambda _name, path=None: "/usr/bin/python3")
        monkeypatch.setattr(
            relay,
            "build_claude_cmd",
            lambda *_args, **_kwargs: [
                "/usr/bin/python3",
                "-c",
                "import signal,time; signal.signal(signal.SIGTERM, lambda *_: None); time.sleep(60)",
            ],
        )
        monkeypatch.setattr(relay, "play_exec_alert", lambda _platform: None)
        monkeypatch.setattr(relay, "play_done_alert", lambda _platform: None)

        daemon._dispatch("killed-worker")
        deadline = time.monotonic() + 2
        while not daemon.executor.processes and time.monotonic() < deadline:
            time.sleep(0.01)
        assert daemon.executor.processes

        daemon.executor.stop_dispatching()
        assert daemon.executor.wait_for_workers(0.01) == ["killed-worker"]
        daemon.executor.terminate_remaining_processes(grace_period=0)
        assert daemon.executor.wait_for_workers(None) == []
        assert daemon.store.get("killed-worker")["payload"] == message
        assert daemon.store.get("killed-worker")["state"] == "executing"

        daemon._closing = False
        daemon.recover_interrupted()
        assert daemon.store.get("killed-worker")["state"] == "held"
        assert daemon.store.get("killed-worker")["payload"] == message
        assert message["body"] == "hello"
    finally:
        daemon.store.close()


def test_run_shutdown_releases_lock_with_live_stub_worker(tmp_path, monkeypatch):
    daemon = make_daemon(tmp_path, enabled=True, open_store=False)
    daemon.config.tailscale_ip = "127.0.0.1"
    worker_started = threading.Event()
    child_stopped = threading.Event()
    popen_kwargs = []

    class FakeServer:
        def close(self):
            return None

        async def wait_closed(self):
            return None

    class StubProcess:
        pid = 424242

        def __init__(self):
            self.returncode = None

        def poll(self):
            return self.returncode

        def communicate(self, timeout=None):
            worker_started.set()
            if child_stopped.wait(timeout):
                self.returncode = -relay.signal.SIGTERM
                return "", ""
            raise relay.subprocess.TimeoutExpired("stub-worker", timeout)

        def wait(self, timeout=None):
            if child_stopped.wait(timeout):
                self.returncode = -relay.signal.SIGTERM
                return self.returncode
            raise relay.subprocess.TimeoutExpired("stub-worker", timeout)

    async def fake_start_server(*_args, **_kwargs):
        return FakeServer()

    async def fake_start_unix_server(*_args, **kwargs):
        Path(kwargs["path"]).touch()
        return FakeServer()

    async def launch_worker():
        message = {
            "msg_id": "shutdown-live-worker",
            "from": "sender",
            "body": "run",
            "auto_execute": True,
        }
        daemon.store.enqueue(message["msg_id"], message, "test")
        daemon._dispatch(message["msg_id"])
        assert await asyncio.wait_for(asyncio.to_thread(worker_started.wait), timeout=2)
        daemon.shutdown_event.set()

    async def idle_drain():
        await asyncio.Event().wait()

    def fake_popen(_cmd, **kwargs):
        popen_kwargs.append(kwargs)
        return StubProcess()

    monkeypatch.setattr(relay.asyncio, "start_server", fake_start_server)
    monkeypatch.setattr(relay.asyncio, "start_unix_server", fake_start_unix_server)
    monkeypatch.setattr(daemon, "watch_file_inbox", launch_worker)
    monkeypatch.setattr(daemon, "drain_queued", idle_drain)
    monkeypatch.setattr(relay, "resolve_background_route", lambda *_args, **_kwargs: {
        "rows": [("test-model", "")], "source": "test",
    })
    monkeypatch.setattr(relay, "pick_route_row", lambda *_args: ("test-model", "", None))
    monkeypatch.setattr(relay.shutil, "which", lambda *_args, **_kwargs: "/usr/bin/claude")
    monkeypatch.setattr(relay, "build_claude_cmd", lambda *_args, **_kwargs: ["stub-worker"])
    monkeypatch.setattr(relay, "play_exec_alert", lambda _platform: None)
    monkeypatch.setattr(relay.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(relay.os, "killpg", lambda _pid, _sig: child_stopped.set())

    try:
        started_at = time.monotonic()
        asyncio.run(daemon.run())
        elapsed = time.monotonic() - started_at

        assert elapsed < 18
        assert popen_kwargs and all(item.get("start_new_session") is True for item in popen_kwargs)
        assert daemon.store is None
        assert daemon._lock_fd is None
        assert daemon.executor.wait_for_workers(0) == []

        second = make_daemon(tmp_path, open_store=False)
        recovered = relay.RelayStore(daemon.config.state_dir)
        try:
            row = recovered.get("shutdown-live-worker")
            assert row["state"] == "executing"
            assert row["payload"] == {
                "msg_id": "shutdown-live-worker",
                "from": "sender",
                "body": "run",
                "auto_execute": True,
            }
        finally:
            recovered.close()
        assert second._acquire_instance_lock()
        second._release_instance_lock()
    finally:
        if daemon.store is not None:
            daemon.store.close()
        daemon._release_instance_lock()


def test_shutdown_persists_blocked_reply_and_startup_resends_once(tmp_path, monkeypatch):
    daemon = make_daemon(tmp_path, enabled=True)
    message = {
        "msg_id": "reply-pending-case",
        "from": "sender",
        "body": "hello",
        "auto_execute": True,
        "reply_to": "sender",
    }
    daemon.store.enqueue(message["msg_id"], message, "test")
    reply_started = threading.Event()
    reply_stopped = threading.Event()
    popen_kwargs = []

    class SuccessfulExecution:
        pid = 434343
        returncode = 0

        def poll(self):
            return self.returncode

        def communicate(self, timeout=None):
            return "child result", ""

    class BlockingReply:
        pid = 434344

        def __init__(self):
            self.returncode = None

        def poll(self):
            return self.returncode

        def communicate(self, timeout=None):
            reply_started.set()
            if reply_stopped.wait(timeout):
                self.returncode = -relay.signal.SIGTERM
                return "", ""
            raise relay.subprocess.TimeoutExpired("stub-reply", timeout)

        def wait(self, timeout=None):
            if reply_stopped.wait(timeout):
                self.returncode = -relay.signal.SIGTERM
                return self.returncode
            raise relay.subprocess.TimeoutExpired("stub-reply", timeout)

    class SuccessfulReply:
        pid = 434345
        returncode = 0

        def poll(self):
            return self.returncode

        def communicate(self, timeout=None):
            return "sent", ""

    def fake_popen(cmd, **kwargs):
        popen_kwargs.append((cmd, kwargs))
        if len(popen_kwargs) == 1:
            return SuccessfulExecution()
        return BlockingReply()

    monkeypatch.setattr(relay, "resolve_background_route", lambda *_args, **_kwargs: {
        "rows": [("test-model", "")], "source": "test",
    })
    monkeypatch.setattr(relay, "pick_route_row", lambda *_args: ("test-model", "", None))
    monkeypatch.setattr(relay.shutil, "which", lambda *_args, **_kwargs: "/usr/bin/claude")
    monkeypatch.setattr(relay, "build_claude_cmd", lambda *_args, **_kwargs: ["stub-execution"])
    monkeypatch.setattr(relay, "play_exec_alert", lambda _platform: None)
    monkeypatch.setattr(relay, "play_done_alert", lambda _platform: None)
    monkeypatch.setattr(relay.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(relay.os, "killpg", lambda _pid, _sig: reply_stopped.set())

    try:
        daemon._dispatch(message["msg_id"])
        assert reply_started.wait(timeout=2)
        assert daemon.store.get(message["msg_id"])["state"] == "done"

        daemon.executor.stop_dispatching()
        daemon.executor.terminate_remaining_processes(grace_period=0, reap_timeout=1)
        assert daemon.executor.wait_for_workers(2) == []

        pending_path = daemon.config.state_dir / "held" / "reply-pending-case.reply-pending.json"
        pending = json.loads(pending_path.read_text(encoding="utf-8"))
        assert pending["result"] == "child result"
        assert pending["success"] is True
        assert pending["attempts"] == 1
        assert set(pending) == {"msg_id", "from", "result", "success", "attempts"}
        assert all(kwargs.get("start_new_session") is True for _cmd, kwargs in popen_kwargs)
        daemon.store.close()

        retry_daemon = make_daemon(tmp_path, open_store=False)
        retry_daemon.config.tailscale_ip = "127.0.0.1"
        retried_commands = []
        startup_events = []
        reply_started = threading.Event()

        class RetryServer:
            def close(self):
                return None

            async def wait_closed(self):
                return None

        async def retry_start_server(*_args, **_kwargs):
            startup_events.append("tcp")
            return RetryServer()

        async def retry_start_unix_server(*_args, **kwargs):
            startup_events.append("uds")
            Path(kwargs["path"]).touch()
            return RetryServer()

        async def stop_retry_run():
            assert await asyncio.wait_for(asyncio.to_thread(reply_started.wait), timeout=2)
            retry_daemon.shutdown_event.set()

        async def idle_retry_drain():
            await asyncio.Event().wait()

        def successful_popen(cmd, **kwargs):
            startup_events.append("reply")
            reply_started.set()
            retried_commands.append((cmd, kwargs))
            return SuccessfulReply()

        monkeypatch.setattr(relay.subprocess, "Popen", successful_popen)
        monkeypatch.setattr(relay.asyncio, "start_server", retry_start_server)
        monkeypatch.setattr(relay.asyncio, "start_unix_server", retry_start_unix_server)
        monkeypatch.setattr(retry_daemon, "watch_file_inbox", stop_retry_run)
        monkeypatch.setattr(retry_daemon, "drain_queued", idle_retry_drain)
        asyncio.run(retry_daemon.run())

        assert len(retried_commands) == 1
        assert "send" in retried_commands[0][0]
        assert "child result" in retried_commands[0][0][-1]
        assert retried_commands[0][0][4] == "--msg-id"
        assert retried_commands[0][0][5] == relay._reply_msg_id(
            retry_daemon.config.machine, message["msg_id"]
        )
        assert retried_commands[0][1]["start_new_session"] is True
        assert startup_events.index("tcp") < startup_events.index("reply")
        assert startup_events.index("uds") < startup_events.index("reply")
        assert not pending_path.exists()
    finally:
        if daemon.store is not None:
            daemon.store.close()
        daemon._release_instance_lock()


def test_startup_resend_runs_off_loop_and_keeps_uds_responsive(tmp_path, monkeypatch):
    daemon = make_daemon(tmp_path, open_store=False)
    daemon.config.tailscale_ip = "127.0.0.1"
    daemon.config.port = 0
    daemon.config.socket_path = str(Path.cwd() / ".relay-test-uds-resend.sock")
    pending_path = daemon.executor._persist_reply_pending(
        {"msg_id": "uds-resend-live", "from": "sender", "body": "task"},
        "result",
        True,
    )
    resend_started = threading.Event()
    helper_uds_completed = threading.Event()
    allow_resend_to_finish = threading.Event()
    resend_finished = threading.Event()
    resend_thread_ids = []

    async def idle():
        await asyncio.Event().wait()

    def send_result_via_uds(_message, _result, _success):
        resend_thread_ids.append(threading.get_ident())
        resend_started.set()
        response = relay._uds_request(
            daemon.config.socket_path,
            {"cmd": "health"},
            timeout=2.0,
        )
        if not response or response.get("status") != "ok":
            return relay.ReplySendResult(delivered=False, started=True)
        helper_uds_completed.set()
        if not allow_resend_to_finish.wait(timeout=3):
            return relay.ReplySendResult(delivered=False, started=True)
        resend_finished.set()
        return relay.ReplySendResult(delivered=True, started=True)

    daemon.executor._send_result_back = send_result_via_uds
    monkeypatch.setattr(daemon, "watch_file_inbox", idle)
    monkeypatch.setattr(daemon, "drain_queued", idle)

    async def ask_health():
        reader, writer = await asyncio.open_unix_connection(daemon.config.socket_path)
        writer.write(relay.frame_and_encode({"cmd": "health"}))
        await writer.drain()
        response = json.loads(await relay.read_framed(reader, timeout=2.0))
        writer.close()
        await writer.wait_closed()
        return response

    async def exercise():
        loop_thread_id = threading.get_ident()
        run_task = asyncio.create_task(daemon.run())
        deadline = time.monotonic() + 3
        while not Path(daemon.config.socket_path).exists():
            if time.monotonic() >= deadline:
                raise AssertionError("daemon UDS socket did not start")
            await asyncio.sleep(0.01)

        assert await asyncio.wait_for(asyncio.to_thread(resend_started.wait), timeout=2)
        assert await asyncio.wait_for(asyncio.to_thread(helper_uds_completed.wait), timeout=2)
        assert resend_thread_ids[0] != loop_thread_id
        response = await ask_health()
        assert response["status"] == "ok"

        allow_resend_to_finish.set()
        assert await asyncio.wait_for(asyncio.to_thread(resend_finished.wait), timeout=2)
        deadline = time.monotonic() + 2
        while pending_path.exists():
            if time.monotonic() >= deadline:
                raise AssertionError("resend did not remove the delivered pending record")
            await asyncio.sleep(0.01)
        daemon.shutdown_event.set()
        await asyncio.wait_for(run_task, timeout=4)

    try:
        asyncio.run(exercise())
    finally:
        if daemon.store is not None:
            daemon.store.close()
        daemon._release_instance_lock()


def test_child_finishing_during_graceful_shutdown_reports_done_and_persists_reply(tmp_path, monkeypatch):
    daemon = make_daemon(tmp_path, enabled=True, open_store=False)
    daemon.config.tailscale_ip = "127.0.0.1"
    daemon.config.port = 0
    daemon.config.socket_path = str(Path.cwd() / ".relay-test-uds-shutdown.sock")
    child_started = threading.Event()
    uds_closed = threading.Event()
    completion_lock_checks = []
    real_start_unix_server = relay.asyncio.start_unix_server
    original_call_on_done = daemon.executor._call_on_done

    class ClosingSignalServer:
        def __init__(self, server):
            self.server = server

        def close(self):
            self.server.close()
            uds_closed.set()

        async def wait_closed(self):
            await self.server.wait_closed()

    class SuccessfulOnUdsClose:
        pid = 515151

        def __init__(self):
            self.returncode = None

        def poll(self):
            return self.returncode

        def communicate(self, timeout=None):
            child_started.set()
            if not uds_closed.wait(timeout):
                raise relay.subprocess.TimeoutExpired("stub-worker", timeout)
            self.returncode = 0
            return "child finished", ""

        def wait(self, timeout=None):
            if not uds_closed.wait(timeout):
                raise relay.subprocess.TimeoutExpired("stub-worker", timeout)
            self.returncode = 0
            return 0

    async def tracking_start_unix_server(*args, **kwargs):
        server = await real_start_unix_server(*args, **kwargs)
        return ClosingSignalServer(server)

    async def launch_worker():
        message = {
            "msg_id": "graceful-completion",
            "from": "sender",
            "body": "run",
            "auto_execute": True,
            "reply_to": "sender",
        }
        daemon.store.enqueue(message["msg_id"], message, "test")
        daemon._dispatch(message["msg_id"])
        await asyncio.Event().wait()

    async def idle():
        await asyncio.Event().wait()

    def check_unlocked_callback(on_done, success):
        acquired = daemon.executor.lock.acquire(blocking=False)
        completion_lock_checks.append(acquired)
        if acquired:
            daemon.executor.lock.release()
        return original_call_on_done(on_done, success)

    monkeypatch.setattr(relay.asyncio, "start_unix_server", tracking_start_unix_server)
    monkeypatch.setattr(daemon, "watch_file_inbox", launch_worker)
    monkeypatch.setattr(daemon, "drain_queued", idle)
    monkeypatch.setattr(relay, "resolve_background_route", lambda *_args, **_kwargs: {
        "rows": [("test-model", "")], "source": "test",
    })
    monkeypatch.setattr(relay, "pick_route_row", lambda *_args: ("test-model", "", None))
    monkeypatch.setattr(relay.shutil, "which", lambda *_args, **_kwargs: "/usr/bin/claude")
    monkeypatch.setattr(relay, "build_claude_cmd", lambda *_args, **_kwargs: ["stub-worker"])
    monkeypatch.setattr(relay, "play_exec_alert", lambda _platform: None)
    monkeypatch.setattr(relay.subprocess, "Popen", lambda *_args, **_kwargs: SuccessfulOnUdsClose())
    daemon.executor._call_on_done = check_unlocked_callback

    async def exercise():
        run_task = asyncio.create_task(daemon.run())
        assert await asyncio.wait_for(asyncio.to_thread(child_started.wait), timeout=3)
        daemon.shutdown_event.set()
        await asyncio.wait_for(run_task, timeout=5)

    try:
        asyncio.run(exercise())
        assert uds_closed.is_set()
        assert completion_lock_checks == [True]
        pending_path = daemon.config.state_dir / "held" / "graceful-completion.reply-pending.json"
        pending = json.loads(pending_path.read_text(encoding="utf-8"))
        assert pending["result"] == "child finished"
        assert pending["success"] is True
        reopened = relay.RelayStore(daemon.config.state_dir)
        try:
            assert reopened.get("graceful-completion")["state"] == "done"
        finally:
            reopened.close()
    finally:
        if daemon.store is not None:
            daemon.store.close()
        daemon._release_instance_lock()


def test_pending_reply_deadletters_after_three_started_attempts(tmp_path):
    daemon = make_daemon(tmp_path, open_store=False)
    original = {"msg_id": "retry-limit", "from": "sender", "body": "task"}
    pending_path = daemon.executor._persist_reply_pending(original, "result", True)
    started_failure = relay.ReplySendResult(delivered=False, started=True)
    daemon.executor._send_result_back = mock.Mock(return_value=started_failure)
    for expected_attempts in (1, 2):
        daemon.executor.resend_pending_replies()
        record = json.loads(pending_path.read_text(encoding="utf-8"))
        assert record["attempts"] == expected_attempts

    daemon.executor.resend_pending_replies()
    dead_path = daemon.config.state_dir / "held" / "retry-limit.reply-dead.json"
    dead = json.loads(dead_path.read_text(encoding="utf-8"))
    assert dead["attempts"] == 3
    assert not pending_path.exists()
    assert daemon.executor._send_result_back.call_count == 3


def test_invalid_pending_reply_is_dead_lettered(tmp_path):
    daemon = make_daemon(tmp_path, open_store=False)
    held_dir = daemon.config.state_dir / "held"
    held_dir.mkdir(parents=True)
    pending_path = held_dir / "invalid-pending.reply-pending.json"
    pending_path.write_text('{"msg_id": "invalid-pending", "attempts": -1}', encoding="utf-8")

    daemon.executor.resend_pending_replies()

    assert not pending_path.exists()
    assert (held_dir / "invalid-pending.reply-dead.json").is_file()
    assert "Dead-lettered invalid pending AUTO-EXEC reply" in str(daemon.logger.error.call_args)


def test_pending_reply_whose_helper_cannot_start_is_dead_lettered(tmp_path):
    daemon = make_daemon(tmp_path, open_store=False)
    original = {"msg_id": "no-helper-start", "from": "sender", "body": "task"}
    pending_path = daemon.executor._persist_reply_pending(original, "result", True)
    daemon.executor._send_result_back = mock.Mock(
        return_value=relay.ReplySendResult(delivered=False, started=False)
    )

    daemon.executor.resend_pending_replies()

    dead_path = daemon.config.state_dir / "held" / "no-helper-start.reply-dead.json"
    assert not pending_path.exists()
    assert dead_path.is_file()
    daemon.executor._send_result_back.assert_called_once()


def test_missing_original_msg_id_is_rejected_for_reply_and_persistence(tmp_path):
    daemon = make_daemon(tmp_path, open_store=False)
    missing_id = {"from": "sender", "body": "task"}

    assert daemon.executor._persist_reply_pending(missing_id, "result", True) is None
    result = daemon.executor._send_result_back(missing_id, "result", True)

    assert result == relay.ReplySendResult(delivered=False, started=False)
    assert not (daemon.config.state_dir / "held" / "unknown.reply-pending.json").exists()
    assert "Message ID is invalid" in str(daemon.logger.error.call_args_list)


@pytest.mark.parametrize("msg_id", ["..", "../escape", "x" * 129])
def test_invalid_msg_id_cannot_build_held_path(tmp_path, msg_id):
    daemon = make_daemon(tmp_path)
    try:
        with pytest.raises(ValueError, match="Message ID is invalid"):
            daemon._write_held_file(msg_id, {"body": "hello"}, "manual")
        assert not (daemon.config.state_dir / "held").exists()
    finally:
        daemon.store.close()


@pytest.mark.parametrize("body", [None, 7])
def test_poison_body_is_rejected_at_tcp_admission(tmp_path, body):
    daemon = make_daemon(tmp_path)
    try:
        message = signed_message(body)
        request = json.dumps(message).encode("utf-8")
        writer = FakeWriter()

        asyncio.run(daemon.handle_tcp_client(FakeReader(relay.frame_message(request)), writer))

        response = decode_response(writer)
        assert response["status"] == "error"
        assert daemon.store.get(message["msg_id"]) is None
        assert daemon.stats["tcp_received"] == 0
    finally:
        daemon.store.close()


def test_poison_row_is_held_and_does_not_block_next_message(tmp_path, monkeypatch):
    daemon = make_daemon(tmp_path)
    try:
        enqueue_message(daemon.store, "a-poison", body=None)
        enqueue_message(daemon.store, "z-good", body="continue")
        daemon.shutdown_event = asyncio.Event()

        def alert(_platform):
            daemon.shutdown_event.set()

        monkeypatch.setattr(relay, "play_alert", alert)
        monkeypatch.setattr(relay, "FILE_POLL_INTERVAL", 0)
        asyncio.run(daemon.drain_queued())

        poison = daemon.store.get("a-poison")
        assert poison["state"] == "held"
        assert poison["held_reason"] == "dispatch-error"
        assert poison["payload"]["body"] is None
        assert daemon.store.get("z-good")["state"] == "done"
    finally:
        daemon.store.close()


@pytest.mark.parametrize(
    "failure",
    [sqlite3.OperationalError("database busy"), OSError("temporary filesystem error")],
)
def test_transient_dispatch_errors_leave_row_queued(tmp_path, monkeypatch, failure):
    daemon = make_daemon(tmp_path)
    try:
        enqueue_message(daemon.store, "transient-dispatch")
        daemon.shutdown_event = asyncio.Event()

        def fail_dispatch(_msg_id):
            daemon.shutdown_event.set()
            raise failure

        monkeypatch.setattr(daemon, "_dispatch", fail_dispatch)
        monkeypatch.setattr(relay, "FILE_POLL_INTERVAL", 0)
        asyncio.run(daemon.drain_queued())

        assert daemon.store.get("transient-dispatch")["state"] == "queued"
    finally:
        daemon.store.close()


def test_failed_held_file_write_keeps_payload_and_retries_on_drain(tmp_path, monkeypatch):
    daemon = make_daemon(tmp_path, enabled=True)
    try:
        enqueue_message(daemon.store, "hold-retry", auto=True)
        assert daemon.store.set_state("hold-retry", "executing", expected_state="queued")
        with mock.patch.object(daemon, "_write_held_file", side_effect=OSError("disk unavailable")):
            daemon.recover_interrupted()

        row = daemon.store.get("hold-retry")
        assert row["state"] == "held"
        assert row["payload"]["body"] == "hello"
        assert row["held_written"] == 0

        original_write = daemon._write_held_file

        def write_and_stop(*args, **kwargs):
            path = original_write(*args, **kwargs)
            daemon.shutdown_event.set()
            return path

        daemon.shutdown_event = asyncio.Event()
        monkeypatch.setattr(relay, "FILE_POLL_INTERVAL", 0)
        monkeypatch.setattr(daemon, "_write_held_file", write_and_stop)
        asyncio.run(daemon.drain_queued())

        row = daemon.store.get("hold-retry")
        assert row["state"] == "held"
        assert row["payload"]["body"] == "hello"
        assert row["held_written"] == 1
        assert (daemon.config.state_dir / "held" / "hold-retry.json").is_file()
    finally:
        daemon.store.close()


def test_confirmed_held_file_pickup_is_not_recreated_by_drain(tmp_path, monkeypatch):
    daemon = make_daemon(tmp_path)
    try:
        enqueue_message(daemon.store, "picked-up")
        assert daemon._hold_message("picked-up", {"body": "hello"}, "manual")
        row = daemon.store.get("picked-up")
        assert row["held_written"] == 1

        held_path = daemon.config.state_dir / "held" / "picked-up.json"
        held_path.unlink()
        daemon.shutdown_event = asyncio.Event()
        original_ensure = daemon._ensure_held_files
        calls = 0

        def ensure_for_three_drains():
            nonlocal calls
            original_ensure()
            calls += 1
            if calls == 3:
                daemon.shutdown_event.set()

        monkeypatch.setattr(daemon, "_ensure_held_files", ensure_for_three_drains)
        monkeypatch.setattr(relay, "FILE_POLL_INTERVAL", 0)
        asyncio.run(daemon.drain_queued())

        assert calls == 3
        assert not held_path.exists()
        assert daemon.store.get("picked-up")["held_written"] == 1
    finally:
        daemon.store.close()


@pytest.mark.parametrize("has_file", [True, False])
def test_legacy_held_rows_migrate_as_already_picked_up(tmp_path, has_file):
    daemon = make_daemon(tmp_path, open_store=False)
    state_dir = daemon.config.state_dir
    state_dir.mkdir(parents=True, exist_ok=True)
    db_path = state_dir / "relay-state.sqlite3"
    connection = sqlite3.connect(db_path)
    connection.execute("""CREATE TABLE messages (
        msg_id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        state TEXT NOT NULL,
        received_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        payload TEXT
    )""")
    connection.execute(
        "INSERT INTO messages VALUES (?, ?, 'held', ?, ?, ?)",
        ("legacy-held", "test", time.time(), time.time(), json.dumps({"body": "hello"})),
    )
    connection.commit()
    connection.close()

    held_path = state_dir / "held" / "legacy-held.json"
    if has_file:
        held_path.parent.mkdir(parents=True)
        held_path.write_text('{"body": "hello"}', encoding="utf-8")

    daemon.store = relay.RelayStore(state_dir, logger=daemon.logger)
    daemon.executor.store = daemon.store
    try:
        assert daemon.store.get("legacy-held")["held_written"] == 1
        daemon._ensure_held_files()
        assert held_path.exists() is has_file
        if not has_file:
            daemon._ensure_held_files()
            held_warnings = [
                call for call in daemon.logger.warning.call_args_list
                if "Legacy held messages have no pickup file" in str(call)
            ]
            assert len(held_warnings) == 1
            assert "legacy-held" in str(held_warnings[0])

        daemon.store.close()
        daemon.store = relay.RelayStore(state_dir, logger=daemon.logger)
        assert daemon.store.get("legacy-held")["held_written"] == 1
    finally:
        daemon.store.close()


def test_user_version_zero_preserves_and_retries_existing_held_written_column(tmp_path):
    daemon = make_daemon(tmp_path, open_store=False)
    state_dir = daemon.config.state_dir
    state_dir.mkdir(parents=True, exist_ok=True)
    db_path = state_dir / "relay-state.sqlite3"
    connection = sqlite3.connect(db_path)
    connection.execute("""CREATE TABLE messages (
        msg_id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        state TEXT NOT NULL,
        received_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        payload TEXT,
        held_written INTEGER NOT NULL DEFAULT 0,
        held_reason TEXT
    )""")
    connection.execute(
        "INSERT INTO messages VALUES (?, ?, 'held', ?, ?, ?, 0, ?)",
        ("version-zero-held", "test", time.time(), time.time(), json.dumps({"body": "hello"}), "manual"),
    )
    connection.execute("PRAGMA user_version = 0")
    connection.commit()
    connection.close()

    daemon.store = relay.RelayStore(state_dir, logger=daemon.logger)
    daemon.executor.store = daemon.store
    try:
        row = daemon.store.get("version-zero-held")
        assert row["held_written"] == 0
        assert daemon.store.connection.execute("PRAGMA user_version").fetchone()[0] == 2
        held_path = state_dir / "held" / "version-zero-held.json"
        assert not held_path.exists()
        daemon.store.close()
        daemon.store = None
        daemon.executor.store = None

        # run() performs the held-file retry before it checks whether the daemon
        # can bind its configured Tailscale address.
        daemon.config.tailscale_ip = None
        asyncio.run(daemon.run())
        restarted = relay.RelayStore(state_dir)
        try:
            assert held_path.is_file()
            assert restarted.get("version-zero-held")["held_written"] == 1
        finally:
            restarted.close()
    finally:
        if daemon.store is not None:
            daemon.store.close()


def test_directory_fsync_einval_is_accepted_for_inbox_and_held_files(tmp_path, monkeypatch):
    daemon = make_daemon(tmp_path)
    original_fsync = os.fsync

    async def refuse_tcp(*_args, **_kwargs):
        raise ConnectionRefusedError("test fallback")

    def reject_directory_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(relay.errno.EINVAL, "directory fsync unsupported")
        return original_fsync(fd)

    try:
        monkeypatch.setattr(daemon.config, "get_peer_ip", lambda _target: "127.0.0.1")
        monkeypatch.setattr(relay.asyncio, "open_connection", refuse_tcp)
        with mock.patch.object(relay.os, "fsync", side_effect=reject_directory_fsync):
            result = asyncio.run(daemon._send_to_target("peer", {"body": "hello"}))
        assert result["method"] == "file"

        enqueue_message(daemon.store, "held-einval")
        with mock.patch.object(relay.os, "fsync", side_effect=reject_directory_fsync):
            daemon._hold_message("held-einval", {"body": "hello"}, "manual")
        assert daemon.store.get("held-einval")["held_written"] == 1
        fsync_warnings = [call for call in daemon.logger.warning.call_args_list
                          if "Directory fsync is unsupported" in str(call)]
        assert len(fsync_warnings) == 1
    finally:
        daemon.store.close()


@pytest.mark.parametrize(
    "unsupported_errno",
    sorted({relay.errno.EINVAL, relay.errno.ENOTSUP, relay.errno.EOPNOTSUPP}),
)
def test_directory_fsync_only_accepts_documented_unsupported_errnos(tmp_path, unsupported_errno):
    directory = tmp_path / "directory"
    directory.mkdir()
    original_fsync = os.fsync

    def reject_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(unsupported_errno, "directory fsync unsupported")
        return original_fsync(fd)

    with mock.patch.object(relay.os, "fsync", side_effect=reject_directory):
        relay._fsync_directory(directory, logger=mock.Mock())

    with mock.patch.object(relay.os, "open", side_effect=OSError(relay.errno.EINVAL, "open failed")):
        with pytest.raises(OSError, match="open failed"):
            relay._fsync_directory(directory, logger=mock.Mock())


@pytest.mark.parametrize("failure_errno", [relay.errno.EBADF, relay.errno.EPERM, relay.errno.EIO])
def test_directory_fsync_propagates_other_errors(tmp_path, monkeypatch, failure_errno):
    directory = tmp_path / "directory"
    directory.mkdir()

    def reject_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(failure_errno, "directory fsync failed")

    monkeypatch.setattr(relay.os, "fsync", reject_directory)
    with pytest.raises(OSError) as exc_info:
        relay._fsync_directory(directory, logger=mock.Mock())
    assert exc_info.value.errno == failure_errno


def test_held_directory_fsync_eio_keeps_row_unwritten_until_retry(tmp_path):
    daemon = make_daemon(tmp_path)
    original_fsync = os.fsync
    failed = False

    def fail_first_directory_fsync(fd):
        nonlocal failed
        if stat.S_ISDIR(os.fstat(fd).st_mode) and not failed:
            failed = True
            raise OSError(relay.errno.EIO, "directory fsync failed")
        return original_fsync(fd)

    try:
        enqueue_message(daemon.store, "held-eio")
        with mock.patch.object(relay.os, "fsync", side_effect=fail_first_directory_fsync):
            daemon._hold_message("held-eio", {"body": "hello"}, "manual")
        assert failed
        assert daemon.store.get("held-eio")["held_written"] == 0

        daemon._ensure_held_files()
        assert daemon.store.get("held-eio")["held_written"] == 1
    finally:
        daemon.store.close()


def test_prune_preserves_young_rows_over_cap_and_enqueue_refuses(tmp_path):
    store = relay.RelayStore(tmp_path / "state")
    try:
        with mock.patch.object(relay, "STORE_MAX_ROWS", 10):
            for msg_id in ("one", "two", "three"):
                enqueue_message(store, msg_id)
                assert store.set_state(msg_id, "done", expected_state="queued")

        with mock.patch.object(relay, "STORE_MAX_ROWS", 2):
            store.prune(now=time.time())
            for msg_id in ("one", "two", "three"):
                row = store.get(msg_id)
                assert row is not None
                assert row["state"] == "done"
            assert store.connection.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 3
            with pytest.raises(relay.StoreFullError):
                store.enqueue("four", {"body": "new"}, "test")
            assert not store.enqueue("three", {"body": "duplicate"}, "test")
    finally:
        store.close()


def test_held_row_without_confirmed_file_is_never_pruned(tmp_path):
    store = relay.RelayStore(tmp_path / "state")
    try:
        enqueue_message(store, "old-held")
        assert store.set_state("old-held", "held", expected_state="queued", reason="manual")
        with store.lock:
            store.connection.execute(
                "UPDATE messages SET received_at = ? WHERE msg_id = ?",
                (time.time() - relay.DEDUP_TTL - 1, "old-held"),
            )
            store.connection.commit()

        store.prune()

        row = store.get("old-held")
        assert row is not None
        assert row["payload"]["body"] == "hello"
    finally:
        store.close()


def test_old_picked_up_held_row_prunes_even_if_file_is_missing(tmp_path):
    store = relay.RelayStore(tmp_path / "state")
    try:
        enqueue_message(store, "old-picked-up")
        assert store.set_state("old-picked-up", "held", expected_state="queued", reason="manual")
        with store.lock:
            store.connection.execute(
                "UPDATE messages SET held_written = 1, received_at = ? WHERE msg_id = ?",
                (time.time() - relay.DEDUP_TTL - 1, "old-picked-up"),
            )
            store.connection.commit()

        store.prune()

        assert store.get("old-picked-up") is None
    finally:
        store.close()


def test_fresh_partial_file_waits_and_old_garbage_is_quarantined_collision_safely(tmp_path):
    daemon = make_daemon(tmp_path)
    try:
        inbox = daemon.config.get_my_file_inbox()
        inbox.mkdir(parents=True, exist_ok=True)
        fresh = inbox / "partial.json"
        fresh.write_bytes(b'{"body":')
        assert asyncio.run(daemon._process_file_message(fresh)) == "retry"
        assert fresh.exists()

        host_dir = re.sub(r"[^A-Za-z0-9._-]", "_", socket.gethostname()) or "unknown"
        rejected = daemon.config.file_root / "rejected" / host_dir
        rejected.mkdir(parents=True)
        old = inbox / "garbage.json"
        old.write_bytes(b"not-json")
        os.utime(old, (time.time() - relay.FILE_DECODE_GRACE - 1,) * 2)
        (rejected / old.name).write_text("preexisting", encoding="utf-8")

        assert asyncio.run(daemon._process_file_message(old)) == "rejected"
        assert not old.exists()
        quarantined = list(rejected.glob("garbage*.json"))
        assert len(quarantined) == 2
        assert any(path.stem != "garbage" for path in quarantined)
    finally:
        daemon.store.close()


def test_second_instance_exits_without_touching_store(tmp_path):
    first = make_daemon(tmp_path, open_store=False)
    second = make_daemon(tmp_path, open_store=False)
    assert first._acquire_instance_lock()
    first.store = relay.RelayStore(first.config.state_dir)
    first.executor.store = first.store
    enqueue_message(first.store, "before-lock-test")
    paths = [first.store.path, Path(str(first.store.path) + "-wal"), Path(str(first.store.path) + "-shm")]
    before = {path: path.read_bytes() if path.exists() else None for path in paths}

    try:
        with pytest.raises(SystemExit) as exc:
            asyncio.run(second.run())
        assert exc.value.code == 1
        after = {path: path.read_bytes() if path.exists() else None for path in paths}
        assert after == before
        assert second.store is None
    finally:
        first.store.close()
        first._release_instance_lock()


def test_startup_logs_effective_auto_execute_setting_once(tmp_path):
    daemon = make_daemon(tmp_path, enabled=False, open_store=False)
    asyncio.run(daemon.run())
    messages = [args[0] for args, _kwargs in daemon.logger.info.call_args_list
                if args and str(args[0]).startswith("Effective auto_execute.enabled=")]
    assert messages == ["Effective auto_execute.enabled=False"]
    assert daemon.store is None
    assert daemon.executor.store is None
    assert daemon._lock_fd is None


def test_state_transition_compare_and_set_rejects_stale_state(tmp_path):
    store = relay.RelayStore(tmp_path / "state")
    try:
        enqueue_message(store, "cas")
        assert store.set_state("cas", "executing", expected_state="queued")
        assert not store.set_state("cas", "held", expected_state="queued", reason="stale")
        assert store.get("cas")["state"] == "executing"
        assert store.set_state("cas", "done", expected_state="executing")
        assert not store.set_state("cas", "failed", expected_state="executing")
        assert store.get("cas")["state"] == "done"
    finally:
        store.close()


def test_file_sender_writes_only_complete_json_files(tmp_path):
    daemon = make_daemon(tmp_path)
    try:
        inbox = daemon.config.get_file_inbox("peer")
        daemon._write_file_message(inbox, {"body": "complete"})
        files = list(inbox.glob("*.json"))
        assert len(files) == 1
        assert json.loads(files[0].read_text(encoding="utf-8")) == {"body": "complete"}
        assert not list(inbox.glob("*.tmp"))
    finally:
        daemon.store.close()
