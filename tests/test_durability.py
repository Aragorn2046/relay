"""Durability and replay-protection regressions for the relay daemon."""

import asyncio
import importlib.util
import json
import os
import re
import socket
import struct
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


def test_prune_preserves_young_rows_over_cap_and_enqueue_refuses(tmp_path):
    store = relay.RelayStore(tmp_path / "state")
    try:
        with mock.patch.object(relay, "STORE_MAX_ROWS", 10):
            for msg_id in ("one", "two", "three"):
                enqueue_message(store, msg_id)
                assert store.set_state(msg_id, "done", expected_state="queued")

        with mock.patch.object(relay, "STORE_MAX_ROWS", 2):
            store.prune(now=time.time())
            assert len([store.get(msg_id) for msg_id in ("one", "two", "three")]) == 3
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
