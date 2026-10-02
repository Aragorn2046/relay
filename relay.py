#!/usr/bin/env python3
"""Relay daemon — TCP-primary message bus between Dawn, Dusk, and Day.

Unified daemon + CLI. Replaces the old file-based relay.py + relay-watcher.py.

Usage (CLI):
    relay.py send <target> "message"          Send a message
    relay.py send <target> --auto "task"      Send for auto-execution
    relay.py send <target> --auto --budget 2.0 --model <alias> "task"
                                              (no --model: the Model Routing
                                              registry picks, policy background-claude)
    relay.py check                            Check for unread messages
    relay.py read                             Read and archive unread messages
    relay.py status                           Show relay system status
    relay.py history                          Show recent archived messages
    relay.py ping <target>                    Health-check a remote daemon
    relay.py health                           Local daemon health

Usage (daemon):
    relay.py daemon                           Start the relay daemon
"""

import asyncio
import errno
import fcntl
import hashlib
import hmac
import json
import math
import re
import logging
import os
import shutil
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

VERSION = "2.1.2"
DEFAULT_PORT = 7272
MAX_MESSAGE_SIZE = 1_048_576  # 1 MB
HMAC_MAX_AGE = 300.0  # 5 minutes
RATE_LIMIT = 10  # connections per second per IP
FILE_POLL_INTERVAL = 5  # seconds
DEDUP_TTL = 3600.0  # 1 hour
STORE_MAX_ROWS = 200_000
TCP_CONNECT_TIMEOUT = 2.0
TCP_READ_TIMEOUT = 5.0
EXECUTION_TIMEOUT = 300  # 5 minutes
FILE_DECODE_GRACE = 30.0
WORKER_START_FAILED = object()
_UNSUPPORTED_DIRECTORY_FSYNC_ERRNOS = frozenset({
    errno.EINVAL,
    errno.ENOTSUP,
    errno.EOPNOTSUPP,
    errno.EBADF,
    errno.EISDIR,
    errno.EPERM,
})
_UNSUPPORTED_DIRECTORY_FSYNC_LOGGED = False
_UNSUPPORTED_DIRECTORY_FSYNC_LOCK = threading.Lock()

assert DEDUP_TTL >= 2 * HMAC_MAX_AGE, "dedup TTL must cover the full HMAC replay window"

# ── Model routing ──
# Every AUTO-EXEC run follows the Model Routing registry's background-claude
# card, resolved per run by Config/scripts/session-route.py. The relay has no
# model of its own: when the registry cannot be read, session-route returns its
# compiled default and logs it loudly (stderr + ~/.shelby/routing-fallback.jsonl);
# when session-route itself fails, the run is refused, never guessed.
ROUTE_CONSUMER = "background-claude"
ROUTE_TIMEOUT = 15.0
_CLAUDE_LEVELS = ("", "low", "medium", "high", "xhigh", "max")
# Bare aliases older relays put on every AUTO message (their old default).
_LEGACY_DEFAULT_ALIASES = frozenset({"sonnet", "opus", "haiku"})

# ── Machine Detection ──

DEFAULT_MACHINE_MAP = {}
ALL_MACHINES = []  # Populated from config


def detect_machine(machine_map=None):
    """Detect which machine we're running on via hostname lookup."""
    if not machine_map:
        return "unknown"
    hostname = socket.gethostname().upper()
    for pattern, name in machine_map.items():
        if pattern.upper() in hostname:
            return name
    return "unknown"


def detect_platform():
    """Detect OS platform."""
    return "darwin" if sys.platform == "darwin" else "linux"


def detect_tailscale_ip():
    """Get this machine's Tailscale IPv4 address."""
    # WSL2: no Linux tailscale binary, but tailscale.exe via /mnt/c works
    candidates = ["tailscale", "tailscale.exe"]
    for cmd in candidates:
        try:
            result = subprocess.run(
                [cmd, "ip", "-4"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                ip = result.stdout.strip().splitlines()[0].strip() if result.stdout else ""
                if ip.startswith("100."):
                    return ip
        except (FileNotFoundError, PermissionError, OSError, subprocess.TimeoutExpired):
            continue

    # Fallback: parse ip addr for 100.x.x.x (WSL2 mirrored networking)
    try:
        result = subprocess.run(
            ["ip", "addr"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if "inet 100." in line:
                    parts = line.split()
                    for p in parts:
                        if p.startswith("100."):
                            return p.split("/")[0]
    except (FileNotFoundError, PermissionError, OSError, subprocess.TimeoutExpired):
        pass

    # Last resort: use config
    return None


# ── Configuration ──

class Config:
    """Load and provide relay configuration."""

    def __init__(self, config_path=None):
        self.platform = detect_platform()

        # Find config file
        if config_path:
            self.config_path = Path(config_path)
        else:
            self.config_path = Path.home() / ".relay" / "config.json"

        self.data = {}
        if self.config_path.exists():
            with open(self.config_path) as f:
                self.data = json.load(f)

        # Machine detection from config
        machine_map = self.data.get("machine_map", {})
        self.machine = self.data.get("machine") or detect_machine(machine_map)

        # Populate ALL_MACHINES from peers
        global ALL_MACHINES
        self.peers = self.data.get("peers", {})
        ALL_MACHINES = list(self.peers.keys())

        self.port = self.data.get("port", DEFAULT_PORT)
        self.socket_path = self._expand(self.data.get("socket_path", "/tmp/relay.sock"))
        self.log_dir = Path(self._expand(self.data.get("log_dir", "~/logs")))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir = Path(self._expand(self.data.get("state_dir", "~/.shelby/relay")))

        # File fallback paths
        fb = self.data.get("file_fallback", {})
        vault = fb.get("vault_path")
        smb = fb.get("smb_path")
        self.vault_path = Path(vault) if vault else None
        self.smb_path = Path(smb) if smb else None

        # Remote relay paths for SSH fallback delivery (per-peer)
        self.remote_relay_paths = self.data.get("remote_relay_paths", {})

        # Auto-execution config
        ae = self.data.get("auto_execute", {})
        self.auto_execute_enabled = ae.get("enabled") is True
        self.max_concurrent = ae.get("max_concurrent", 2)
        self.exec_timeout = ae.get("timeout", EXECUTION_TIMEOUT)
        self.max_queue_age = ae.get("max_queue_age", 3600)
        # auto_execute.default_model and auto_execute.allowed_models are no
        # longer read: the Model Routing registry decides (resolve_background_route).
        self.default_budget = ae.get("default_budget", 1.0)
        self.max_budget = ae.get("max_budget", 5.0)
        for retired in ("default_model", "allowed_models"):
            if retired in ae:
                print(f"WARNING: auto_execute.{retired} is ignored: the Model Routing registry "
                      f"({ROUTE_CONSUMER}) decides the model", file=sys.stderr, flush=True)

        # Secret
        secret_file = self._expand(self.data.get("secret_file", "~/.relay-secret"))
        self.secret = self._load_secret(secret_file)

        # Tailscale IP
        ts_ip = detect_tailscale_ip()
        config_ip = self.peers.get(self.machine, {}).get("ip")
        self.tailscale_ip = ts_ip or config_ip

        self.other_machines = [m for m in ALL_MACHINES if m != self.machine]

    def _expand(self, path):
        return str(Path(os.path.expanduser(path)))

    def _load_secret(self, path):
        p = Path(path)
        if p.exists():
            mode = p.stat().st_mode & 0o777
            if mode & 0o077:
                print(f"WARNING: Secret file {path} is too permissive ({oct(mode)}). Run: chmod 600 {path}", file=sys.stderr)
            return p.read_text().strip()
        return None

    def get_peer_ip(self, target):
        return self.peers.get(target, {}).get("ip")

    def get_peer_ssh_user(self, target):
        return self.peers.get(target, {}).get("ssh_user")

    def get_remote_relay_path(self, target):
        """Get the remote relay root path for SSH delivery."""
        return self.remote_relay_paths.get(target)

    def get_file_inbox(self, target):
        """Get the file-based inbox path for a target machine."""
        root = self._get_file_root()
        if root:
            return root / f"inbox-{target}"
        return None

    def get_my_file_inbox(self):
        """Get our own file-based inbox for receiving fallback messages."""
        root = self._get_file_root()
        if root:
            return root / f"inbox-{self.machine}"
        return None

    def get_archive_dir(self):
        root = self._get_file_root()
        if root:
            return root / "archive"
        return None

    def _get_file_root(self):
        # Try SMB first (Dawn/Dusk LAN)
        if self.smb_path and self.smb_path.exists():
            try:
                list(self.smb_path.iterdir())
                return self.smb_path
            except (PermissionError, OSError):
                pass
        # Vault fallback
        if self.vault_path and self.vault_path.exists():
            return self.vault_path
        return None


# ── HMAC Authentication ──

def sign_message(payload, secret):
    """Add HMAC-SHA256 signature and metadata to a message."""
    payload["msg_id"] = str(uuid.uuid4())
    payload["timestamp"] = time.time()

    # Canonical serialization (without signature)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signature = hmac.new(
        secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    payload["signature"] = signature
    return payload


def verify_message(message, secret, max_age=HMAC_MAX_AGE, now=None):
    """Verify a signed relay message without changing the caller's object."""
    try:
        if not isinstance(secret, str) or not secret or not isinstance(message, dict):
            return False

        signature = message.get("signature")
        if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
            return False

        timestamp = message.get("timestamp")
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
            return False
        if not math.isfinite(timestamp):
            return False
        now = time.time() if now is None else now
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
            return False
        if isinstance(max_age, bool) or not isinstance(max_age, (int, float)) or not math.isfinite(max_age):
            return False
        if abs(now - timestamp) > max_age:
            return False

        msg_id = message.get("msg_id")
        if not isinstance(msg_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", msg_id):
            return False

        unsigned = dict(message)
        unsigned.pop("signature", None)
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)
    except Exception:
        return False


def validate_inbound_message(message):
    """Reject message bodies that cannot be safely displayed or executed."""
    if not isinstance(message, dict):
        raise ValueError("Message must be a JSON object")
    body = message.get("body", message.get("message", ""))
    if not isinstance(body, str):
        raise ValueError("Message body must be a string")
    if len(body.encode("utf-8")) > MAX_MESSAGE_SIZE:
        raise ValueError("Message body is too large")


class StoreFullError(RuntimeError):
    """Raised when replay-protected rows prevent another durable enqueue."""


# ── Message Framing ──

def frame_message(payload_bytes):
    """4-byte big-endian length prefix + payload."""
    return struct.pack("!I", len(payload_bytes)) + payload_bytes


async def read_framed(reader, timeout=TCP_READ_TIMEOUT):
    """Read a length-prefixed message."""
    header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    length = struct.unpack("!I", header)[0]
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large: {length}")
    data = await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
    return data


def frame_and_encode(msg_dict):
    """Serialize dict to framed bytes."""
    payload = json.dumps(msg_dict).encode("utf-8")
    return frame_message(payload)


def _fsync_directory(path, logger=None):
    """Sync directory metadata, accepting filesystems that do not support it."""
    global _UNSUPPORTED_DIRECTORY_FSYNC_LOGGED
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = None
    try:
        fd = os.open(path, flags)
        os.fsync(fd)
    except OSError as exc:
        if exc.errno not in _UNSUPPORTED_DIRECTORY_FSYNC_ERRNOS:
            raise
        with _UNSUPPORTED_DIRECTORY_FSYNC_LOCK:
            should_log = not _UNSUPPORTED_DIRECTORY_FSYNC_LOGGED
            _UNSUPPORTED_DIRECTORY_FSYNC_LOGGED = True
        if should_log:
            (logger or logging.getLogger("relay")).debug(
                "Directory fsync is unsupported for %s: %s", path, exc
            )
    finally:
        if fd is not None:
            os.close(fd)


# ── Durable message state and deduplication ──

class RelayStore:
    """SQLite-backed queue and replay store shared by the event loop and workers."""

    STATES = frozenset({"queued", "executing", "done", "failed", "held"})
    def __init__(self, state_dir, logger=None):
        self.state_dir = Path(state_dir).expanduser()
        self.logger = logger or logging.getLogger("relay")
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_dir, 0o700)
        self.path = self.state_dir / "relay-state.sqlite3"
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        self.lock = threading.Lock()
        self.connection = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self.connection.row_factory = sqlite3.Row
        with self.lock:
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=FULL")
            self.connection.execute("""CREATE TABLE IF NOT EXISTS messages (
                msg_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                state TEXT NOT NULL,
                received_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                payload TEXT,
                held_written INTEGER NOT NULL DEFAULT 0,
                held_reason TEXT
            )""")
            columns = {row[1] for row in self.connection.execute("PRAGMA table_info(messages)")}
            added_held_written = "held_written" not in columns
            if "held_written" not in columns:
                self.connection.execute(
                    "ALTER TABLE messages ADD COLUMN held_written INTEGER NOT NULL DEFAULT 0"
                )
            if "held_reason" not in columns:
                self.connection.execute("ALTER TABLE messages ADD COLUMN held_reason TEXT")
            self.connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_state_received "
                "ON messages(state, received_at)"
            )
            missing_legacy_files = []
            if added_held_written:
                legacy_held = self.connection.execute(
                    "SELECT msg_id FROM messages WHERE state = 'held' AND held_written = 0"
                ).fetchall()
                missing_legacy_files = [
                    row["msg_id"]
                    for row in legacy_held
                    if not (self.state_dir / "held" / f"{row['msg_id']}.json").is_file()
                ]
                self.connection.execute(
                    "UPDATE messages SET held_written = 1 "
                    "WHERE state = 'held' AND held_written = 0"
                )
            self.connection.commit()
            self._secure_modes()
            if missing_legacy_files:
                self.logger.warning(
                    "Legacy held messages without pickup files treated as picked up: %s",
                    ", ".join(missing_legacy_files),
                )

    def _secure_modes(self):
        for path in (self.path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
            try:
                if path.exists():
                    os.chmod(path, 0o600)
            except OSError:
                pass

    def enqueue(self, msg_id, message_dict, source):
        payload = json.dumps(message_dict, sort_keys=True, separators=(",", ":"))
        now = time.time()
        with self.lock:
            existing = self.connection.execute(
                "SELECT 1 FROM messages WHERE msg_id = ?", (msg_id,)
            ).fetchone()
            if existing:
                return False
            count = self.connection.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
            if count >= STORE_MAX_ROWS:
                self._prune_locked(now)
                count = self.connection.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
            if count >= STORE_MAX_ROWS:
                self.connection.commit()
                self._secure_modes()
                raise StoreFullError(f"relay store is at its {STORE_MAX_ROWS}-row capacity")
            cursor = self.connection.execute(
                "INSERT INTO messages (msg_id, source, state, received_at, updated_at, payload) "
                "VALUES (?, ?, 'queued', ?, ?, ?)",
                (msg_id, source, now, now, payload),
            )
            self.connection.commit()
            self._secure_modes()
            return cursor.rowcount == 1

    def set_state(self, msg_id, state, expected_state, reason=None):
        if state not in self.STATES:
            raise ValueError(f"invalid relay state: {state}")
        transitions = {
            "queued": {"executing", "done", "held"},
            "executing": {"queued", "done", "failed", "held"},
        }
        if state not in transitions.get(expected_state, set()):
            raise ValueError(f"invalid relay transition: {expected_state} -> {state}")
        now = time.time()
        with self.lock:
            if state in ("done", "failed"):
                cursor = self.connection.execute(
                    "UPDATE messages SET state = ?, updated_at = ?, payload = NULL, "
                    "held_written = 0, held_reason = NULL WHERE msg_id = ? AND state = ?",
                    (state, now, msg_id, expected_state),
                )
            elif state == "held":
                cursor = self.connection.execute(
                    "UPDATE messages SET state = ?, updated_at = ?, held_written = 0, held_reason = ? "
                    "WHERE msg_id = ? AND state = ?",
                    (state, now, reason or "held", msg_id, expected_state),
                )
            else:
                cursor = self.connection.execute(
                    "UPDATE messages SET state = ?, updated_at = ?, held_written = 0, held_reason = NULL "
                    "WHERE msg_id = ? AND state = ?",
                    (state, now, msg_id, expected_state),
                )
            self.connection.commit()
            self._secure_modes()
            return cursor.rowcount == 1

    def mark_held_written(self, msg_id):
        with self.lock:
            cursor = self.connection.execute(
                "UPDATE messages SET held_written = 1, updated_at = ? "
                "WHERE msg_id = ? AND state = 'held' AND payload IS NOT NULL",
                (time.time(), msg_id),
            )
            self.connection.commit()
            self._secure_modes()
            return cursor.rowcount == 1

    def get(self, msg_id):
        with self.lock:
            row = self.connection.execute("SELECT * FROM messages WHERE msg_id = ?", (msg_id,)).fetchone()
            return self._decode_row(row)

    def list_state(self, state):
        with self.lock:
            rows = self.connection.execute(
                "SELECT * FROM messages WHERE state = ? ORDER BY received_at ASC, msg_id ASC", (state,)
            ).fetchall()
            return [self._decode_row(row) for row in rows]

    def list_unwritten_held(self):
        """Load only held rows whose pickup file still needs to be written."""
        with self.lock:
            rows = self.connection.execute(
                "SELECT * FROM messages WHERE state = 'held' AND held_written = 0 "
                "ORDER BY received_at ASC, msg_id ASC"
            ).fetchall()
            return [self._decode_row(row) for row in rows]

    def counts(self):
        with self.lock:
            rows = self.connection.execute("SELECT state, COUNT(*) AS count FROM messages GROUP BY state").fetchall()
            return {row["state"]: row["count"] for row in rows}

    def prune(self, now=None):
        now = time.time() if now is None else now
        with self.lock:
            self._prune_locked(now)
            self.connection.commit()
            self._secure_modes()

    def _prune_locked(self, now):
        cutoff = now - DEDUP_TTL
        self.connection.execute(
            "DELETE FROM messages WHERE state IN ('done', 'failed') AND received_at < ?",
            (cutoff,),
        )
        held_rows = self.connection.execute(
            "SELECT msg_id FROM messages "
            "WHERE state = 'held' AND held_written = 1 AND received_at < ? "
            "ORDER BY received_at ASC",
            (cutoff,),
        ).fetchall()
        for row in held_rows:
            self.connection.execute(
                "DELETE FROM messages WHERE msg_id = ? AND state = 'held' "
                "AND received_at < ? AND held_written = 1",
                (row["msg_id"], cutoff),
            )

    def _decode_row(self, row):
        if row is None:
            return None
        item = dict(row)
        item["payload"] = json.loads(item["payload"]) if item["payload"] is not None else None
        return item

    def close(self):
        with self.lock:
            self.connection.close()


# ── Rate Limiting ──

class RateLimiter:
    def __init__(self, max_per_second=RATE_LIMIT):
        self.max = max_per_second
        self.requests = defaultdict(list)

    def allow(self, ip):
        now = time.time()
        self.requests[ip] = [t for t in self.requests[ip] if now - t < 1.0]
        if len(self.requests[ip]) >= self.max:
            return False
        self.requests[ip].append(now)
        return True


# ── Alert Sounds ──

def play_alert(platform):
    """Play message alert sound."""
    try:
        if platform == "darwin":
            subprocess.run(
                ["afplay", "/System/Library/Sounds/Glass.aiff"],
                capture_output=True, timeout=5
            )
        else:
            ps_cmd = (
                "[Console]::Beep(800,150); Start-Sleep -Milliseconds 50; "
                "[Console]::Beep(1000,150); Start-Sleep -Milliseconds 50; "
                "[Console]::Beep(1200,200)"
            )
            subprocess.run(
                ["powershell.exe", "-Command", ps_cmd],
                capture_output=True, timeout=10
            )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass


def play_exec_alert(platform):
    """Play auto-execution starting alert."""
    try:
        if platform == "darwin":
            subprocess.run(
                ["afplay", "/System/Library/Sounds/Purr.aiff"],
                capture_output=True, timeout=5
            )
        else:
            ps_cmd = (
                "[Console]::Beep(600,100); Start-Sleep -Milliseconds 30; "
                "[Console]::Beep(800,100); Start-Sleep -Milliseconds 30; "
                "[Console]::Beep(1000,100); Start-Sleep -Milliseconds 30; "
                "[Console]::Beep(1200,100); Start-Sleep -Milliseconds 30; "
                "[Console]::Beep(1400,150)"
            )
            subprocess.run(
                ["powershell.exe", "-Command", ps_cmd],
                capture_output=True, timeout=10
            )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass


def play_done_alert(platform):
    """Play task completion alert."""
    try:
        if platform == "darwin":
            subprocess.run(
                ["afplay", "/System/Library/Sounds/Ping.aiff"],
                capture_output=True, timeout=5
            )
        else:
            ps_cmd = "[Console]::Beep(1200,150); Start-Sleep -Milliseconds 50; [Console]::Beep(800,200)"
            subprocess.run(
                ["powershell.exe", "-Command", ps_cmd],
                capture_output=True, timeout=10
            )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass


# ── Auto-Execution ──

class RouteRefused(Exception):
    """The registry answered, but with a route these runs must not launch."""


def _session_route_helper():
    override = os.environ.get("SHELBY_SESSION_ROUTE")
    if override:
        return override
    home = Path.home()
    for candidate in (home / "42" / "Config" / "scripts" / "session-route.py",
                      home / "vault" / "Config" / "scripts" / "session-route.py"):
        if candidate.exists():
            return str(candidate)
    return str(home / "42" / "Config" / "scripts" / "session-route.py")


def resolve_background_route(logger=None, timeout=ROUTE_TIMEOUT, process_runner=None):
    """The registry's background-claude card as {rows: [(model, effort)...], source}.

    Raises RouteRefused when the card refuses (helper exit 3), when it has no
    Claude row, or when session-route itself cannot answer: a run is never
    started on a guessed model. A registry that cannot be read is session-route's
    job: it answers with its compiled default and logs that loudly.
    """
    helper = _session_route_helper()
    try:
        runner = process_runner or subprocess.run
        proc = runner(
            [sys.executable, helper, "--consumer", ROUTE_CONSUMER, "--json", "--timeout", str(timeout)],
            capture_output=True, text=True, errors="replace", timeout=timeout + 15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RouteRefused(f"session-route did not answer: {type(exc).__name__}: {exc}") from exc
    if proc is None:
        raise RouteRefused("session-route was not started during shutdown")
    try:
        payload = json.loads(proc.stdout)
    except (ValueError, TypeError):
        payload = None
    if not isinstance(payload, dict):
        first = (proc.stderr or "").strip().splitlines()[:1]
        raise RouteRefused(f"session-route exit {proc.returncode}" + (f": {first[0][:200]}" if first else ""))
    if proc.returncode != 0:
        raise RouteRefused(payload.get("reason") or f"session-route exit {proc.returncode}")
    fallbacks = payload.get("fallbacks") or []
    if not isinstance(fallbacks, list):
        raise RouteRefused("session-route answered with a malformed fallback list")
    if payload.get("route_source") not in ("live", "cache", "default"):
        raise RouteRefused(f"session-route answered with an unknown route source {payload.get('route_source')!r}")
    answer = [payload] + [item for item in fallbacks if isinstance(item, dict)]
    rows = [(item.get("model"), item.get("effort")) for item in answer if item.get("kind") == "claude"]
    skipped = [f"{item.get('kind')}:{item.get('model')}" for item in answer if item.get("kind") != "claude"]
    if skipped and logger is not None:
        logger.info(f"AUTO-EXEC route: {ROUTE_CONSUMER} rows this runtime cannot launch (not Claude), "
                    f"skipped as the card documents: {', '.join(skipped)}")
    # Non-Claude rows are skipped (documented on the card). A Claude row that
    # is not launchable (not a claude-* id, or a level the CLI rejects) is
    # route damage: refuse rather than quietly run a later row.
    for m, e in rows:
        if not (isinstance(m, str) and re.fullmatch(r"claude-[a-z0-9.-]+", m) and (e or "") in _CLAUDE_LEVELS):
            raise RouteRefused(f"the {ROUTE_CONSUMER} card has an unlaunchable Claude row ({m!r} at {e!r})")
    rows = [(m, e or None) for m, e in rows]
    if not rows:
        raise RouteRefused(f"the {ROUTE_CONSUMER} card has no Claude row")
    source = ("compiled default (registry unreadable, logged by session-route)"
              if payload.get("route_source") == "default"
              else f"registry rev {payload.get('revision')} ({payload.get('route_source')})")
    return {"rows": rows, "source": source}


def pick_route_row(route, requested_model=None):
    """(model, effort, fallback_model) for this run. A message may name a model
    only if that model is one of the card's own Claude rows (it then runs at
    that row's effort). The overload fallback is the next LATER row with another
    model at the same level (never a wrap back to an earlier row; rows at
    another level are skipped): the CLI takes one --effort for the whole run."""
    rows = route["rows"]
    index = 0
    if requested_model and requested_model.strip().lower() in _LEGACY_DEFAULT_ALIASES:
        # An older sender stamps its old default alias on every AUTO message:
        # that is no choice at all, so the card's own order applies.
        requested_model = None
    if requested_model:
        matches = [i for i, (model, _) in enumerate(rows) if model == requested_model]
        if not matches:
            raise RouteRefused(f"model {requested_model!r} is not a row on the {ROUTE_CONSUMER} card "
                               f"({', '.join(m for m, _ in rows)})")
        index = matches[0]
    model, effort = rows[index]
    # The first LATER row with another model at this row's level (rows at
    # another level are skipped, never used, never a wrap to an earlier row).
    later = [m for m, e in rows[index + 1:] if m != model and e == effort]
    return model, effort, (later[0] if later else None)


def build_claude_cmd(claude_bin, model, budget, task, effort=None, fallback_model=None):
    cmd = [claude_bin, "--model", model]
    if effort:
        cmd += ["--effort", effort]
    if fallback_model and fallback_model != model:
        cmd += ["--fallback-model", fallback_model]
    return cmd + ["--max-budget-usd", str(budget), "-p", "--", task]


class AutoExecutor:
    def __init__(self, config, logger, store=None):
        self.config = config
        self.logger = logger
        self.store = store
        self.active = 0
        self.lock = threading.Lock()
        self.workers = {}
        self.processes = {}
        self._stopping = False
        self._shutdown_killed = set()

    def can_accept(self):
        with self.lock:
            return not self._stopping and self.active < self.config.max_concurrent

    def _is_admitted(self, msg):
        if self.store is None:
            return True
        msg_id = msg.get("msg_id") if isinstance(msg, dict) else None
        row = self.store.get(msg_id) if isinstance(msg_id, str) else None
        return bool(row and row["state"] == "executing" and row.get("payload") == msg)

    def execute(self, msg, on_done=None):
        """Start an admitted task in a worker; refuse disabled or full queues."""
        if getattr(self.config, "auto_execute_enabled", False) is not True:
            self.logger.warning("AUTO-EXEC disabled (auto_execute.enabled is not true): refusing execution")
            return False
        if not self._is_admitted(msg):
            self.logger.error("AUTO-EXEC refused: message is not durably admitted as executing")
            return False
        with self.lock:
            if self._stopping:
                return False
            if self.active >= self.config.max_concurrent:
                return False
            self.active += 1
            worker = None
            start_error = None
            try:
                worker = threading.Thread(target=self._run, args=(msg, on_done), daemon=True)
                self.workers[worker] = msg.get("msg_id", "(unknown)")
                worker.start()
                return True
            except Exception as exc:
                start_error = exc
                self.active -= 1
                if worker is not None:
                    self.workers.pop(worker, None)
        try:
            self.logger.debug(f"AUTO-EXEC could not start worker: {start_error}")
        except Exception:
            pass
        return WORKER_START_FAILED

    def stop_dispatching(self):
        """Prevent new worker threads and execution subprocesses from starting."""
        with self.lock:
            self._stopping = True

    def _start_worker_process(self, cmd, **kwargs):
        worker = threading.current_thread()
        with self.lock:
            if self._stopping:
                return None
            process = subprocess.Popen(cmd, **kwargs)
            self.processes[worker] = process
            return process

    def _run_worker_process(self, cmd, **kwargs):
        timeout = kwargs.pop("timeout", None)
        kwargs.pop("check", None)
        if kwargs.pop("capture_output", False):
            kwargs.setdefault("stdout", subprocess.PIPE)
            kwargs.setdefault("stderr", subprocess.PIPE)
        worker = threading.current_thread()
        process = self._start_worker_process(cmd, **kwargs)
        if process is None:
            return None
        try:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                try:
                    process.kill()
                except OSError:
                    pass
                stdout, stderr = process.communicate()
                raise subprocess.TimeoutExpired(
                    cmd,
                    timeout,
                    output=stdout if stdout is not None else exc.output,
                    stderr=stderr if stderr is not None else exc.stderr,
                ) from exc
        finally:
            self._forget_worker_process(worker, process)
        return subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)

    def _forget_worker_process(self, worker, process):
        with self.lock:
            if self.processes.get(worker) is process:
                self.processes.pop(worker, None)

    def _worker_was_shutdown_killed(self, worker=None):
        worker = worker or threading.current_thread()
        with self.lock:
            return worker in self._shutdown_killed

    def wait_for_workers(self, timeout):
        """Join active workers for at most timeout seconds and return their IDs."""
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        with self.lock:
            workers = list(self.workers.items())
        for worker, _msg_id in workers:
            if deadline is None:
                worker.join()
            else:
                remaining = max(0.0, deadline - time.monotonic())
                worker.join(remaining)
        with self.lock:
            return [msg_id for worker, msg_id in self.workers.items() if worker.is_alive()]

    def terminate_remaining_processes(self, grace_period=5.0):
        """Terminate and reap worker subprocesses that outlive graceful shutdown."""
        with self.lock:
            processes = list(self.processes.items())

        terminating = []
        for worker, process in processes:
            if process.poll() is not None:
                continue
            with self.lock:
                still_registered = self.processes.get(worker) is process
                if still_registered and process.poll() is None:
                    self._shutdown_killed.add(worker)
                else:
                    still_registered = False
            if not still_registered:
                continue
            try:
                process.terminate()
            except OSError:
                pass
            terminating.append(process)

        deadline = time.monotonic() + max(0.0, grace_period)
        for process in terminating:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                pass

        for process in terminating:
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            process.wait()

    def _call_on_done(self, on_done, success):
        if on_done is None:
            return
        try:
            on_done(success)
        except Exception as exc:
            try:
                self.logger.error(f"AUTO-EXEC completion callback failed: {exc}")
            except Exception:
                pass

    def _run(self, msg, on_done=None):
        success = False
        completion_allowed = True
        worker = threading.current_thread()
        task = ""
        budget = 0.0
        model = "(unknown)"
        try:
            if self._is_stopping():
                completion_allowed = False
                return
            if self.store is not None and getattr(self.config, "auto_execute_enabled", False) is not True:
                self.logger.warning("AUTO-EXEC disabled (auto_execute.enabled is not true): refusing execution")
                return
            if not self._is_admitted(msg):
                self.logger.error("AUTO-EXEC refused: message is not durably admitted as executing")
                return
            task = msg.get("body", msg.get("message", ""))
            budget = min(float(msg.get("budget", self.config.default_budget)), self.config.max_budget)
            explicit_model = msg.get("model")
            # The registry always decides; a message may only pick one of the card's rows.
            try:
                try:
                    route = resolve_background_route(
                        self.logger, process_runner=self._run_worker_process
                    )
                    model, effort, fallback_model = pick_route_row(route, explicit_model)
                except RouteRefused:
                    raise
                except Exception as exc:  # never wedge auto-exec on an unexpected answer
                    raise RouteRefused(f"route could not be read: {type(exc).__name__}: {exc}") from exc
            except RouteRefused as exc:
                if self._is_stopping() or self._worker_was_shutdown_killed(worker):
                    completion_allowed = False
                    return
                reason = f"REFUSED: the Model Routing registry route for {ROUTE_CONSUMER} cannot run: {exc}"
                try:
                    self.logger.error(f"AUTO-EXEC {reason} (task: {task[:80]})")
                    print(f"ERROR: {reason}", file=sys.stderr, flush=True)
                    self._log_to_vault(task, reason, False, 0.0, "(refused)", budget)
                    if msg.get("reply_to"):
                        self._send_result_back(msg, reason, False)
                except Exception as log_exc:  # never leak the concurrency slot
                    try:
                        self.logger.error(f"AUTO-EXEC refusal could not be reported: {log_exc}")
                    except Exception:
                        pass
                return

            route_note = route["source"] + (f", message chose row {model}" if explicit_model else "")
            sender = msg.get("from", "unknown")
            self.logger.info(f"AUTO-EXEC from {sender}: {task[:120]} (model={model}, effort={effort or '-'}, "
                             f"route={route_note}, budget=${budget})")
            if self._is_stopping():
                completion_allowed = False
                return
            play_exec_alert(self.config.platform)
            if self._is_stopping():
                completion_allowed = False
                return

            start = time.time()
            result = ""
            env = os.environ.copy()
            env.pop("CLAUDECODE", None)
            # Daemons spawned outside an interactive shell don't inherit fnm/Homebrew
            # PATH entries, so `claude` isn't resolvable. Prepend common install paths.
            home = Path.home()
            extra_path = ":".join(str(p) for p in [
                home / ".local/share/fnm/aliases/default/bin",
                home / ".local/bin",
                home / ".bun/bin",
                "/opt/homebrew/bin",
                "/usr/local/bin",
            ])
            env["PATH"] = f"{extra_path}:{env.get('PATH', '')}"
            claude_bin = shutil.which("claude", path=env["PATH"])

            try:
                if not claude_bin:
                    raise FileNotFoundError(f"'claude' binary not on PATH. Looked in: {extra_path}")
                cmd = build_claude_cmd(claude_bin, model, budget, task, effort, fallback_model)
                cwd = str(home / "workspace")
                if not Path(cwd).exists():
                    cwd = str(home)

                proc = self._start_worker_process(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    cwd=cwd, env=env
                )
                if proc is None:
                    completion_allowed = False
                    return
                timed_out = False
                try:
                    stdout, stderr = proc.communicate(timeout=self.config.exec_timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    proc.kill()
                    proc.communicate()
                    result = f"TIMEOUT after {self.config.exec_timeout}s"
                finally:
                    self._forget_worker_process(worker, proc)
                if self._worker_was_shutdown_killed(worker):
                    completion_allowed = False
                    return
                if not timed_out:
                    result = stdout or ""
                    if proc.returncode == 0:
                        success = True
                    else:
                        result += f"\nSTDERR: {stderr or '(none)'}"
            except FileNotFoundError as exc:
                result = f"CLAUDE BINARY NOT FOUND: {exc}"
                self.logger.error(f"AUTO-EXEC PATH failure: {exc}")
            except Exception as exc:
                result = f"ERROR: {type(exc).__name__}: {exc}"

            duration = time.time() - start
            status = "SUCCESS" if success else "FAILED"
            self.logger.info(f"AUTO-EXEC {status} ({duration:.0f}s): {task[:80]}")
            try:
                self._log_to_vault(task, result, success, duration, model, budget)
            except Exception as exc:
                self.logger.warning(f"Failed to report execution: {exc}")
            if msg.get("reply_to") and not self._is_stopping():
                try:
                    self._send_result_back(msg, result, success)
                except Exception as exc:
                    self.logger.warning(f"Failed to relay result back: {exc}")
            if not self._is_stopping():
                try:
                    play_done_alert(self.config.platform)
                except Exception as exc:
                    self.logger.warning(f"AUTO-EXEC completion alert failed: {exc}")
        except Exception as exc:
            try:
                self.logger.error(f"AUTO-EXEC unexpected failure: {type(exc).__name__}: {exc}")
            except Exception:
                pass
        finally:
            if completion_allowed and not self._worker_was_shutdown_killed(worker):
                self._call_on_done(on_done, success)
            with self.lock:
                self.active = max(0, self.active - 1)
                self.workers.pop(worker, None)
                self.processes.pop(worker, None)
                self._shutdown_killed.discard(worker)

    def _is_stopping(self):
        with self.lock:
            return self._stopping

    def _log_to_vault(self, task, result, success, duration, model, budget):
        try:
            if self.config.vault_path:
                log_dir = self.config.vault_path.parent.parent / "Claude Knowledge Base" / "Automation Logs"
            else:
                log_dir = self.config.log_dir
            log_dir.mkdir(parents=True, exist_ok=True)
            date_str = datetime.now().strftime("%Y-%m-%d")
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            status = "SUCCESS" if success else "FAILED"
            log_file = log_dir / f"relay-executions-{date_str}.md"
            entry = f"\n## {ts} — {status} ({duration:.0f}s, {model}, ${budget})\n\n**Task:** {task[:500]}\n\n**Result:**\n{result[:2000]}\n\n---\n"
            with open(log_file, "a") as f:
                f.write(entry)
        except Exception as e:
            self.logger.warning(f"Failed to log execution: {e}")

    def _send_result_back(self, original_msg, result, success):
        try:
            sender = original_msg.get("from", "")
            if not sender:
                return
            status = "completed" if success else "failed"
            reply = f"[AUTO-RESULT: {status}] Re: {original_msg.get('body', original_msg.get('message', ''))[:100]}\n\n{result[:1500]}"
            worker = threading.current_thread()
            process = self._start_worker_process(
                [sys.executable, __file__, "send", sender, reply],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if process is None:
                return
            try:
                process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
            finally:
                self._forget_worker_process(worker, process)
        except Exception as e:
            self.logger.warning(f"Failed to relay result back: {e}")


# ── Daemon ──

class RelayDaemon:
    def __init__(self, config):
        self.config = config
        self.logger = self._setup_logging()
        # The DB is opened only after acquiring relay.lock in run(). A second
        # daemon must not touch SQLite before it discovers the active instance.
        self.store = None
        self.rate_limiter = RateLimiter()
        self.executor = AutoExecutor(config, self.logger)
        self.shutdown_event = None  # Created in run() to bind to correct loop
        self.start_time = time.time()
        self.stats = {"tcp_received": 0, "tcp_sent": 0, "file_received": 0, "file_sent": 0}
        self._queue_logged = set()
        self._store_full_logged = False
        self._worker_start_attempts = {}
        self._worker_retry_after = {}
        self._worker_start_failure_logged = set()
        self._lock_fd = None
        self._closing = False
        self._lifecycle_lock = threading.Lock()

    def _setup_logging(self):
        logger = logging.getLogger("relay")
        logger.setLevel(logging.INFO)

        # Rotating file handler
        log_file = self.config.log_dir / "relay-daemon.log"
        fh = RotatingFileHandler(str(log_file), maxBytes=5_000_000, backupCount=3)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(fh)

        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S"))
        logger.addHandler(ch)

        return logger

    def _acquire_instance_lock(self):
        state_dir = Path(self.config.state_dir).expanduser()
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(state_dir, 0o700)
        lock_path = state_dir / "relay.lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        os.chmod(lock_path, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                return False
            raise
        self._lock_fd = fd
        return True

    def _release_instance_lock(self):
        if self._lock_fd is None:
            return
        fd, self._lock_fd = self._lock_fd, None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _log_store_full_once(self, exc):
        if not self._store_full_logged:
            self.logger.error(f"Relay store is full; refusing new messages: {exc}")
            self._store_full_logged = True

    def _worker_retry_is_pending(self, msg_id):
        retry_at = self._worker_retry_after.get(msg_id)
        if retry_at is None:
            return False
        if time.monotonic() < retry_at:
            return True
        self._worker_retry_after.pop(msg_id, None)
        return False

    def _record_worker_start_failure(self, msg_id):
        attempts = self._worker_start_attempts.get(msg_id, 0)
        delay = min(5.0 * (2 ** attempts), 300.0)
        self._worker_start_attempts[msg_id] = attempts + 1
        self._worker_retry_after[msg_id] = time.monotonic() + delay
        if msg_id not in self._worker_start_failure_logged:
            self.logger.error(
                f"AUTO-EXEC worker could not start for {msg_id}; retrying in {delay:.0f}s"
            )
            self._worker_start_failure_logged.add(msg_id)

    def _clear_worker_start_failure(self, msg_id):
        self._worker_start_attempts.pop(msg_id, None)
        self._worker_retry_after.pop(msg_id, None)
        self._worker_start_failure_logged.discard(msg_id)

    # ── TCP Server ──

    async def handle_tcp_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else "unknown"

        try:
            if not self.rate_limiter.allow(peer_ip):
                self.logger.warning(f"Rate limited: {peer_ip}")
                writer.close()
                await writer.wait_closed()
                return

            data = await read_framed(reader, timeout=30.0)
            message = json.loads(data.decode("utf-8"))

            if not isinstance(message, dict):
                raise ValueError("Message must be a JSON object")

            # Ping: no auth required
            if message.get("type", "relay") == "ping":
                resp = {
                    "type": "pong",
                    "machine": self.config.machine,
                    "uptime": time.time() - self.start_time,
                    "version": VERSION,
                    "stats": self.stats,
                }
                writer.write(frame_and_encode(resp))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # All other messages require HMAC
            if not self.config.secret:
                self.logger.warning("TCP message refused: no shared secret configured")
                writer.close()
                await writer.wait_closed()
                return

            if not verify_message(message, self.config.secret):
                self.logger.warning(f"HMAC verification failed from {peer_ip}")
                writer.close()
                await writer.wait_closed()
                return

            try:
                validate_inbound_message(message)
            except ValueError as exc:
                self.logger.warning(f"Invalid signed message from {peer_ip}: {exc}")
                resp = {"status": "error", "error": str(exc)}
                writer.write(frame_and_encode(resp))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            msg_id = message.get("msg_id", "")
            message_without_signature = dict(message)
            message_without_signature.pop("signature", None)
            try:
                is_new = self.store.enqueue(msg_id, message_without_signature, "tcp")
            except Exception as exc:
                if isinstance(exc, StoreFullError):
                    self._log_store_full_once(exc)
                else:
                    self.logger.error(f"Failed to durably enqueue TCP message {msg_id}: {exc}")
                resp = {"status": "error", "error": "enqueue failed", "msg_id": msg_id}
                writer.write(frame_and_encode(resp))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if not is_new:
                resp = {"status": "ok", "note": "duplicate", "msg_id": msg_id}
                writer.write(frame_and_encode(resp))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            self._store_full_logged = False

            resp = {"status": "ok", "msg_id": msg_id}
            writer.write(frame_and_encode(resp))
            await writer.drain()
            writer.close()
            await writer.wait_closed()

            self.stats["tcp_received"] += 1
            self._dispatch(msg_id)

        except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
            self.logger.warning(f"Connection error from {peer_ip}: {e}")
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as e:
            self.logger.warning(f"Invalid message from {peer_ip}: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error handling {peer_ip}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _write_held_file(self, msg_id, message, reason):
        held_dir = self.config.state_dir / "held"
        held_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(held_dir, 0o700)
        held_path = held_dir / f"{msg_id}.json"
        record = dict(message) if isinstance(message, dict) else {"payload": message}
        record["held_reason"] = reason
        record["held_at"] = time.time()
        tmp_path = held_dir / f".{msg_id}.{uuid.uuid4().hex}.tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(record, stream, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp_path, held_path)
            _fsync_directory(held_dir, logger=self.logger)
            _fsync_directory(self.config.state_dir, logger=self.logger)
        finally:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass
        return held_path

    def _hold_message(self, msg_id, message, reason, expected_state=None):
        row = self.store.get(msg_id)
        if not row:
            return False
        if row["state"] == "held":
            self._queue_logged.discard(msg_id)
            return False
        expected_state = expected_state or row["state"]
        if row["state"] != expected_state:
            return False
        if not self.store.set_state(msg_id, "held", expected_state, reason=reason):
            return False
        self._queue_logged.discard(msg_id)
        held_row = self.store.get(msg_id)
        payload = held_row.get("payload") if held_row else message
        try:
            held_path = self._write_held_file(msg_id, payload, reason)
            self.store.mark_held_written(msg_id)
            if reason == "AUTO-EXEC disabled; manual pickup required":
                self.logger.warning(
                    f"AUTO-EXEC disabled (auto_execute.enabled is not true): held for manual pickup: {held_path}"
                )
            else:
                self.logger.warning(f"AUTO-EXEC held for manual pickup: {held_path} ({reason})")
        except Exception as exc:
            self.logger.error(f"Could not write held message {msg_id}: {exc}")
        return True

    def _ensure_held_files(self):
        for row in self.store.list_unwritten_held():
            msg_id = row["msg_id"]
            payload = row.get("payload")
            if payload is None:
                self.logger.error(f"Held message {msg_id} has no DB payload for file recovery")
                continue
            try:
                self._write_held_file(msg_id, payload, row.get("held_reason") or "held")
                self.store.mark_held_written(msg_id)
            except Exception as exc:
                self.logger.error(f"Could not retry held message {msg_id}: {exc}")

    def recover_interrupted(self):
        """Never retry tasks whose worker may have started before a crash."""
        for row in self.store.list_state("executing"):
            reason = "interrupted during execution; not re-run automatically"
            if self._hold_message(row["msg_id"], row.get("payload") or {}, reason,
                                  expected_state="executing"):
                self.logger.warning(f"Recovered interrupted execution as held: {row['msg_id']}")

    def _is_auto_message(self, message):
        tags = message.get("tags", [])
        tagged_auto = isinstance(tags, (list, tuple, set)) and "AUTO" in tags
        return bool(message.get("auto_execute")) or tagged_auto

    def _dispatch(self, msg_id):
        """Dispatch one durably queued message, or leave it queued for the drain."""
        if self._closing:
            return
        row = self.store.get(msg_id)
        if not row or row["state"] != "queued":
            return
        message = row.get("payload") or {}
        try:
            validate_inbound_message(message)
        except (ValueError, TypeError) as exc:
            self.logger.error(f"Dispatch rejected invalid message {msg_id}: {exc}")
            self._hold_message(msg_id, message, "dispatch-error", expected_state="queued")
            self._queue_logged.discard(msg_id)
            return
        if not self._is_auto_message(message):
            sender = message.get("from", "unknown")
            body = message.get("body", message.get("message", "(empty)"))
            play_alert(self.config.platform)
            self.logger.info(f"Message from {sender}: {body[:200]}")
            self.store.set_state(msg_id, "done", expected_state="queued")
            self._clear_worker_start_failure(msg_id)
            return

        if getattr(self.config, "auto_execute_enabled", False) is not True:
            self._hold_message(msg_id, message, "AUTO-EXEC disabled; manual pickup required",
                               expected_state="queued")
            return

        try:
            max_queue_age = float(self.config.max_queue_age)
        except (TypeError, ValueError):
            max_queue_age = 3600.0
        if time.time() - row["received_at"] > max_queue_age:
            self._hold_message(msg_id, message, "AUTO-EXEC queue age exceeded; manual pickup required",
                               expected_state="queued")
            return

        if self._worker_retry_is_pending(msg_id):
            return

        if not self.executor.can_accept():
            if msg_id not in self._queue_logged:
                body = message.get("body", message.get("message", ""))
                self.logger.warning(f"Max concurrent executions reached, queued: {str(body)[:80]}")
                self._queue_logged.add(msg_id)
            return

        if not self.store.set_state(msg_id, "executing", expected_state="queued"):
            return

        def on_done(success):
            with self._lifecycle_lock:
                if self.store.set_state(msg_id, "done" if success else "failed",
                                        expected_state="executing"):
                    self._queue_logged.discard(msg_id)
                    self._clear_worker_start_failure(msg_id)

        try:
            result = self.executor.execute(message, on_done=on_done)
            if result is WORKER_START_FAILED:
                if self.store.set_state(msg_id, "queued", expected_state="executing"):
                    self._queue_logged.discard(msg_id)
                    self._record_worker_start_failure(msg_id)
            elif not result:
                self.store.set_state(msg_id, "queued", expected_state="executing")
            else:
                self._clear_worker_start_failure(msg_id)
        except Exception as exc:
            self.logger.error(f"Could not start queued execution {msg_id}; leaving it for retry: {exc}")
            try:
                self.store.set_state(msg_id, "queued", expected_state="executing")
            except (sqlite3.OperationalError, OSError) as state_exc:
                self.logger.warning(f"Could not requeue {msg_id} after dispatch failure: {state_exc}")

    async def drain_queued(self):
        last_prune = 0.0
        while not self.shutdown_event.is_set():
            try:
                self._ensure_held_files()
                for row in self.store.list_state("queued"):
                    try:
                        self._dispatch(row["msg_id"])
                    except (sqlite3.OperationalError, OSError) as exc:
                        self.logger.warning(
                            f"Dispatch temporarily failed for {row['msg_id']}; leaving it queued: {exc}"
                        )
                    except Exception as exc:
                        self.logger.error(f"Dispatch failed for {row['msg_id']}: {exc}")
                now = time.monotonic()
                if now - last_prune >= 60.0:
                    self.store.prune()
                    last_prune = now
                await asyncio.sleep(FILE_POLL_INTERVAL)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.logger.error(f"Queue drain error: {exc}")
                await asyncio.sleep(FILE_POLL_INTERVAL)

    async def _process_message(self, message):
        """Compatibility helper for callers that already durably enqueued."""
        self._dispatch(message["msg_id"])

    # ── Unix Socket Server (local CLI IPC) ──

    async def handle_uds_client(self, reader, writer):
        try:
            data = await read_framed(reader, timeout=30.0)
            request = json.loads(data.decode("utf-8"))
            cmd = request.get("cmd", "")

            if cmd == "health":
                resp = {
                    "status": "ok",
                    "machine": self.config.machine,
                    "uptime": time.time() - self.start_time,
                    "version": VERSION,
                    "tailscale_ip": self.config.tailscale_ip,
                    "port": self.config.port,
                    "stats": self.stats,
                }
            elif cmd == "send":
                target = request.get("target")
                message = request.get("message", {})
                result = await self._send_to_target(target, message)
                status = "error" if result.get("method") == "error" else "ok"
                resp = {"status": status, "delivery": result}
                if status == "error":
                    resp["error"] = result.get("error", "delivery failed")
            elif cmd == "check":
                resp = self._check_file_inbox()
            elif cmd == "read":
                resp = self._read_file_inbox()
            elif cmd == "status":
                resp = self._get_status()
            elif cmd == "history":
                resp = self._get_history()
            else:
                resp = {"status": "error", "error": f"Unknown command: {cmd}"}

            writer.write(frame_and_encode(resp))
            await writer.drain()
        except Exception as e:
            try:
                resp = {"status": "error", "error": str(e)}
                writer.write(frame_and_encode(resp))
                await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()
            await writer.wait_closed()

    # ── Send Logic ──

    async def _send_to_target(self, target, message):
        """Send via TCP, fall back to file."""
        if not isinstance(self.config.secret, str) or not self.config.secret:
            self.logger.error("Cannot send: no shared secret configured")
            return {"method": "error", "error": "no shared secret configured"}
        if target == self.config.machine:
            return {"method": "error", "error": "Cannot send to self"}

        peer_ip = self.config.get_peer_ip(target)
        if not peer_ip:
            return {"method": "error", "error": f"Unknown target: {target}"}

        # Sign the message
        message = sign_message(dict(message), self.config.secret)

        # Try TCP first
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(peer_ip, self.config.port),
                timeout=TCP_CONNECT_TIMEOUT
            )
            payload = json.dumps(message).encode("utf-8")
            writer.write(frame_message(payload))
            await writer.drain()

            # Read ACK
            resp_data = await read_framed(reader, timeout=TCP_READ_TIMEOUT)
            resp = json.loads(resp_data.decode("utf-8"))
            writer.close()
            await writer.wait_closed()

            if resp.get("status") == "ok":
                self.stats["tcp_sent"] += 1
                self.logger.info(f"Sent to {target} via TCP")
                return {"method": "tcp", "msg_id": message.get("msg_id")}

        except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
            self.logger.info(f"TCP to {target} failed ({e}), falling back to file")

        # File fallback
        inbox = self.config.get_file_inbox(target)
        if inbox:
            self._write_file_message(inbox, message)
            self.stats["file_sent"] += 1
            self.logger.info(f"Sent to {target} via file fallback")

            # Also try SSH delivery
            self._ssh_deliver(target, inbox, message)

            return {"method": "file", "msg_id": message.get("msg_id")}

        return {"method": "error", "error": "No delivery method available"}

    def _write_file_message(self, inbox_path, message):
        """Write a message to a file-based inbox."""
        inbox_path.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"{ts}-{self.config.machine}.json"
        filepath = inbox_path / filename
        if filepath.exists():
            filepath = inbox_path / f"{filepath.stem}-{uuid.uuid4().hex}.json"
        tmp_path = inbox_path / f".{filepath.name}.{uuid.uuid4().hex}.tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(message, stream, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp_path, filepath)
            _fsync_directory(inbox_path, logger=self.logger)
        finally:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass

    def _ssh_deliver(self, target, local_inbox, message):
        """Try SSH/scp delivery as additional file transport."""
        peer_ip = self.config.get_peer_ip(target)
        ssh_user = self.config.get_peer_ssh_user(target)
        if not peer_ip or not ssh_user:
            return

        # Remote relay path from config
        remote_base = self.config.get_remote_relay_path(target)
        if not remote_base:
            return

        remote_inbox = f"{remote_base}/inbox-{target}"
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"{ts}-{self.config.machine}.json"

        # Write temp file
        tmp = Path(f"/tmp/relay-{filename}")
        tmp.write_text(json.dumps(message, indent=2))

        try:
            subprocess.run(
                ["ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=accept-new",
                 f"{ssh_user}@{peer_ip}", f"mkdir -p {remote_inbox}"],
                capture_output=True, timeout=10
            )
            subprocess.run(
                ["scp", "-o", "ConnectTimeout=5",
                 str(tmp), f"{ssh_user}@{peer_ip}:{remote_inbox}/{filename}"],
                capture_output=True, timeout=15
            )
        except (subprocess.TimeoutExpired, OSError):
            pass
        finally:
            tmp.unlink(missing_ok=True)

    # ── File Inbox Watcher ──

    async def watch_file_inbox(self):
        """Poll file-based inbox for fallback messages."""
        seen = set()

        # On startup, note existing files
        inbox = self.config.get_my_file_inbox()
        if inbox and inbox.exists():
            for f in inbox.glob("*.json"):
                seen.add(f.name)
            # Process any existing messages
            for f in sorted(inbox.glob("*.json")):
                result = await self._process_file_message(f)
                if result == "retry":
                    seen.discard(f.name)
                else:
                    seen.add(f.name)

        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(FILE_POLL_INTERVAL)
                inbox = self.config.get_my_file_inbox()
                if not inbox or not inbox.exists():
                    continue

                for msg_path in sorted(inbox.glob("*.json")):
                    if msg_path.name not in seen:
                        seen.add(msg_path.name)
                        result = await self._process_file_message(msg_path)
                        if result == "retry":
                            seen.discard(msg_path.name)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"File watcher error: {e}")

    async def _process_file_message(self, msg_path):
        """Process a file-based message."""
        try:
            file_stat = msg_path.stat()
            if file_stat.st_size > MAX_MESSAGE_SIZE:
                self._reject_file(msg_path, "too-large")
                return "rejected"
            msg = json.loads(msg_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            try:
                age = time.time() - file_stat.st_mtime
            except (UnboundLocalError, OSError):
                age = FILE_DECODE_GRACE
            if age < FILE_DECODE_GRACE:
                self.logger.info(f"File message {msg_path.name} is incomplete; retrying later")
                return "retry"
            self._reject_file(msg_path, "bad-json")
            return "rejected"
        except OSError as exc:
            self.logger.warning(f"Could not read file message {msg_path.name}: {type(exc).__name__}")
            return "seen"

        if not isinstance(msg, dict):
            self._reject_file(msg_path, "bad-json")
            return "rejected"
        if not isinstance(self.config.secret, str) or not self.config.secret:
            self._reject_file(msg_path, "unsigned-no-secret")
            return "rejected"
        if not verify_message(msg, self.config.secret):
            self._reject_file(msg_path, self._file_verification_reason(msg))
            return "rejected"

        try:
            validate_inbound_message(msg)
        except ValueError as exc:
            self._reject_file(msg_path, f"invalid-message: {exc}")
            return "rejected"

        msg_id = msg["msg_id"]
        message_without_signature = dict(msg)
        message_without_signature.pop("signature", None)
        try:
            is_new = self.store.enqueue(msg_id, message_without_signature, "file")
        except Exception as exc:
            if isinstance(exc, StoreFullError):
                self._log_store_full_once(exc)
            else:
                self.logger.error(f"Failed to durably enqueue file message {msg_path.name}: {exc}")
            return "retry"

        if is_new:
            self._store_full_logged = False
        self._archive_file(msg_path)
        if is_new:
            self.stats["file_received"] += 1
            self._dispatch(msg_id)
        return "processed"

    def _file_verification_reason(self, message):
        signature = message.get("signature")
        if not isinstance(signature, str):
            return "unsigned"
        timestamp = message.get("timestamp")
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
            return "bad-timestamp"
        try:
            if not math.isfinite(timestamp) or abs(time.time() - timestamp) > HMAC_MAX_AGE:
                return "stale"
        except (OverflowError, TypeError, ValueError):
            return "bad-timestamp"
        return "bad-signature"

    def _reject_file(self, msg_path, reason):
        self.logger.warning(f"Rejected file message {msg_path.name}: {reason}")
        try:
            root = self.config._get_file_root() or msg_path.parent.parent
            hostname = socket.gethostname()
            hostname = re.sub(r"[^A-Za-z0-9._-]", "_", hostname) or "unknown"
            rejected = root / "rejected" / hostname
            rejected.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(rejected, 0o700)
            target = rejected / msg_path.name
            if target.exists():
                target = rejected / f"{msg_path.stem}-{uuid.uuid4().hex}{msg_path.suffix}"
            try:
                os.link(msg_path, target)
                msg_path.unlink()
            except OSError:
                if target.exists():
                    target = rejected / f"{msg_path.stem}-{uuid.uuid4().hex}{msg_path.suffix}"
                msg_path.rename(target)
            _fsync_directory(rejected, logger=self.logger)
        except OSError:
            # The watcher's seen set prevents repeated logs while the source remains.
            pass

    def _archive_file(self, msg_path):
        """Move processed message to archive."""
        archive = self.config.get_archive_dir()
        if archive:
            archive.mkdir(parents=True, exist_ok=True)
            try:
                msg_path.rename(archive / msg_path.name)
            except OSError:
                try:
                    msg_path.unlink()
                except OSError:
                    pass

    # ── Status & Query Methods ──

    def _check_file_inbox(self):
        inbox = self.config.get_my_file_inbox()
        if not inbox or not inbox.exists():
            return {"messages": 0}
        messages = list(inbox.glob("*.json"))
        senders = {}
        for m in messages:
            try:
                data = json.loads(m.read_text())
                sender = data.get("from", "unknown")
                senders[sender] = senders.get(sender, 0) + 1
            except (json.JSONDecodeError, OSError):
                pass
        return {"messages": len(messages), "senders": senders}

    def _read_file_inbox(self):
        inbox = self.config.get_my_file_inbox()
        archive = self.config.get_archive_dir()
        if not inbox or not inbox.exists():
            return {"messages": []}

        result = []
        for msg_path in sorted(inbox.glob("*.json")):
            try:
                msg = json.loads(msg_path.read_text())
                result.append(msg)
                if archive:
                    archive.mkdir(parents=True, exist_ok=True)
                    msg_path.rename(archive / msg_path.name)
            except (json.JSONDecodeError, OSError) as e:
                result.append({"error": str(e), "file": msg_path.name})
        return {"messages": result, "archived": len(result)}

    def _get_status(self):
        inbox = self.config.get_my_file_inbox()
        inbox_count = len(list(inbox.glob("*.json"))) if inbox and inbox.exists() else 0

        outbox_counts = {}
        for target in self.config.other_machines:
            ob = self.config.get_file_inbox(target)
            outbox_counts[target] = len(list(ob.glob("*.json"))) if ob and ob.exists() else 0

        archive = self.config.get_archive_dir()
        archive_count = len(list(archive.glob("*.json"))) if archive and archive.exists() else 0

        return {
            "machine": self.config.machine,
            "tailscale_ip": self.config.tailscale_ip,
            "port": self.config.port,
            "uptime": time.time() - self.start_time,
            "version": VERSION,
            "transport": "tcp+file",
            "inbox": inbox_count,
            "outbox": outbox_counts,
            "archive": archive_count,
            "held": self.store.counts().get("held", 0),
            "stats": self.stats,
        }

    def _get_history(self):
        archive = self.config.get_archive_dir()
        if not archive or not archive.exists():
            return {"messages": []}

        messages = []
        for msg_path in sorted(archive.glob("*.json"), reverse=True)[:10]:
            try:
                msg = json.loads(msg_path.read_text())
                messages.append({
                    "from": msg.get("from", "unknown"),
                    "to": msg.get("to", "unknown"),
                    "timestamp": msg.get("timestamp", "unknown"),
                    "body": (msg.get("body", msg.get("message", "")))[:100],
                })
            except (json.JSONDecodeError, OSError):
                pass
        return {"messages": messages}

    # ── Main Loop ──

    async def run(self):
        """Start all daemon components."""
        self.shutdown_event = asyncio.Event()
        self.logger.info(f"Relay daemon v{VERSION} starting on {self.config.machine}")
        if not self._acquire_instance_lock():
            self.logger.error("Another relay instance holds relay.lock; exiting")
            raise SystemExit(1)

        tcp_server = None
        uds_server = None
        watcher_task = None
        drain_task = None
        sock_path = Path(self.config.socket_path)
        owns_socket = False
        try:
            self.store = RelayStore(self.config.state_dir, logger=self.logger)
            self.executor.store = self.store
            enabled = getattr(self.config, "auto_execute_enabled", False) is True
            self.logger.info(f"Effective auto_execute.enabled={enabled}")

            self.recover_interrupted()
            self._ensure_held_files()
            self.store.prune()

            if not self.config.tailscale_ip:
                self.logger.error("Cannot determine Tailscale IP — aborting")
                return

            if not self.config.secret:
                self.logger.error("No shared secret configured — all inbound messages will be refused and all outbound sends will fail")

            loop = asyncio.get_running_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, lambda s=sig: self.shutdown_event.set())

            if sock_path.exists():
                sock_path.unlink()

            tcp_server = await asyncio.start_server(
                self.handle_tcp_client,
                self.config.tailscale_ip,
                self.config.port,
            )
            self.logger.info(f"TCP server listening on {self.config.tailscale_ip}:{self.config.port}")

            uds_server = await asyncio.start_unix_server(
                self.handle_uds_client,
                path=self.config.socket_path,
            )
            owns_socket = True
            os.chmod(self.config.socket_path, 0o600)
            self.logger.info(f"UDS server listening on {self.config.socket_path}")

            watcher_task = asyncio.create_task(self.watch_file_inbox())
            drain_task = asyncio.create_task(self.drain_queued())
            self.logger.info("Daemon ready")
            await self.shutdown_event.wait()
        finally:
            self.logger.info("Shutting down...")
            with self._lifecycle_lock:
                self._closing = True
            self.executor.stop_dispatching()
            for server in (tcp_server, uds_server):
                if server is not None:
                    server.close()
            for server in (tcp_server, uds_server):
                if server is not None:
                    await server.wait_closed()
            tasks = [task for task in (watcher_task, drain_task) if task is not None]
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

            in_flight = self.executor.wait_for_workers(15.0)
            if in_flight:
                self.logger.error(f"AUTO-EXEC workers still in flight at shutdown: {', '.join(in_flight)}")
                self.executor.terminate_remaining_processes(grace_period=5.0)
                self.executor.wait_for_workers(None)

            try:
                if owns_socket and sock_path.exists():
                    sock_path.unlink()
                if self.store is not None:
                    self.store.close()
                    self.store = None
                    self.executor.store = None
            finally:
                self._release_instance_lock()
            self.logger.info("Shutdown complete")


# ── CLI Client ──

def cli_send_via_daemon(socket_path, target, body, machine_name, auto=False, budget=1.0, model=None):
    """Send a message through the local daemon."""
    message = {
        "from": machine_name,
        "to": target,
        "type": "exec" if auto else "relay",
        "body": body,
        "auto_execute": auto,
    }
    if auto:
        message["budget"] = budget
        if model:  # no model = the receiver resolves it from the registry
            message["model"] = model
        message["reply_to"] = machine_name
        message["tags"] = ["AUTO"]

    request = {"cmd": "send", "target": target, "message": message}
    resp = _uds_request(socket_path, request)

    if resp:
        delivery = resp.get("delivery", {})
        method = delivery.get("method", "unknown")
        if method == "error":
            print(f"Error: {delivery.get('error')}")
        else:
            mode = f" [AUTO, ${budget}, {model or 'registry route'}]" if auto else ""
            print(f"Message sent to {target}{mode} via {method}")
    else:
        # Daemon not running — direct send
        print("Daemon not running, sending directly...")
        _direct_send(target, message)


def _direct_send(target, message):
    """Send without daemon (fallback for when daemon is down)."""
    config = Config()

    if not isinstance(config.secret, str) or not config.secret:
        print("Error: no shared secret configured")
        return
    message = sign_message(dict(message), config.secret)

    # Try TCP
    peer_ip = config.get_peer_ip(target)
    if peer_ip:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TCP_CONNECT_TIMEOUT)
            sock.connect((peer_ip, config.port))
            payload = json.dumps(message).encode("utf-8")
            sock.sendall(frame_message(payload))
            # Read ACK
            header = sock.recv(4)
            if header:
                length = struct.unpack("!I", header)[0]
                resp_data = sock.recv(length)
                resp = json.loads(resp_data.decode("utf-8"))
                if resp.get("status") == "ok":
                    print(f"Sent to {target} via TCP (direct)")
                    sock.close()
                    return
            sock.close()
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass

    # File fallback
    inbox = config.get_file_inbox(target)
    if inbox:
        inbox.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"{ts}-{config.machine}.json"
        (inbox / filename).write_text(json.dumps(message, indent=2))
        print(f"Sent to {target} via file (direct, daemon down)")
    else:
        print(f"Error: no delivery method available for {target}")


def _uds_request(socket_path, request, timeout=10.0):
    """Send a request to the daemon via Unix socket."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(socket_path)
        payload = json.dumps(request).encode("utf-8")
        sock.sendall(frame_message(payload))

        # Read response
        header = sock.recv(4)
        if not header:
            sock.close()
            return None
        length = struct.unpack("!I", header)[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(min(length - len(data), 65536))
            if not chunk:
                break
            data += chunk
        sock.close()
        return json.loads(data.decode("utf-8"))
    except (ConnectionRefusedError, FileNotFoundError, socket.timeout, OSError):
        return None


def cli_health(socket_path):
    resp = _uds_request(socket_path, {"cmd": "health"})
    if resp:
        print(f"Relay daemon v{resp.get('version', '?')}")
        print(f"Machine: {resp.get('machine')}")
        print(f"Tailscale IP: {resp.get('tailscale_ip')}:{resp.get('port')}")
        uptime = resp.get("uptime", 0)
        h, rem = divmod(int(uptime), 3600)
        m, s = divmod(rem, 60)
        print(f"Uptime: {h}h {m}m {s}s")
        stats = resp.get("stats", {})
        print(f"Stats: TCP rx={stats.get('tcp_received', 0)} tx={stats.get('tcp_sent', 0)} | File rx={stats.get('file_received', 0)} tx={stats.get('file_sent', 0)}")
    else:
        print("Daemon not running.")


def cli_ping(socket_path, target):
    """Ping a remote daemon via TCP."""
    config = Config()
    peer_ip = config.get_peer_ip(target)
    if not peer_ip:
        print(f"Unknown target: {target}")
        return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_CONNECT_TIMEOUT + 1)
        start = time.time()
        sock.connect((peer_ip, config.port))
        msg = json.dumps({"type": "ping"}).encode("utf-8")
        sock.sendall(frame_message(msg))
        header = sock.recv(4)
        length = struct.unpack("!I", header)[0]
        resp_data = sock.recv(length)
        elapsed = (time.time() - start) * 1000
        resp = json.loads(resp_data.decode("utf-8"))
        sock.close()

        if resp.get("type") == "pong":
            print(f"pong from {target} ({resp.get('machine')}) v{resp.get('version')} — {elapsed:.0f}ms")
            uptime = resp.get("uptime", 0)
            h, rem = divmod(int(uptime), 3600)
            m, s = divmod(rem, 60)
            print(f"  uptime: {h}h {m}m {s}s")
        else:
            print(f"Unexpected response: {resp}")
    except ConnectionRefusedError:
        print(f"{target} ({peer_ip}:{config.port}): connection refused — daemon not running?")
    except socket.timeout:
        print(f"{target} ({peer_ip}:{config.port}): timeout — unreachable")
    except OSError as e:
        print(f"{target} ({peer_ip}:{config.port}): {e}")


def cli_check(socket_path):
    resp = _uds_request(socket_path, {"cmd": "check"})
    if resp:
        count = resp.get("messages", 0)
        if count:
            senders = resp.get("senders", {})
            parts = [f"{c} from {s}" for s, c in senders.items()]
            print(f"You have {count} unread message(s): {', '.join(parts)}")
        # Silent if none (same as old behavior)
    else:
        # Daemon not running, check files directly
        config = Config()
        inbox = config.get_my_file_inbox()
        if inbox and inbox.exists():
            messages = list(inbox.glob("*.json"))
            if messages:
                print(f"You have {len(messages)} unread file message(s). Run `relay.py read` to view.")


def cli_read(socket_path):
    resp = _uds_request(socket_path, {"cmd": "read"})
    if resp:
        messages = resp.get("messages", [])
        if not messages:
            print("No unread messages.")
            return
        for msg in messages:
            if "error" in msg:
                print(f"Error: {msg['error']}")
                continue
            ts = msg.get("timestamp", "unknown")
            if isinstance(ts, (int, float)):
                ts = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            sender = msg.get("from", "unknown")
            body = msg.get("body", msg.get("message", "(empty)"))
            print(f"\n--- From {sender} at {ts} ---")
            print(body)
            print("---")
        print(f"\n{len(messages)} message(s) archived.")
    else:
        print("Daemon not running. Reading files directly...")
        config = Config()
        inbox = config.get_my_file_inbox()
        archive = config.get_archive_dir()
        if not inbox or not inbox.exists():
            print("No messages.")
            return
        messages = sorted(inbox.glob("*.json"))
        if not messages:
            print("No unread messages.")
            return
        for msg_path in messages:
            try:
                msg = json.loads(msg_path.read_text())
                ts = msg.get("timestamp", "unknown")
                if isinstance(ts, (int, float)):
                    ts = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                sender = msg.get("from", "unknown")
                body = msg.get("body", msg.get("message", "(empty)"))
                print(f"\n--- From {sender} at {ts} ---")
                print(body)
                print("---")
                if archive:
                    archive.mkdir(parents=True, exist_ok=True)
                    msg_path.rename(archive / msg_path.name)
            except (json.JSONDecodeError, OSError) as e:
                print(f"Error reading {msg_path.name}: {e}")
        print(f"\n{len(messages)} message(s) archived.")


def cli_status(socket_path):
    resp = _uds_request(socket_path, {"cmd": "status"})
    if resp:
        print(f"Machine: {resp.get('machine')} (v{resp.get('version', '?')})")
        print(f"Transport: {resp.get('transport')}")
        print(f"Tailscale: {resp.get('tailscale_ip')}:{resp.get('port')}")
        print()
        print(f"Inbox: {resp.get('inbox', 0)} unread")
        print(f"Held: {resp.get('held', 0)}")
        for target, count in resp.get("outbox", {}).items():
            print(f"Outbox → {target}: {count} pending")
        print(f"Archive: {resp.get('archive', 0)} total")
        stats = resp.get("stats", {})
        print(f"\nStats: TCP rx={stats.get('tcp_received', 0)} tx={stats.get('tcp_sent', 0)} | File rx={stats.get('file_received', 0)} tx={stats.get('file_sent', 0)}")
    else:
        # Fallback: direct file check (same as old relay.py status)
        config = Config()
        print(f"Machine: {config.machine} (daemon NOT running)")
        print(f"Transport: file-only (daemon offline)")
        root = config._get_file_root()
        if root:
            print(f"Relay root: {root}")
        inbox = config.get_my_file_inbox()
        inbox_count = len(list(inbox.glob("*.json"))) if inbox and inbox.exists() else 0
        print(f"\nInbox: {inbox_count} unread")
        held_dir = config.state_dir / "held"
        held_count = len(list(held_dir.glob("*.json"))) if held_dir.exists() else 0
        print(f"Held: {held_count}")
        for target in config.other_machines:
            ob = config.get_file_inbox(target)
            count = len(list(ob.glob("*.json"))) if ob and ob.exists() else 0
            print(f"Outbox → {target}: {count} pending")
        archive = config.get_archive_dir()
        archive_count = len(list(archive.glob("*.json"))) if archive and archive.exists() else 0
        print(f"Archive: {archive_count} total")


def cli_history(socket_path, machine_name):
    resp = _uds_request(socket_path, {"cmd": "history"})
    if resp:
        messages = resp.get("messages", [])
        if not messages:
            print("No message history.")
            return
        machine = machine_name
        print(f"Last {len(messages)} messages:\n")
        for msg in messages:
            ts = msg.get("timestamp", "unknown")
            if isinstance(ts, (int, float)):
                ts = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            sender = msg.get("from", "unknown")
            target = msg.get("to", "unknown")
            body = msg.get("body", "")
            if sender == machine:
                direction = f"→ {target}"
            else:
                direction = f"← {sender}"
            print(f"  {direction} [{ts}] {body[:100]}")
    else:
        print("Daemon not running. No history available.")


# ── Main ──

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1].lower()
    config = Config()
    socket_path = config.socket_path

    if command == "daemon":
        daemon = RelayDaemon(config)
        asyncio.run(daemon.run())

    elif command == "send":
        args = sys.argv[2:]
        if not args:
            print("Usage: relay.py send <dawn|dusk|day> [--auto] [--budget N] [--model M] \"message\"")
            sys.exit(1)

        target = args[0].lower()
        if target not in ALL_MACHINES:
            print(f"Unknown target: {target}. Use one of: {', '.join(ALL_MACHINES)}")
            sys.exit(1)

        args = args[1:]
        auto = False
        budget = config.default_budget
        model = None
        msg_parts = []
        i = 0
        while i < len(args):
            if args[i] == "--auto":
                auto = True
            elif args[i] == "--budget" and i + 1 < len(args):
                i += 1
                budget = float(args[i])
            elif args[i] == "--model" and i + 1 < len(args):
                i += 1
                model = args[i]
            else:
                msg_parts.append(args[i])
            i += 1
        body = " ".join(msg_parts)
        if not body:
            print("Usage: relay.py send <dawn|dusk|day> [--auto] [--budget N] [--model M] \"message\"")
            sys.exit(1)

        cli_send_via_daemon(socket_path, target, body, config.machine, auto=auto, budget=budget, model=model)

    elif command == "check":
        cli_check(socket_path)

    elif command == "read":
        cli_read(socket_path)

    elif command == "status":
        cli_status(socket_path)

    elif command == "history":
        cli_history(socket_path, config.machine)

    elif command == "ping":
        if len(sys.argv) < 3:
            print("Usage: relay.py ping <dawn|dusk|day>")
            sys.exit(1)
        cli_ping(socket_path, sys.argv[2].lower())

    elif command == "health":
        cli_health(socket_path)

    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
