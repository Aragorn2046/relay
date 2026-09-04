#!/usr/bin/env python3
"""Relay daemon — TCP-primary message bus between Dawn, Dusk, and Day.

Unified daemon + CLI. Replaces the old file-based relay.py + relay-watcher.py.

Usage (CLI):
    relay.py send <target> "message"          Send a message
    relay.py send <target> --auto "task"      Send for auto-execution
    relay.py send <target> --auto --budget 2.0 --model claude-opus-5 "task"
    relay.py check                            Check for unread messages
    relay.py read                             Read and archive unread messages
    relay.py status                           Show relay system status
    relay.py history                          Show recent archived messages
    relay.py ping <target>                    Health-check a remote daemon
    relay.py health                           Local daemon health
    relay.py probe-claude                     Verify Claude CLI flags without a model call

Usage (daemon):
    relay.py daemon                           Start the relay daemon
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections import OrderedDict, defaultdict
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

VERSION = "2.1.0"
DEFAULT_PORT = 7272
MAX_MESSAGE_SIZE = 1_048_576  # 1 MB
HMAC_MAX_AGE = 300.0  # 5 minutes
RATE_LIMIT = 10  # connections per second per IP
FILE_POLL_INTERVAL = 5  # seconds
DEDUP_TTL = 3600.0  # 1 hour
TCP_CONNECT_TIMEOUT = 2.0
TCP_READ_TIMEOUT = 5.0
EXECUTION_TIMEOUT = 300  # 5 minutes
PRIMARY_MODEL = "claude-fable-5-1"
FALLBACK_MODEL = "claude-opus-5"
ALLOWED_MODELS = (PRIMARY_MODEL, FALLBACK_MODEL)
LEGACY_WIRE_MODELS = frozenset({"sonnet", "opus"})
WIRE_COMPATIBILITY_MODE = True
CLAUDE_REQUIRED_FLAGS = (
    "--model",
    "--settings",
    "--max-budget-usd",
    "--print",
)
CLAUDE_OPTIONAL_FLAGS = ("--effort", "--fallback-model")
ULTRACODE_SETTINGS = '{"ultracode":true,"effortLevel":"xhigh"}'


def normalize_model(model):
    """Return the canonical relay model for a supported current or legacy name."""
    if not isinstance(model, str):
        return None

    normalized = model.strip().lower().replace("_", "-")
    for provider_prefix in ("anthropic:", "anthropic/"):
        if normalized.startswith(provider_prefix):
            normalized = normalized.removeprefix(provider_prefix)
            break

    if normalized in ALLOWED_MODELS:
        return normalized

    parts = normalized.split("-")
    claude_qualified = bool(parts and parts[0] == "claude")
    if claude_qualified:
        parts = parts[1:]

    families = {part for part in parts if part in {"fable", "sonnet", "haiku", "opus"}}
    if len(families) != 1:
        return None
    family = next(iter(families))

    # Bare aliases must start with the family. Vendor IDs may put a dated
    # generation before it, for example claude-3-5-sonnet-20240620.
    if not claude_qualified and (not parts or parts[0] != family):
        return None

    if family in {"fable", "sonnet", "haiku"}:
        return PRIMARY_MODEL
    if family == "opus":
        return FALLBACK_MODEL
    return None


def build_claude_environment():
    """Build the isolated environment used for Claude CLI subprocesses."""
    env = os.environ.copy()
    env.pop("CLAUDECODE", None)
    env["CLAUDE_CODE_SUBAGENT_MODEL"] = FALLBACK_MODEL

    # Daemons spawned outside an interactive shell don't inherit fnm/Homebrew
    # PATH entries, so `claude` isn't resolvable. Prepend common locations on
    # both WSL and macOS.
    home = Path.home()
    extra_path = ":".join(str(path) for path in [
        home / ".local/share/fnm/aliases/default/bin",
        home / ".local/bin",
        home / ".bun/bin",
        "/opt/homebrew/bin",
        "/usr/local/bin",
    ])
    env["PATH"] = f"{extra_path}:{env.get('PATH', '')}"
    return env, extra_path


def probe_claude_capabilities(claude_bin, env):
    """Inspect the installed CLI without making a model request or spending tokens."""
    # Subagent mode intentionally presents a reduced plain-help surface. Probe
    # the complete option catalog first, then run the parser smoke with the
    # actual execution environment (including the forced Opus 5 subagent).
    help_env = env.copy()
    help_env.pop("CLAUDE_CODE_SUBAGENT_MODEL", None)
    version_result = None
    try:
        version_result = subprocess.run(
            [claude_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            env=help_env,
        )
    except (FileNotFoundError, PermissionError, OSError, subprocess.TimeoutExpired):
        # Version text is evidence only; do not take working execution offline
        # when that optional probe is unavailable.
        pass

    def detected_flags(text):
        return [
            flag for flag in (*CLAUDE_REQUIRED_FLAGS, *CLAUDE_OPTIONAL_FLAGS)
            if re.search(rf"(?<![\w-]){re.escape(flag)}(?![\w-])", text)
        ]

    # Some Bun-packaged Claude builds intermittently truncate piped --help
    # output while still exiting zero. Union several no-spend attempts, also
    # tolerating a transient timeout, before declaring a capability absent.
    help_results = []
    help_errors = []
    help_text = ""
    supported = []
    missing_required = list(CLAUDE_REQUIRED_FLAGS)
    for _ in range(4):
        try:
            help_result = subprocess.run(
                [claude_bin, "--help"],
                capture_output=True,
                text=True,
                timeout=10,
                env=help_env,
            )
        except (FileNotFoundError, PermissionError, OSError, subprocess.TimeoutExpired) as exc:
            help_errors.append(f"{type(exc).__name__}: {exc}")
            continue
        help_results.append(help_result)
        help_text += f"\n{help_result.stdout or ''}\n{help_result.stderr or ''}"
        supported = detected_flags(help_text)
        missing_required = [flag for flag in CLAUDE_REQUIRED_FLAGS if flag not in supported]
        if not missing_required:
            break

    missing_optional = [flag for flag in CLAUDE_OPTIONAL_FLAGS if flag not in supported]
    version_text = ""
    if version_result is not None:
        version_text = (version_result.stdout or version_result.stderr or "").strip()
    version = version_text.splitlines()[0] if version_text else "unknown"
    errors = []
    if not help_results or not any(result.returncode == 0 for result in help_results):
        detail = help_errors[-1] if help_errors else "non-zero exits"
        errors.append(f"all help probes failed: {detail}")
    if missing_required:
        errors.append(f"missing required flags: {', '.join(missing_required)}")

    parser_smoke_ok = False
    if not errors:
        smoke_cmd = [
            claude_bin,
            "--model", PRIMARY_MODEL,
            "--settings", ULTRACODE_SETTINGS,
        ]
        if "--effort" not in missing_optional:
            smoke_cmd.extend(["--effort", "xhigh"])
        if "--fallback-model" not in missing_optional:
            smoke_cmd.extend(["--fallback-model", FALLBACK_MODEL])
        smoke_cmd.extend(["--max-budget-usd", "0.01", "--print", "--help"])
        try:
            smoke_result = subprocess.run(
                smoke_cmd,
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
            )
            parser_smoke_ok = smoke_result.returncode == 0
            if not parser_smoke_ok:
                errors.append(f"flag parser smoke exited {smoke_result.returncode}")
        except (FileNotFoundError, PermissionError, OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"flag parser smoke failed: {type(exc).__name__}: {exc}")

    return {
        "ok": not errors,
        "version": version,
        "parser_smoke_ok": parser_smoke_ok,
        "supported_flags": supported,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "error": "; ".join(errors) if errors else None,
    }

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
        self.model_policy_events = []
        self.auto_execute_enabled = ae.get("enabled", True)
        self.canonical_wire_ready = ae.get("canonical_wire_ready", False) is True
        self.max_concurrent = ae.get("max_concurrent", 2)
        self.exec_timeout = ae.get("timeout", EXECUTION_TIMEOUT)
        raw_default_model = ae.get("default_model", PRIMARY_MODEL)
        normalized_default = normalize_model(raw_default_model)
        if normalized_default is None:
            normalized_default = PRIMARY_MODEL
            self.model_policy_events.append((
                "warning",
                f"Configured default model {raw_default_model!r} is unsupported; using {PRIMARY_MODEL}",
            ))
        elif raw_default_model != normalized_default:
            self.model_policy_events.append((
                "info",
                f"Configured default model normalized: {raw_default_model!r} -> {normalized_default}",
            ))
        self.default_budget = ae.get("default_budget", 1.0)
        self.max_budget = ae.get("max_budget", 5.0)

        allowed_models_present = "allowed_models" in ae
        raw_allowed_models = ae.get("allowed_models")
        normalized_allowed = []
        if allowed_models_present:
            candidates = raw_allowed_models if isinstance(raw_allowed_models, list) else [raw_allowed_models]
            for candidate in candidates:
                normalized = normalize_model(candidate)
                if normalized is None:
                    self.model_policy_events.append((
                        "warning",
                        f"Configured allowed model {candidate!r} was dropped as unsupported",
                    ))
                    continue
                if candidate != normalized:
                    self.model_policy_events.append((
                        "info",
                        f"Configured allowed model normalized: {candidate!r} -> {normalized}",
                    ))
                if normalized not in normalized_allowed:
                    normalized_allowed.append(normalized)

        # Only an absent key receives defaults. An explicit empty or wholly
        # invalid list is a fail-closed operator decision.
        self.allowed_models = (
            list(ALLOWED_MODELS)
            if not allowed_models_present
            else normalized_allowed
        )
        if allowed_models_present and not normalized_allowed:
            self.auto_execute_enabled = False
            self.model_policy_events.append((
                "warning",
                "Configured allowed_models had no supported entries; auto-execution is disabled",
            ))

        if self.allowed_models and normalized_default not in self.allowed_models:
            replacement = next(
                (model for model in ALLOWED_MODELS if model in self.allowed_models),
                self.allowed_models[0],
            )
            self.model_policy_events.append((
                "warning",
                f"Configured default model {normalized_default} is outside allowed_models; using {replacement}",
            ))
            normalized_default = replacement
        self.default_model = normalized_default
        if not self.canonical_wire_ready:
            self.wire_default_model = (
                "sonnet" if self.default_model == PRIMARY_MODEL else "opus"
            )
            if raw_default_model != self.wire_default_model:
                self.model_policy_events.append((
                    "info",
                    f"Compatibility wire default: {raw_default_model!r} -> {self.wire_default_model}",
                ))
        else:
            self.wire_default_model = (
                raw_default_model
                if normalize_model(raw_default_model) == self.default_model
                else self.default_model
            )

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


def verify_message(message, secret, max_age=HMAC_MAX_AGE):
    """Verify HMAC signature and timestamp freshness."""
    signature = message.pop("signature", None)
    if not signature:
        return False

    ts = message.get("timestamp", 0)
    if abs(time.time() - ts) > max_age:
        return False

    canonical = json.dumps(message, sort_keys=True, separators=(",", ":"))
    expected = hmac.new(
        secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected)


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


# ── Deduplication ──

class DeduplicationFilter:
    def __init__(self, ttl=DEDUP_TTL):
        self.seen = OrderedDict()
        self.ttl = ttl

    def is_duplicate(self, msg_id):
        self._expire()
        if msg_id in self.seen:
            return True
        self.seen[msg_id] = time.time()
        return False

    def _expire(self):
        cutoff = time.time() - self.ttl
        while self.seen:
            oldest_id, oldest_time = next(iter(self.seen.items()))
            if oldest_time > cutoff:
                break
            self.seen.pop(oldest_id)


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

class AutoExecutor:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.active = 0
        self.lock = threading.Lock()
        self.capability_lock = threading.Lock()
        self.capability_cache = {}

    def _get_claude_capabilities(self, claude_bin, env):
        """Cache successful probes per binary revision; retry failures next task."""
        try:
            stat = Path(claude_bin).stat()
            cache_key = (claude_bin, stat.st_mtime_ns, stat.st_size)
        except OSError:
            cache_key = (claude_bin, None, None)

        with self.capability_lock:
            cached = self.capability_cache.get(cache_key)
            if cached is not None:
                return cached

            report = probe_claude_capabilities(claude_bin, env)
            if report["ok"]:
                self.capability_cache = {cache_key: report}
                self.logger.info(
                    "Claude CLI capability probe passed: version=%s flags=%s",
                    report["version"],
                    ",".join(report["supported_flags"]),
                )
            else:
                # Transient help/parser failures must recover on the next task;
                # only successful capability evidence is safe to cache.
                self.capability_cache.clear()
                self.logger.error(
                    "Claude CLI capability probe failed: version=%s error=%s",
                    report["version"],
                    report["error"],
                )
            if "--effort" in report["missing_optional"]:
                self.logger.warning(
                    "Claude CLI lacks --effort; using effortLevel=xhigh in the settings overlay"
                )
            if "--fallback-model" in report["missing_optional"]:
                self.logger.warning(
                    "Claude CLI lacks --fallback-model; automatic fallback is disabled rather than substituting another model"
                )
            return report

    def can_accept(self):
        with self.lock:
            return self.active < self.config.max_concurrent

    def execute(self, msg):
        """Run auto-execution in a thread (subprocess is blocking)."""
        with self.lock:
            self.active += 1
        t = threading.Thread(target=self._run, args=(msg,), daemon=True)
        t.start()

    def _run(self, msg):
        task = msg.get("body", msg.get("message", ""))
        if not isinstance(task, str):
            self.logger.warning(
                "AUTO-EXEC rejected: task body must be text (sender=%s)",
                msg.get("from", "unknown"),
            )
            if msg.get("reply_to"):
                self._send_result_back(msg, "Relay task body must be text", False)
            with self.lock:
                self.active -= 1
            return
        budget = min(float(msg.get("budget", self.config.default_budget)), self.config.max_budget)
        requested_model = msg.get("model", self.config.default_model)
        model = normalize_model(requested_model)
        if model not in self.config.allowed_models:
            self.logger.warning(
                "AUTO-EXEC rejected: invalid model %r from %s",
                requested_model,
                msg.get("from", "unknown"),
            )
            if msg.get("reply_to"):
                self._send_result_back(
                    msg,
                    f"Unsupported or disallowed relay model: {requested_model!r}",
                    False,
                )
            with self.lock:
                self.active -= 1
            return
        sender = msg.get("from", "unknown")
        if requested_model != model:
            self.logger.info(
                "AUTO-EXEC model normalized from %r to %s for sender %s",
                requested_model,
                model,
                sender,
            )

        env, extra_path = build_claude_environment()
        home = Path.home()
        claude_bin = shutil.which("claude", path=env["PATH"])
        if not claude_bin:
            result = f"CLAUDE BINARY NOT FOUND: looked in {extra_path}"
            self.logger.error("AUTO-EXEC PATH failure: %s", result)
            self._log_to_vault(task, result, False, 0, model, budget)
            if msg.get("reply_to"):
                self._send_result_back(msg, result, False)
            with self.lock:
                self.active -= 1
            return

        capabilities = self._get_claude_capabilities(claude_bin, env)
        if not capabilities["ok"]:
            result = f"CLAUDE CLI CAPABILITY CHECK FAILED: {capabilities['error']}"
            self._log_to_vault(task, result, False, 0, model, budget)
            if msg.get("reply_to"):
                self._send_result_back(msg, result, False)
            with self.lock:
                self.active -= 1
            return

        self.logger.info(f"AUTO-EXEC from {sender}: {task[:120]} (model={model}, budget=${budget})")
        play_exec_alert(self.config.platform)

        start = time.time()
        success = False
        result = ""

        try:
            cmd = [
                claude_bin,
                "--model", model,
                "--settings", ULTRACODE_SETTINGS,
            ]
            if "--effort" not in capabilities["missing_optional"]:
                cmd.extend(["--effort", "xhigh"])
            if (
                model == PRIMARY_MODEL
                and FALLBACK_MODEL in self.config.allowed_models
                and "--fallback-model" not in capabilities["missing_optional"]
            ):
                cmd.extend(["--fallback-model", FALLBACK_MODEL])
            cmd.extend(["--max-budget-usd", str(budget), "--print"])
            cwd = str(home / "workspace")
            if not Path(cwd).exists():
                cwd = str(home)

            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                input=task,
                timeout=self.config.exec_timeout, cwd=cwd, env=env
            )
            result = proc.stdout or ""
            if proc.returncode == 0:
                success = True
            else:
                result += f"\nSTDERR: {proc.stderr or '(none)'}"
        except subprocess.TimeoutExpired:
            result = f"TIMEOUT after {self.config.exec_timeout}s"
        except FileNotFoundError as e:
            result = f"CLAUDE BINARY NOT FOUND: {e}"
            self.logger.error(f"AUTO-EXEC PATH failure: {e}")
        except Exception as e:
            result = f"ERROR: {type(e).__name__}: {e}"

        duration = time.time() - start
        status = "SUCCESS" if success else "FAILED"
        self.logger.info(f"AUTO-EXEC {status} ({duration:.0f}s): {task[:80]}")

        # Log to vault
        self._log_to_vault(task, result, success, duration, model, budget)

        # Send result back
        if msg.get("reply_to"):
            self._send_result_back(msg, result, success)

        play_done_alert(self.config.platform)

        with self.lock:
            self.active -= 1

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
            subprocess.run(
                [sys.executable, __file__, "send", sender, reply],
                capture_output=True, timeout=30
            )
        except Exception as e:
            self.logger.warning(f"Failed to relay result back: {e}")


# ── Daemon ──

class RelayDaemon:
    def __init__(self, config):
        self.config = config
        self.logger = self._setup_logging()
        for level, message in getattr(self.config, "model_policy_events", []):
            getattr(self.logger, level)("MODEL POLICY: %s", message)
        self.dedup = DeduplicationFilter()
        self.rate_limiter = RateLimiter()
        self.executor = AutoExecutor(config, self.logger)
        self.shutdown_event = None  # Created in run() to bind to correct loop
        self.start_time = time.time()
        self.stats = {"tcp_received": 0, "tcp_sent": 0, "file_received": 0, "file_sent": 0}

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

            msg_type = message.get("type", "relay")

            # Ping: no auth required
            if msg_type == "ping":
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
                self.logger.error("No shared secret configured — rejecting message")
                writer.close()
                await writer.wait_closed()
                return

            if not verify_message(message, self.config.secret):
                self.logger.warning(f"HMAC verification failed from {peer_ip}")
                writer.close()
                await writer.wait_closed()
                return

            # Deduplication
            msg_id = message.get("msg_id", "")
            if self.dedup.is_duplicate(msg_id):
                resp = {"status": "ok", "note": "duplicate", "msg_id": msg_id}
                writer.write(frame_and_encode(resp))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # ACK immediately
            resp = {"status": "ok", "msg_id": msg_id}
            writer.write(frame_and_encode(resp))
            await writer.drain()
            writer.close()
            await writer.wait_closed()

            self.stats["tcp_received"] += 1

            # Process the message
            await self._process_message(message)

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

    async def _process_message(self, message):
        """Route a received message: display, auto-execute, or store."""
        sender = message.get("from", "unknown")
        body = message.get("body", message.get("message", "(empty)"))
        auto = message.get("auto_execute", False)
        tags = message.get("tags", [])

        if auto or "AUTO" in tags:
            if not self.config.auto_execute_enabled:
                self.logger.warning(
                    "AUTO-EXEC refused: auto-execution is disabled (sender=%s)",
                    sender,
                )
                if message.get("reply_to"):
                    await asyncio.to_thread(
                        self.executor._send_result_back,
                        message,
                        "Relay auto-execution is disabled by receiver policy",
                        False,
                    )
                return
            if self.executor.can_accept():
                self.executor.execute(message)
            else:
                self.logger.warning(f"Max concurrent executions reached, queuing: {body[:80]}")
                # Write to file inbox for later processing
                inbox = self.config.get_my_file_inbox()
                if inbox:
                    self._write_file_message(inbox, message)
        else:
            play_alert(self.config.platform)
            self.logger.info(f"Message from {sender}: {body[:200]}")

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
                resp = {"status": "ok", "delivery": result}
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
        if target == self.config.machine:
            return {"method": "error", "error": "Cannot send to self"}

        peer_ip = self.config.get_peer_ip(target)
        if not peer_ip:
            return {"method": "error", "error": f"Unknown target: {target}"}

        # Sign the message
        if self.config.secret:
            message = sign_message(message, self.config.secret)

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
        filepath.write_text(json.dumps(message, indent=2))

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
                await self._process_file_message(f)
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
                        await self._process_file_message(msg_path)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"File watcher error: {e}")

    async def _process_file_message(self, msg_path):
        """Process a file-based message."""
        try:
            msg = json.loads(msg_path.read_text())

            # HMAC is mandatory when a secret is configured
            if self.config.secret:
                if not verify_message(msg, self.config.secret):
                    self.logger.warning(f"HMAC failed/missing on file message: {msg_path.name}")
                    return

            # Dedup
            msg_id = msg.get("msg_id", msg_path.name)
            if self.dedup.is_duplicate(msg_id):
                # Archive duplicate silently
                self._archive_file(msg_path)
                return

            self.stats["file_received"] += 1
            await self._process_message(msg)

            # Archive processed message
            self._archive_file(msg_path)

        except (json.JSONDecodeError, OSError) as e:
            self.logger.warning(f"Error reading file message {msg_path.name}: {e}")

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

        if not self.config.tailscale_ip:
            self.logger.error("Cannot determine Tailscale IP — aborting")
            return

        if not self.config.secret:
            self.logger.warning("No shared secret — HMAC disabled (insecure!)")

        # Set up signal handlers
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda s=sig: self.shutdown_event.set())

        # Clean up stale socket
        sock_path = Path(self.config.socket_path)
        if sock_path.exists():
            sock_path.unlink()

        # Start TCP server
        tcp_server = await asyncio.start_server(
            self.handle_tcp_client,
            self.config.tailscale_ip,
            self.config.port,
        )
        self.logger.info(f"TCP server listening on {self.config.tailscale_ip}:{self.config.port}")

        # Start Unix socket server
        uds_server = await asyncio.start_unix_server(
            self.handle_uds_client,
            path=self.config.socket_path,
        )
        os.chmod(self.config.socket_path, 0o600)
        self.logger.info(f"UDS server listening on {self.config.socket_path}")

        # Start file watcher
        watcher_task = asyncio.create_task(self.watch_file_inbox())

        self.logger.info("Daemon ready")

        # Wait for shutdown
        await self.shutdown_event.wait()

        self.logger.info("Shutting down...")
        tcp_server.close()
        await tcp_server.wait_closed()
        uds_server.close()
        await uds_server.wait_closed()
        watcher_task.cancel()
        try:
            await watcher_task
        except asyncio.CancelledError:
            pass

        # Clean up socket
        if sock_path.exists():
            sock_path.unlink()

        self.logger.info("Shutdown complete")


# ── CLI Client ──

def cli_send_via_daemon(
    socket_path,
    target,
    body,
    machine_name,
    auto=False,
    budget=1.0,
    model="sonnet",
    model_explicit=True,
    canonical_wire_ready=False,
):
    """Send a message through the local daemon."""
    message = {
        "from": machine_name,
        "to": target,
        "type": "exec" if auto else "relay",
        "body": body,
        "auto_execute": auto,
    }
    if auto:
        requested_model = model
        validated_model = normalize_model(requested_model)
        if validated_model is None:
            raise ValueError(f"Unsupported model: {requested_model}")
        if (
            WIRE_COMPATIBILITY_MODE
            and not canonical_wire_ready
            and requested_model not in LEGACY_WIRE_MODELS
        ):
            source = "explicit --model" if model_explicit else "configured default"
            raise ValueError(
                f"During receiver-first compatibility rollout, {source} must use "
                "the legacy wire alias 'sonnet' or 'opus'; canonical wire names require "
                "canonical_wire_ready after every receiver is upgraded"
            )
        message["budget"] = budget
        # Compatibility window: validate locally, but preserve the caller's
        # wire value until every receiver has shipped normalization support.
        message["model"] = requested_model
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
            mode = f" [AUTO, ${budget}, {model}]" if auto else ""
            print(f"Message sent to {target}{mode} via {method}")
    else:
        # Daemon not running — direct send
        print("Daemon not running, sending directly...")
        _direct_send(target, message)


def _direct_send(target, message):
    """Send without daemon (fallback for when daemon is down)."""
    config = Config()

    if config.secret:
        message = sign_message(message, config.secret)

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


def cli_probe_claude():
    """Print a secret-free installed-CLI capability report; never calls a model."""
    env, searched_path = build_claude_environment()
    claude_bin = shutil.which("claude", path=env["PATH"])
    if not claude_bin:
        report = {
            "ok": False,
            "binary": None,
            "version": "unavailable",
            "parser_smoke_ok": False,
            "supported_flags": [],
            "missing_required": list(CLAUDE_REQUIRED_FLAGS),
            "missing_optional": list(CLAUDE_OPTIONAL_FLAGS),
            "error": f"claude binary not found in {searched_path}",
            "model_request_made": False,
        }
    else:
        report = probe_claude_capabilities(claude_bin, env)
        report = {
            **report,
            "binary": claude_bin,
            "model_request_made": False,
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return report["ok"]


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
        model = config.wire_default_model
        model_explicit = False
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
                model_explicit = True
            else:
                msg_parts.append(args[i])
            i += 1
        body = " ".join(msg_parts)
        if not body:
            print("Usage: relay.py send <dawn|dusk|day> [--auto] [--budget N] [--model M] \"message\"")
            sys.exit(1)

        try:
            cli_send_via_daemon(
                socket_path,
                target,
                body,
                config.machine,
                auto=auto,
                budget=budget,
                model=model,
                model_explicit=model_explicit,
                canonical_wire_ready=config.canonical_wire_ready,
            )
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(2)

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

    elif command == "probe-claude":
        if not cli_probe_claude():
            sys.exit(2)

    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
