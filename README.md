# Relay

TCP-primary message relay for cross-machine communication over Tailscale.

## Features

- **TCP transport** over Tailscale mesh with file-based fallback
- **HMAC-SHA256** message authentication with pre-shared secret
- **Auto-execution** of tagged messages via Claude CLI (budget-capped, model-allowlisted)
- **Pinned model policy** — Fable 5.1 at Ultra Code effort, with Opus 5 as the only fallback
- **Deduplication**, rate limiting, and message archiving
- **Zero dependencies** — Python 3.9+ stdlib only

## Setup

Requirements: Python 3.9+ and a Claude Code CLI for which
`python3 relay.py probe-claude` reports `"ok": true`. The capability probe makes
no model request and spends no tokens. This release was validated against
Claude Code 2.1.260; capability presence, rather than the version string alone,
is the release gate.

1. Generate a shared secret and distribute to all machines:
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))" > ~/.relay-secret
   chmod 600 ~/.relay-secret
   ```

2. Create config from template:
   ```bash
   mkdir -p ~/.relay
   cp config.example.json ~/.relay/config.json
   # Edit with your machine names, Tailscale IPs, and paths
   ```

3. Start the daemon:
   ```bash
   python3 relay.py daemon
   ```

## CLI

```
relay.py send <target> "message"       Send a message
relay.py send <target> --auto "task"   Send for auto-execution
relay.py check                         Check for unread messages
relay.py read                          Read and archive messages
relay.py ping <target>                 Health-check a peer
relay.py health                        Local daemon status
relay.py status                        Full system status
relay.py history                       Recent archived messages
relay.py probe-claude                  Check installed Claude CLI flags without a model call
```

## Model policy and compatibility

Relay auto-execution accepts exactly two canonical models:

| Role | Canonical model |
|---|---|
| Primary | `claude-fable-5-1` |
| Only fallback and subagent model | `claude-opus-5` |

Legacy names are accepted at the receiver and audited when normalized. Fable,
Sonnet, and Haiku aliases map to Fable 5.1; old Opus aliases map to Opus 5.
This includes dated vendor IDs such as `claude-3-5-sonnet-20240620` and
`claude-3-opus-20240229`. Compatibility uses a finite alias table: unknown
families and unlisted or future version IDs are rejected and, when `reply_to`
is present, the sender receives a failure result.

During the compatibility window the CLI validates and normalizes every accepted
model spelling locally, then emits only the compatible `sonnet` or `opus` wire
alias. That includes explicit canonical `--model` values and legacy aliases
with harmless case, spacing, or provider-prefix differences. Once
`canonical_wire_ready` is explicitly set to `true`, the sender emits canonical
names instead. This mechanically prevents a new sender from placing a canonical
name onto an old receiver's queue without refusing an otherwise valid task.
Deploy receiver-first:

1. Deploy the new `relay.py` to every receiving daemon while leaving existing
   `auto_execute` model settings unchanged.
2. Run `python3 relay.py probe-claude` on each host and restart each daemon only
   after the probe passes.
3. Confirm every receiver reports relay 2.1.0 and accepts old aliases.
4. Migrate each config to the canonical names shown above. Leave
   `canonical_wire_ready` false until every receiver is verified; it may remain
   false indefinitely with no change to the model that actually executes.
5. Only after all receivers are upgraded may senders set
   `canonical_wire_ready` true to emit canonical names on the wire.

Rollback is the reverse compatibility operation: pause new auto-execution,
drain queued messages while upgraded receivers can still normalize both name
formats, set `canonical_wire_ready` false, restore legacy config names, then
roll back senders and receivers.
Never revert a receiver while canonical-model messages remain queued for it.

An explicitly narrower `allowed_models` list remains narrower after upgrade.
Unsupported entries are dropped with an audit warning. Only an absent
`allowed_models` key receives the canonical pair; an explicitly empty or wholly
invalid list disables auto-execution and refuses incoming tasks. A Fable-only
allowlist also suppresses automatic Opus fallback. The subagent model remains
Opus 5 as a separate fleetwide invariant.

Task bodies are passed to Claude over standard input, never as command-line
arguments. A body such as `--version` or `--model claude-opus-5` therefore
remains inert user text and cannot change the relay's selected model or flags.
The Claude capability probe treats `--effort` as required and fails closed when
it is unavailable; the settings overlay is defense in depth, not a substitute
for the explicit native `ultracode` effort argument.

## Activation hold

Creating the configured `activation_hold_sentinel` (default
`~/.relay/activation.hold`) leaves health, ping, status, and ordinary relay
traffic available while fail-closing unattended execution. Signed TCP AUTO
requests are acknowledged only after an atomic durable write to the local file
inbox. Every file inbox entry remains untouched while the sentinel exists,
including across daemon restarts; removing the sentinel releases eligible
entries to the normal receiver policy. An explicit `auto_execute.enabled=false`
also leaves queued AUTO files unarchived. Health, ping, and status responses
report `held=true` while the barrier is active.

## Tests

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile relay.py tests/test_model_invariant.py
python3 relay.py probe-claude
```

## Service Management

**macOS (launchd):**
```bash
cp com.relay.daemon.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.relay.daemon.plist
```

**Linux (systemd):**
```bash
sudo cp relay-daemon.service /etc/systemd/system/
sudo systemctl enable --now relay-daemon
```

## License

MIT
