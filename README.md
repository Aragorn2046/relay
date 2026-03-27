# Relay

TCP-primary message relay for cross-machine communication over Tailscale.

## Features

- **TCP transport** over Tailscale mesh with file-based fallback
- **HMAC-SHA256** message authentication with pre-shared secret
- **Auto-execution** of tagged messages via Claude CLI (budget-capped, model-allowlisted)
- **Deduplication**, rate limiting, and message archiving
- **Zero dependencies** — Python 3.9+ stdlib only

## Setup

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
