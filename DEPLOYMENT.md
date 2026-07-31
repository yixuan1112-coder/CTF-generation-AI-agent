# Publishing generated CTF challenges

Generated challenges use one of these runtime contracts:

| Delivery | Local runtime | Player connection |
|---|---|---|
| `web` | Docker HTTP service | Browser URL |
| `tcp` | Docker TCP service | `nc host port` |
| `api` | Docker HTTP API | Browser, curl, or script |
| `blockchain` | Docker deterministic JSON-RPC dev-chain simulator | JSON-RPC URL |
| `mqtt` | Docker MQTT device simulator | `mosquitto_sub` |
| `android` | Attachment-first Android analysis workspace | Android SDK/AVD optional |
| `static` | No server | Player ZIP download |

Each bundle contains `runtime.json` for lifecycle tooling and `deployment.json`
for publishing automation. `organizer/` is always private.

## Local launch

Use **Launch instance** in CTF Forge Studio. The backend builds the reviewed
bundle, binds a random port on `127.0.0.1`, and returns the browser URL or client
command. It never accepts a filesystem path or shell command from the browser.

## Publish a service challenge

Use a dedicated Linux Docker host or an isolated container runner:

1. Copy the organizer-owned generated bundle to the server over SSH or CI.
2. Set a unique flag for that deployment and keep the bundle private.
3. Change the Compose published address from `127.0.0.1::PORT` to the internal
   address used by your reverse proxy or TCP load balancer.
4. Run `docker compose up -d --build`.
5. Route HTTP/JSON-RPC through HTTPS. Route TCP and MQTT through dedicated,
   rate-limited ports. Do not expose the Docker daemon.
6. Put only the public URL/client command and the exported player ZIP in CTFd.

For a single event, use one isolated Compose project per challenge. For multiple
teams, provision one project per team with CPU, memory, process, network, and
time limits, then destroy it after the lease expires.

## Publish an attachment challenge

Export the player ZIP:

```powershell
python -m ctf_factory.cli export generated\<challenge-slug>
```

Upload the resulting file from `exports/` to CTFd, S3, R2, or OSS. The exporter
excludes `organizer/` and rebuilds service challenges with
`flag{replace_at_deployment}` so a downloadable source package cannot disclose
the live event flag.

## Android

The current Mobile templates are reverse-engineering artifacts. They can be
solved with Jadx, apktool, Ghidra, or a locally configured Android SDK. A
generated `launch-android.ps1` can start an existing AVD, but these templates do
not pretend that a synthetic DEX/native artifact is an installable application.
A true dynamic Android challenge requires a separately reviewed, buildable APK
template and an emulator host with hardware virtualization.

## Production minimums

- Linux runner hosts; rootless Docker where possible.
- Per-instance CPU, memory, PID, disk, and wall-clock limits.
- No host filesystem mounts, Docker socket mounts, privileged mode, or outbound
  internet unless a reviewed challenge explicitly requires it.
- HTTPS for browser/API/RPC traffic.
- Rate limits for HTTP, TCP, MQTT, and flag submissions.
- PostgreSQL-backed users and challenge state, Redis queueing, object storage for
  player files, audit logs, and automatic instance expiry.
- Organizer bundles and flags stored as secrets, never in public Git history or
  public object storage.
