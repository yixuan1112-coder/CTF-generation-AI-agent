from __future__ import annotations

import base64
import json
from pathlib import Path

from .models import ChallengeSpec


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _manifest(out: Path, **values: object) -> None:
    _write(out / "runtime.json", json.dumps(values, ensure_ascii=False, indent=2))


def _docker(out: Path, port: int) -> None:
    _write(out / "Dockerfile", 'FROM python:3.12-alpine\nWORKDIR /app\nCOPY player /app\nUSER 65534\nEXPOSE %d\nCMD ["python", "service.py"]\n' % port)
    _write(out / "docker-compose.yml", f'''services:
  challenge:
    build: .
    ports: ["127.0.0.1::{port}"]
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
''')


def _player_artifacts(out: Path) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for path in sorted((out / "player").rglob("*")):
        if not path.is_file() or path.name in {"flag.txt", "service.py"}:
            continue
        data = path.read_bytes()
        name = path.relative_to(out / "player").as_posix()
        try:
            result[name] = {"encoding": "utf-8", "data": data.decode("utf-8")}
        except UnicodeDecodeError:
            result[name] = {"encoding": "base64", "data": base64.b64encode(data).decode()}
    return result


def _configure_tcp(spec: ChallengeSpec, out: Path) -> None:
    _write(out / "player/flag.txt", spec.flag + "\n")
    _write(out / "player/runtime-artifacts.json", json.dumps(_player_artifacts(out), indent=2))
    _write(out / "player/service.py", '''import json, socketserver
from pathlib import Path

ARTIFACTS=json.loads(Path("runtime-artifacts.json").read_text())
FLAG=Path("flag.txt").read_text().strip()

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"CTF PWN TRAINING SERVICE\\n")
        self.wfile.write(json.dumps(ARTIFACTS).encode()+b"\\n")
        self.wfile.write(b"Submit with: SUBMIT flag{...}\\n> ")
        line=self.rfile.readline(4096).decode(errors="replace").strip()
        answer=line.removeprefix("SUBMIT ").strip()
        self.wfile.write(b"correct\\n" if answer==FLAG else b"incorrect\\n")

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True

Server(("0.0.0.0",31337),Handler).serve_forever()
''')
    _docker(out, 31337)
    _manifest(out, kind="docker", protocol="tcp", service="challenge", container_port=31337,
              client="nc {host} {port}", public=True)


def _configure_ai(spec: ChallengeSpec, out: Path) -> None:
    _write(out / "player/runtime-artifacts.json", json.dumps(_player_artifacts(out), indent=2))
    _write(out / "player/service.py", f'''import json
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs,urlparse

TYPE={spec.challenge_type!r}
ARTIFACTS=json.loads(Path("runtime-artifacts.json").read_text())

class Handler(BaseHTTPRequestHandler):
    def reply(self,value,status=200):
        body=json.dumps(value).encode()
        self.send_response(status);self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
    def do_GET(self):
        route=urlparse(self.path)
        if route.path=="/health": self.reply({{"ok":True,"model":"deterministic-local-ctf"}});return
        if route.path=="/challenge": self.reply({{"type":TYPE,"artifacts":ARTIFACTS}});return
        if route.path=="/query":
            prompt=parse_qs(route.query).get("q",[""])[0]
            self.reply({{"type":TYPE,"prompt":prompt,"artifacts":ARTIFACTS,
                         "notice":"Treat retrieved content as untrusted challenge data."}});return
        self.reply({{"error":"not found"}},404)
    def log_message(self,*args): pass

ThreadingHTTPServer(("0.0.0.0",8000),Handler).serve_forever()
''')
    _docker(out, 8000)
    _manifest(out, kind="docker", protocol="http", service="challenge", container_port=8000,
              client="{url}/challenge", public=True)


def _configure_blockchain(spec: ChallengeSpec, out: Path) -> None:
    artifacts = _player_artifacts(out)
    _write(out / "player/runtime-artifacts.json", json.dumps(artifacts, indent=2))
    _write(out / "player/Challenge.sol", '''// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
contract Challenge {
    bytes32[] private evidence;
    event Evidence(bytes data);
    function evidenceLength() external view returns (uint256) { return evidence.length; }
}
''')
    _write(out / "player/service.py", f'''import json
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path

TYPE={spec.challenge_type!r}
ARTIFACTS=json.loads(Path("runtime-artifacts.json").read_text())

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            n=int(self.headers.get("Content-Length","0"));req=json.loads(self.rfile.read(n))
            method=req.get("method");params=req.get("params",[])
            if method=="eth_chainId": result="0x7a69"
            elif method=="web3_clientVersion": result="CTF-Deterministic-DevChain/1.0"
            elif method=="ctf_getChallenge": result={{"type":TYPE,"artifacts":ARTIFACTS}}
            elif method=="eth_getStorageAt":
                source=json.loads(Path("storage.json").read_text())
                result="0x"+source.get("slots",{{}}).get(params[1],"0"*32)
            elif method=="eth_getLogs":
                result=json.loads(Path("events.json").read_text())
            else: raise ValueError("unsupported local training RPC method")
            payload={{"jsonrpc":"2.0","id":req.get("id"),"result":result}}
        except Exception as exc:
            payload={{"jsonrpc":"2.0","id":None,"error":{{"code":-32602,"message":str(exc)}}}}
        body=json.dumps(payload).encode();self.send_response(200)
        self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(body)))
        self.end_headers();self.wfile.write(body)
    def log_message(self,*args): pass

ThreadingHTTPServer(("0.0.0.0",8545),Handler).serve_forever()
''')
    _docker(out, 8545)
    _manifest(out, kind="docker", protocol="json-rpc", service="challenge", container_port=8545,
              client="RPC {url}", public=True,
              note="Deterministic JSON-RPC dev-chain simulator with a Solidity contract artifact.")


def _mqtt_packet(topic: str, payload: str) -> dict[str, str]:
    return {"topic": topic, "payload": payload}


def _configure_iot(spec: ChallengeSpec, out: Path) -> None:
    seed: list[dict[str, str]] = []
    capture = out / "player/mqtt-capture.json"
    if capture.is_file():
        for message in json.loads(capture.read_text(encoding="utf-8")):
            if message.get("retain"):
                seed.append(_mqtt_packet(message["topic"], message["payload"]))
    if not seed:
        for name, value in _player_artifacts(out).items():
            seed.append(_mqtt_packet(f"ctf/{spec.slug}/{name}", value["data"]))
    _write(out / "player/mqtt-seed.json", json.dumps(seed, indent=2))
    _write(out / "player/service.py", '''import json,socketserver
from pathlib import Path

MESSAGES=json.loads(Path("mqtt-seed.json").read_text())

def remaining(n):
    out=bytearray()
    while True:
        digit=n%128;n//=128
        if n:digit|=128
        out.append(digit)
        if not n:return bytes(out)

def publish(topic,payload):
    topic=topic.encode();payload=payload.encode()
    body=len(topic).to_bytes(2,"big")+topic+payload
    return b"1"+remaining(len(body))+body

class Handler(socketserver.BaseRequestHandler):
    def recv_packet(self):
        first=self.request.recv(1)
        if not first:return None,None
        multiplier=1;length=0
        while True:
            digit=self.request.recv(1)[0];length+=(digit&127)*multiplier
            if not digit&128:break
            multiplier*=128
        data=b""
        while len(data)<length:data+=self.request.recv(length-len(data))
        return first[0],data
    def handle(self):
        while True:
            packet,data=self.recv_packet()
            if packet is None:return
            kind=packet>>4
            if kind==1:self.request.sendall(b" \\x02\\x00\\x00")
            elif kind==8:
                packet_id=data[:2];self.request.sendall(b"\\x90\\x03"+packet_id+b"\\x00")
                for item in MESSAGES:self.request.sendall(publish(item["topic"],item["payload"]))
            elif kind==12:self.request.sendall(b"\\xd0\\x00")
            elif kind==14:return

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True

Server(("0.0.0.0",1883),Handler).serve_forever()
''')
    _docker(out, 1883)
    _manifest(out, kind="docker", protocol="mqtt", service="challenge", container_port=1883,
              client='mosquitto_sub -h {host} -p {port} -t "#" -v', public=True)


def _configure_android(spec: ChallengeSpec, out: Path) -> None:
    _write(out / "launch-android.ps1", '''param([Parameter(Mandatory=$true)][string]$Avd)
$ErrorActionPreference = "Stop"
$emulator = Get-Command emulator -ErrorAction Stop
$adb = Get-Command adb -ErrorAction Stop
Start-Process -FilePath $emulator.Source -ArgumentList @("-avd", $Avd) -PassThru
& $adb.Source wait-for-device
Write-Host "Android emulator is ready. This reverse-engineering challenge is attachment-first; inspect the supplied APK/smali/native artifact with Jadx, apktool, or Ghidra."
''')
    _manifest(out, kind="android", protocol="adb", public=False, launchable=False,
              client="powershell -File launch-android.ps1 -Avd <your-avd>",
              note="Requires Android SDK, adb, and a pre-created AVD. Current mobile templates are reverse-engineering artifacts, not installable production APKs.")


def configure_runtime(spec: ChallengeSpec, out: Path) -> None:
    if spec.delivery == "web":
        _manifest(out, kind="docker", protocol="http", service="challenge", container_port=8000,
                  client="{url}", public=True)
    elif spec.delivery == "tcp":
        _configure_tcp(spec, out)
    elif spec.delivery == "api":
        _configure_ai(spec, out)
    elif spec.delivery == "blockchain":
        _configure_blockchain(spec, out)
    elif spec.delivery == "mqtt":
        _configure_iot(spec, out)
    elif spec.delivery == "android":
        _configure_android(spec, out)
    else:
        _manifest(out, kind="attachment", protocol="download", public=True, launchable=False,
                  client="Download the player bundle")

    _write(out / "deployment.json", json.dumps({
        "slug": spec.slug,
        "delivery": spec.delivery,
        "runtime": json.loads((out / "runtime.json").read_text(encoding="utf-8")),
        "public_files": ["README.md", "challenge.json", "quality.json", "player/"],
        "private_files": ["organizer/"],
    }, ensure_ascii=False, indent=2))
