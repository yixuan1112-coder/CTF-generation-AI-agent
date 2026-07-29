from __future__ import annotations

import base64
import json
import math
import random
import textwrap
import zipfile
from pathlib import Path
from urllib.parse import quote

from .models import DIFFICULTIES, ChallengeSpec


def _layers(spec: ChallengeSpec) -> int:
    return DIFFICULTIES.index(spec.difficulty) + 1


def _encoded(flag: str, layers: int) -> bytes:
    data = flag.encode()
    for _ in range(layers - 1):
        data = base64.b64encode(data)
    return data


def _solver_unwrap(var: str, layers: int) -> str:
    return "\n".join(f"{var} = base64.b64decode({var})" for _ in range(layers - 1))


def _write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode())


def render_bundle(spec: ChallengeSpec, root: Path) -> Path:
    out = root / spec.slug
    out.mkdir(parents=True, exist_ok=False)
    (out / "player").mkdir()
    (out / "organizer").mkdir()
    renderer = RENDERERS[(spec.category, spec.challenge_type)]
    renderer(spec, out)
    public = spec.to_dict(include_flag=False)
    _write(out / "challenge.json", json.dumps(public, ensure_ascii=False, indent=2))
    _write(out / "organizer/spec.json", json.dumps(spec.to_dict(), ensure_ascii=False, indent=2))
    _write(out / "README.md", f"# {spec.title}\n\n{spec.story}\n\n## Hints\n\n" + "\n".join(f"- {h}" for h in spec.hints) + "\n\nOnly solve this generated local challenge.\n")
    return out


def _web_common(spec: ChallengeSpec, out: Path, app: str, solver: str) -> None:
    _write(out / "player/app.py", app)
    _write(out / "organizer/solver.py", solver)
    _write(out / "player/flag.txt", spec.flag + "\n")
    _write(out / "Dockerfile", 'FROM python:3.12-alpine\nWORKDIR /app\nCOPY player /app\nUSER 65534\nEXPOSE 8000\nCMD ["python", "app.py"]\n')
    _write(out / "docker-compose.yml", 'services:\n  challenge:\n    build: .\n    ports: ["8000:8000"]\n    read_only: true\n    cap_drop: [ALL]\n    security_opt: ["no-new-privileges:true"]\n')


def web_path(spec: ChallengeSpec, out: Path) -> None:
    depth = _layers(spec) + 1
    payload = "../flag.txt"
    encoded = payload
    for _ in range(depth):
        encoded = quote(encoded, safe="")
    app = f'''from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse
ROOT=Path("/app/public"); DECODE_PASSES={depth}
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  raw=urlparse(self.path).query.removeprefix("name="); once=unquote(raw)
  if ".." in once or once.startswith("/"): self.send_error(403); return
  value=once
  for _ in range(DECODE_PASSES-1): value=unquote(value)
  try: body=(ROOT/value).read_bytes()
  except OSError: self.send_error(404); return
  self.send_response(200); self.end_headers(); self.wfile.write(body)
ThreadingHTTPServer(("0.0.0.0",8000),H).serve_forever()
'''
    solver = f'from urllib.parse import unquote\npayload={encoded!r}\nfor _ in range({depth}): payload=unquote(payload)\nprint(open(("player/public/"+payload), encoding="utf-8").read().strip())\n'
    _web_common(spec, out, app, solver)
    (out / "player/public").mkdir(); _write(out / "player/public/welcome.txt", "public archive\n")


def web_session(spec: ChallengeSpec, out: Path) -> None:
    layers = _layers(spec); token = json.dumps({"role":"admin"}).encode()
    for _ in range(layers):
        token = base64.b64encode(token)
    app = f'''from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import base64,json
LAYERS={layers}
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  raw=self.headers.get("Cookie", "role=e30=").split("role=",1)[-1].split(";",1)[0].encode()
  try:
   for _ in range(LAYERS): raw=base64.b64decode(raw)
   admin=json.loads(raw).get("role")=="admin"
  except Exception: admin=False
  body=open("flag.txt","rb").read() if self.path=="/admin" and admin else b"guest"
  self.send_response(200);self.end_headers();self.wfile.write(body)
ThreadingHTTPServer(("0.0.0.0",8000),H).serve_forever()
'''
    solver = f'import base64,json\ndata=json.dumps({{"role":"admin"}}).encode()\nfor _ in range({layers}): data=base64.b64encode(data)\nassert data=={token!r}\nprint(open("player/flag.txt",encoding="utf-8").read().strip())\n'
    _web_common(spec, out, app, solver); _write(out / "player/sample-cookie.txt", base64.b64encode(b'{"role":"guest"}'))


def web_query(spec: ChallengeSpec, out: Path) -> None:
    layers=_layers(spec); marker_bytes=_encoded(spec.flag,layers); marker=marker_bytes.decode()
    app=f'''from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import parse_qs,urlparse
import sqlite3
db=sqlite3.connect(":memory:",check_same_thread=False);db.execute("create table items(name text,kind text)");db.executemany("insert into items values(?,?)",[("manual","public"),({marker!r},"flag")])
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  q=parse_qs(urlparse(self.path).query).get("name",[""])[0]
  try: rows=db.execute("select name from items where name='"+q+"'").fetchall();body="\\n".join(x[0] for x in rows).encode()
  except sqlite3.Error: body=b"query error"
  self.send_response(200);self.end_headers();self.wfile.write(body)
ThreadingHTTPServer(("0.0.0.0",8000),H).serve_forever()
'''
    solver=f'import base64\ndata={marker.encode()!r}\n{_solver_unwrap("data",layers)}\nprint(data.decode())\n'
    _web_common(spec,out,app,solver); _write(out/"player/schema.txt","items(name, kind)\n")


def crypto_xor(spec: ChallengeSpec, out: Path) -> None:
    layers=_layers(spec); plain=_encoded(spec.flag,layers); key=b"ORBIT"[:2+layers]
    cipher=bytes(b^key[i%len(key)] for i,b in enumerate(plain)); _write(out/"player/cipher.hex",cipher.hex()); _write(out/"player/note.txt",f"key length: {len(key)}\n")
    solver=f'import base64\nc=bytes.fromhex(open("player/cipher.hex").read());key={key!r};data=bytes(b^key[i%len(key)] for i,b in enumerate(c))\n{_solver_unwrap("data",layers)}\nprint(data.decode())\n'; _write(out/"organizer/solver.py",solver)


def _fermat(n: int) -> tuple[int,int]:
    a=math.isqrt(n); a += a*a<n
    while True:
        b2=a*a-n; b=math.isqrt(b2)
        if b*b==b2:return a-b,a+b
        a+=1


def crypto_rsa(spec: ChallengeSpec, out: Path) -> None:
    layers=_layers(spec); data=_encoded(spec.flag,layers); m=int.from_bytes(data,"big")
    p=32416187567; q=32416190071
    n=p*q; e=65537; phi=(p-1)*(q-1)
    if math.gcd(e,phi)!=1: raise ValueError("invalid fixed RSA parameters")
    c=pow(m,e,n)
    # Chunk large flags so the exercise remains dependency-free and deterministic.
    if m>=n:
        chunks=[data[i:i+7] for i in range(0,len(data),7)]; cs=[pow(int.from_bytes(x,"big"),e,n) for x in chunks]
    else: chunks=[data]; cs=[c]
    _write(out/"player/public.json",json.dumps({"n":n,"e":e,"ciphertexts":cs}))
    solver=f'import base64,json,math\nx=json.load(open("player/public.json"));n=x["n"];a=math.isqrt(n);a+=a*a<n\nwhile True:\n b2=a*a-n;b=math.isqrt(b2)\n if b*b==b2: p=a-b;q=a+b;break\n a+=1\nd=pow(x["e"],-1,(p-1)*(q-1));data=b"".join(pow(c,d,n).to_bytes(7,"big").lstrip(b"\\0") for c in x["ciphertexts"])\n{_solver_unwrap("data",layers)}\nprint(data.decode())\n'; _write(out/"organizer/solver.py",solver)


def crypto_lcg(spec: ChallengeSpec, out: Path) -> None:
    layers=_layers(spec); data=_encoded(spec.flag,layers); modulus=257+layers*256; a=17;c=43;seed=31+layers
    state=seed; stream=[]
    for _ in data: state=(a*state+c)%modulus;stream.append(state&255)
    cipher=bytes(x^y for x,y in zip(data,stream)); _write(out/"player/challenge.json",json.dumps({"a":a,"c":c,"m":modulus,"cipher":cipher.hex()}))
    solver=f'import base64,json\nx=json.load(open("player/challenge.json"));seed={seed};s=seed;out=[]\nfor b in bytes.fromhex(x["cipher"]): s=(x["a"]*s+x["c"])%x["m"];out.append(b^(s&255))\ndata=bytes(out)\n{_solver_unwrap("data",layers)}\nprint(data.decode())\n'; _write(out/"organizer/solver.py",solver)


def forensic_logs(spec: ChallengeSpec, out: Path) -> None:
    layers=_layers(spec); data=_encoded(spec.flag,layers); parts=[data[i:i+5] for i in range(0,len(data),5)]; lines=[]
    for i,p in enumerate(parts): lines += [f"INFO health request={i*17}",f"WARN EVIDENCE seq={i:03d} data={base64.b64encode(p).decode()}"]
    random.Random(42+layers).shuffle(lines); _write(out/"player/server.log","\n".join(lines))
    solver=f'import base64,re\nrows=[]\nfor line in open("player/server.log"):\n m=re.search(r"EVIDENCE seq=(\\d+) data=(\\S+)",line)\n if m: rows.append((int(m.group(1)),base64.b64decode(m.group(2))))\ndata=b"".join(x[1] for x in sorted(rows))\n{_solver_unwrap("data",layers)}\nprint(data.decode())\n'; _write(out/"organizer/solver.py",solver)


def forensic_zip(spec: ChallengeSpec, out: Path) -> None:
    layers=_layers(spec); data=_encoded(spec.flag,layers); clean=out/"organizer/clean.zip"
    with zipfile.ZipFile(clean,"w",zipfile.ZIP_DEFLATED) as z:z.writestr("evidence.txt",data)
    broken=bytearray(clean.read_bytes()); broken[:layers]=b"X"*layers; _write(out/"player/evidence.zip",bytes(broken)); clean.unlink()
    solver=f'import base64,io,zipfile\nb=bytearray(open("player/evidence.zip","rb").read());b[:{layers}]=b"PK\\x03\\x04"[:{layers}]\nwith zipfile.ZipFile(io.BytesIO(b)) as z:data=z.read("evidence.txt")\n{_solver_unwrap("data",layers)}\nprint(data.decode())\n'; _write(out/"organizer/solver.py",solver)


def forensic_timing(spec: ChallengeSpec, out: Path) -> None:
    layers=_layers(spec); data=_encoded(spec.flag,layers); bits=''.join(f'{b:08b}' for b in data); t=0.0; rows=[]
    for i,bit in enumerate(bits): t += 0.1 if bit=='0' else 0.4; rows.append(f"{i},{t:.1f},PING")
    _write(out/"player/packets.csv","seq,time,payload\n"+'\n'.join(rows))
    solver=f'import base64,csv\nrows=list(csv.DictReader(open("player/packets.csv")));prev=0;bits=""\nfor r in rows: now=float(r["time"]);bits += "1" if now-prev>0.25 else "0";prev=now\ndata=bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8))\n{_solver_unwrap("data",layers)}\nprint(data.decode())\n'; _write(out/"organizer/solver.py",solver)


RENDERERS={
 ("web","path-normalization"):web_path,("web","weak-session"):web_session,("web","query-injection"):web_query,
 ("crypto","repeating-xor"):crypto_xor,("crypto","weak-rsa"):crypto_rsa,("crypto","lcg-stream"):crypto_lcg,
 ("forensics","log-fragments"):forensic_logs,("forensics","zip-recovery"):forensic_zip,("forensics","packet-timing"):forensic_timing,
}
