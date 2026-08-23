"""Bridge TCP <-> the vulnerable binary, one process per connection, flag in env."""
import os
import socket
import subprocess
import threading

BIN = "/app/chall"


def handle(conn):
    conn.setblocking(True)
    try:
        fd = conn.fileno()
        p = subprocess.Popen([BIN], stdin=fd, stdout=fd, stderr=subprocess.DEVNULL,
                             env={"FLAG": os.environ.get("FLAG", "flag{replace_at_deployment}"),
                                  "PATH": "/usr/bin:/bin"})
        timer = threading.Timer(60, lambda: p.poll() is None and p.kill())
        timer.start()
        p.wait()
        timer.cancel()
    except (OSError, ConnectionError):
        pass
    finally:
        conn.close()


def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)
    print(f"heaptcache listening on 0.0.0.0:{port}", flush=True)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
