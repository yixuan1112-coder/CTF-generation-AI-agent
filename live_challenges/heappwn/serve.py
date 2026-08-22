"""Bridge TCP <-> the vulnerable binary, one process per connection, flag in env."""
import os
import socket
import subprocess
import threading

BIN = "/app/chall"


def handle(conn):
    # The child does blocking read() on this fd; a Python timeout would put the
    # socket in non-blocking mode and make read() return EAGAIN, so keep it blocking
    # and enforce the time limit by killing the child instead.
    conn.setblocking(True)
    try:
        fd = conn.fileno()
        p = subprocess.Popen([BIN], stdin=fd, stdout=fd, stderr=subprocess.DEVNULL,
                             env={"FLAG": os.environ.get("FLAG", "flag{replace_at_deployment}"),
                                  "PATH": "/usr/bin:/bin"})
        # kill the child if it outlives the socket timeout window
        timer = threading.Timer(90, lambda: p.poll() is None and p.kill())
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
    print(f"heappwn listening on 0.0.0.0:{port}", flush=True)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
