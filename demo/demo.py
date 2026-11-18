"""Run a bounded two-agent demo. Requires root to attach eBPF programs."""
import contextlib
import json
from pathlib import Path
import select
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time


def line(child, expected):
    if not select.select([child.stdout], [], [], 12)[0] or child.stdout.readline().strip() != expected:
        raise RuntimeError(f"{child.args[0]} did not report {expected}")


def server(listener, cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    conn, _ = listener.accept()
    with ctx.wrap_socket(conn, server_side=True) as stream:
        if stream.recv(64) == b"agent-demo/ping":
            stream.sendall(b"agent-demo/pong")


def run(folder, output):
    (folder / "config").touch()
    (folder / "shared").touch()
    cert, key = folder / "cert.pem", folder / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "1", "-subj", "/CN=localhost", "-keyout", key,
                    "-out", cert], check=True, stderr=subprocess.DEVNULL)
    with socket.socket() as listener, contextlib.ExitStack() as cleanup:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        threading.Thread(target=server, args=(listener, cert, key), daemon=True).start()
        workers = []
        for name in ("A", "B"):
            args = ["./demo-agent", name, folder, str(listener.getsockname()[1]), cert]
            child = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            cleanup.callback(finish, child)
            line(child, "ready")
            workers.append(child)
        a, b = (p.pid for p in workers)
        args = ["./agentsnoop", "--pid", str(a), "--pid", str(b),
                "--sensitive", folder / "secret.demo", "--tls-demo", str(a)]
        with output.open("x") as log:
            mon = subprocess.Popen(args, stdout=log)
            cleanup.callback(finish, mon)
            deadline = time.monotonic() + 12
            while '"ready"' not in output.read_text():
                if mon.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("monitor did not start")
                time.sleep(.02)
            for child in workers:
                child.stdin.write("\n")
                child.stdin.flush()
            for child in workers:
                line(child, "done")
            mon.send_signal(signal.SIGINT)
            if mon.wait(timeout=12):
                raise RuntimeError("monitor failed")
        records = [json.loads(s) for s in output.read_text().splitlines()]
        print(f"Agent A={a}  Agent B={b}")
        for row in records:
            if row["type"] in ("alert", "health") or row.get("event") in ("ssl_write", "ssl_read"):
                print(json.dumps(row, ensure_ascii=False))
        if len(sys.argv) > 1:
            print(f"完整事件与内核栈: {output}")



def finish(child):
    if child.poll() is None:
        if child.stdin:
            child.stdin.close()
        else:
            child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="agentsnoop-") as tmp:
        folder = Path(tmp)
        run(folder, Path(sys.argv[1]) if len(sys.argv) > 1 else folder / "trace.jsonl")
