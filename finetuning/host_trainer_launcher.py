#!/usr/bin/env python3
"""
AIPAM Host Trainer Launcher — Auto-start service for the host trainer.

Runs on the host system (macOS or Linux) alongside Docker. The Docker
backend calls this launcher to start/stop/check the host trainer on demand.

This solves the Docker–host boundary problem: Docker containers cannot
start native host processes, but they CAN send HTTP requests to the host.

Port: 8003 (launcher) → manages → port 8002 (host_trainer)

Usage:
    python finetuning/host_trainer_launcher.py   # started by start.sh
"""

import json
import os
import platform as _platform
import signal
import subprocess
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

IS_LINUX = _platform.system() == "Linux"

PORT = 8003
HOST_TRAINER_PORT = 8002
FINETUNING_DIR = Path(__file__).resolve().parent
HOST_TRAINER_SCRIPT = FINETUNING_DIR / "host_trainer.py"
LOG_FILE = Path("/tmp/aipam_host_trainer.log")
PID_FILE = Path("/tmp/aipam_host_trainer.pid")

_trainer_process = None


def _kill_port(port: int):
    """Kill any process listening on the given port (cross-platform)."""
    try:
        if IS_LINUX:
            subprocess.run(["fuser", "-k", f"{port}/tcp"],
                           capture_output=True, timeout=3)
        else:
            result = subprocess.run(
                ["lsof", "-ti", f":{port}"],
                capture_output=True, text=True, timeout=3,
            )
            if result.stdout.strip():
                for pid in result.stdout.strip().split("\n"):
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                    except (OSError, ValueError):
                        pass
    except Exception:
        pass


def is_trainer_running() -> bool:
    """Check if host_trainer.py is currently running."""
    global _trainer_process
    # Check our tracked process
    if _trainer_process and _trainer_process.poll() is None:
        return True
    # Check PID file
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, 0)  # signal 0 = check if alive
            return True
        except (OSError, ValueError):
            PID_FILE.unlink(missing_ok=True)
    # Check port
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(1)
        sock.connect(("127.0.0.1", HOST_TRAINER_PORT))
        sock.close()
        return True
    except (ConnectionRefusedError, OSError):
        return False


def start_trainer() -> dict:
    """Start the host trainer process."""
    global _trainer_process

    if is_trainer_running():
        return {"status": "already_running", "message": "Host trainer is already running"}

    # Kill any stale process on the port
    _kill_port(HOST_TRAINER_PORT)
    time.sleep(0.5)

    # Launch host_trainer.py
    log_fh = open(LOG_FILE, "a")
    _trainer_process = subprocess.Popen(
        [sys.executable, str(HOST_TRAINER_SCRIPT)],
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        start_new_session=True,  # Detach from launcher
    )

    PID_FILE.write_text(str(_trainer_process.pid))

    # Wait for it to become responsive
    for _ in range(10):
        time.sleep(0.5)
        if is_trainer_running():
            return {
                "status": "started",
                "pid": _trainer_process.pid,
                "message": "Host trainer started successfully",
            }

    return {"status": "error", "message": "Host trainer started but not responding"}


def stop_trainer() -> dict:
    """Stop the host trainer process."""
    global _trainer_process

    killed = False

    # Kill tracked process
    if _trainer_process and _trainer_process.poll() is None:
        _trainer_process.terminate()
        try:
            _trainer_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _trainer_process.kill()
        killed = True
        _trainer_process = None

    # Kill by PID file
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            killed = True
        except (OSError, ValueError):
            pass
        PID_FILE.unlink(missing_ok=True)

    # Kill anything on the port
    _kill_port(HOST_TRAINER_PORT)
    killed = True

    if killed:
        return {"status": "stopped", "message": "Host trainer stopped"}
    return {"status": "not_running", "message": "Host trainer was not running"}


class LauncherHandler(BaseHTTPRequestHandler):
    """HTTP handler for launcher commands."""

    def do_POST(self):
        if self.path == "/start":
            result = start_trainer()
            self._respond(200, result)
        elif self.path == "/stop":
            result = stop_trainer()
            self._respond(200, result)
        elif self.path == "/restart":
            stop_trainer()
            time.sleep(1)
            result = start_trainer()
            self._respond(200, result)
        else:
            self._respond(404, {"error": "Not found"})

    def do_GET(self):
        if self.path == "/status":
            running = is_trainer_running()
            self._respond(200, {
                "trainer_running": running,
                "trainer_port": HOST_TRAINER_PORT,
                "launcher_port": PORT,
            })
        elif self.path == "/health":
            self._respond(200, {"status": "ok"})
        else:
            self._respond(404, {"error": "Not found"})

    def _respond(self, code: int, body: dict):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, format, *args):
        print(f"[LAUNCHER] {args[0]}")


def main():
    print("=" * 60)
    print("AIPAM Host Trainer Launcher")
    print("=" * 60)
    print(f"Launcher port: {PORT}")
    print(f"Trainer port:  {HOST_TRAINER_PORT}")
    print(f"Trainer script: {HOST_TRAINER_SCRIPT}")
    print(f"Trainer log:    {LOG_FILE}")
    print()
    print("The Docker backend calls this launcher to auto-start")
    print("the host trainer when a training job is requested.")
    print("=" * 60)

    server = HTTPServer(("0.0.0.0", PORT), LauncherHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[LAUNCHER] Shutting down...")
        stop_trainer()
        server.server_close()


if __name__ == "__main__":
    main()
