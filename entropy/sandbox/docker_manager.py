"""Docker sandbox — isolated containers for live testing."""
from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SandboxConfig:
    image:         str   = "nginx:alpine"   # target image to test
    network_name:  str   = field(default_factory=lambda: f"entropy-net-{uuid.uuid4().hex[:8]}")
    container_name: str  = field(default_factory=lambda: f"entropy-target-{uuid.uuid4().hex[:8]}")
    env:           Dict[str, str] = field(default_factory=dict)
    ports:         Dict[int, int] = field(default_factory=lambda: {80: 0})  # container:host
    startup_wait:  float = 3.0    # seconds to wait for container to be ready
    auto_destroy:  bool  = True   # destroy sandbox after run


@dataclass
class SandboxInfo:
    container_id:   str = ""
    container_name: str = ""
    network_id:     str = ""
    network_name:   str = ""
    host_port:      int = 0
    base_url:       str = ""
    running:        bool = False


# ---------------------------------------------------------------------------
# Sandbox Manager
# ---------------------------------------------------------------------------

class SandboxManager:
    """
    Manages an ephemeral Docker sandbox for safe chaos testing.

    If Docker is unavailable, falls back to a no-op stub so the rest of
    the framework can continue operating.
    """

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config  = config or SandboxConfig()
        self._info   = SandboxInfo()
        self._docker_available = self._check_docker()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def info(self) -> SandboxInfo:
        return self._info

    def setup(self) -> SandboxInfo:
        """Create network + container. Returns SandboxInfo."""
        if not self._docker_available:
            print("  [sandbox] Docker not available — running in no-sandbox mode.")
            self._info.base_url = "http://localhost"
            self._info.running  = False
            return self._info

        try:
            self._create_network()
            self._start_container()
            self._wait_for_ready()
            self._info.running = True
            print(f"  [sandbox] ✓ Sandbox ready at {self._info.base_url}")
        except Exception as exc:
            print(f"  [sandbox] ✗ Failed to start sandbox: {exc}")
            self.teardown()
        return self._info

    def teardown(self) -> None:
        """Stop + remove container and network."""
        if not self._docker_available:
            return
        if self._info.container_id:
            self._run(["docker", "rm", "-f", self._info.container_id], check=False)
            print(f"  [sandbox] Container {self._info.container_name} removed.")
        if self._info.network_id:
            self._run(["docker", "network", "rm", self._info.network_id], check=False)
            print(f"  [sandbox] Network {self._info.network_name} removed.")
        self._info.running = False

    def __enter__(self) -> SandboxInfo:
        return self.setup()

    def __exit__(self, *args) -> None:
        if self.config.auto_destroy:
            self.teardown()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _create_network(self) -> None:
        result = self._run([
            "docker", "network", "create",
            "--driver", "bridge",
            self.config.network_name,
        ])
        self._info.network_id   = result.stdout.strip()
        self._info.network_name = self.config.network_name

    def _start_container(self) -> None:
        cmd = [
            "docker", "run", "-d",
            "--name", self.config.container_name,
            "--network", self.config.network_name,
        ]
        # Environment variables
        for k, v in self.config.env.items():
            cmd += ["-e", f"{k}={v}"]
        # Port mappings
        for container_port, host_port in self.config.ports.items():
            if host_port == 0:
                cmd += ["-P"]  # random host port
            else:
                cmd += ["-p", f"{host_port}:{container_port}"]
        cmd.append(self.config.image)

        result = self._run(cmd)
        self._info.container_id   = result.stdout.strip()
        self._info.container_name = self.config.container_name

        # Discover actual host port
        port_result = self._run([
            "docker", "port", self._info.container_id,
        ])
        for line in port_result.stdout.splitlines():
            # e.g.  80/tcp -> 0.0.0.0:32768
            if "->" in line:
                host_addr = line.split("->")[-1].strip()
                host_port = int(host_addr.split(":")[-1])
                self._info.host_port = host_port
                self._info.base_url  = f"http://localhost:{host_port}"
                break

    def _wait_for_ready(self) -> None:
        deadline = time.monotonic() + self.config.startup_wait + 10
        while time.monotonic() < deadline:
            result = self._run(
                ["docker", "inspect", "--format", "{{.State.Status}}", self._info.container_id],
                check=False,
            )
            if "running" in result.stdout.lower():
                time.sleep(self.config.startup_wait)  # allow app to initialise
                return
            time.sleep(0.5)
        raise TimeoutError("Container did not reach 'running' state in time.")

    @staticmethod
    def _run(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check,
        )

    @staticmethod
    def _check_docker() -> bool:
        try:
            subprocess.run(
                ["docker", "info"],
                capture_output=True,
                check=True,
                timeout=5,
            )
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Docker Compose support
# ---------------------------------------------------------------------------

class DockerComposeSandbox:
    """
    Variant that uses a docker-compose.yml to spin up the test environment.
    Useful when the target app has multiple services (DB, cache, etc.).
    """

    def __init__(self, compose_file: str, service: str = "", startup_wait: float = 5.0):
        self.compose_file = compose_file
        self.service      = service
        self.startup_wait = startup_wait
        self._up          = False

    def setup(self) -> None:
        cmd = ["docker-compose", "-f", self.compose_file, "up", "-d"]
        if self.service:
            cmd.append(self.service)
        subprocess.run(cmd, check=True)
        time.sleep(self.startup_wait)
        self._up = True
        print(f"  [compose] ✓ docker-compose services started.")

    def teardown(self) -> None:
        if not self._up:
            return
        subprocess.run(
            ["docker-compose", "-f", self.compose_file, "down", "--volumes"],
            check=False,
        )
        print("  [compose] docker-compose services stopped.")

    def __enter__(self):
        self.setup()
        return self

    def __exit__(self, *args):
        self.teardown()
