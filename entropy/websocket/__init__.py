"""WebSocket fuzzer for ws:// and wss:// endpoints."""
from __future__ import annotations

import base64
import hashlib
import json
import random
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Minimal WebSocket client (stdlib only)
# ---------------------------------------------------------------------------

class _WSClient:
    """Bare-bones WebSocket client without external dependencies."""

    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, url: str, timeout: float = 10.0, verify_ssl: bool = True):
        self.url     = url
        self.timeout = timeout
        parsed       = urlparse(url)
        self.host    = parsed.hostname or "localhost"
        self.port    = parsed.port or (443 if parsed.scheme == "wss" else 80)
        self.path    = parsed.path or "/"
        self.ssl     = parsed.scheme == "wss"
        self._sock: Optional[socket.socket] = None
        self._verify_ssl = verify_ssl

    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.ssl:
            ctx = ssl.create_default_context()
            if not self._verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
            self._sock = ctx.wrap_socket(raw, server_hostname=self.host)
        else:
            self._sock = raw

        # Handshake
        key      = base64.b64encode(random.randbytes(16)).decode()
        expected = base64.b64encode(
            hashlib.sha1((key + self.GUID).encode()).digest()
        ).decode()

        handshake = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self._sock.sendall(handshake.encode())

        # Read response headers
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self._sock.recv(1024)
            if not chunk:
                raise ConnectionError("WebSocket handshake failed")
            resp += chunk

        if b"101" not in resp:
            raise ConnectionError(f"WebSocket upgrade rejected: {resp[:200]}")

    def send(self, payload: Any) -> None:
        if isinstance(payload, dict):
            data = json.dumps(payload).encode()
        elif isinstance(payload, str):
            data = payload.encode()
        else:
            data = payload

        # Build masked frame (opcode=0x1 text)
        mask_key = random.randbytes(4)
        masked   = bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))
        length   = len(data)
        if length <= 125:
            header = struct.pack("BB", 0x81, 0x80 | length)
        elif length <= 65535:
            header = struct.pack("!BBH", 0x81, 0xFE, length)
        else:
            header = struct.pack("!BBQ", 0x81, 0xFF, length)
        self._sock.sendall(header + mask_key + masked)

    def recv(self) -> Optional[Any]:
        try:
            self._sock.settimeout(3.0)
            header = self._recvall(2)
            if not header:
                return None
            opcode = header[0] & 0x0F
            length = header[1] & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._recvall(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._recvall(8))[0]
            raw = self._recvall(length)
            try:
                return json.loads(raw.decode())
            except Exception:
                return raw.decode(errors="replace")
        except (socket.timeout, OSError):
            return None

    def _recvall(self, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = self._sock.recv(n - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.sendall(b"\x88\x80\x00\x00\x00\x00")  # close frame
                self._sock.close()
            except Exception:
                pass
            self._sock = None


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@dataclass
class WSFinding:
    title:       str
    description: str
    severity:    str
    payload:     Any
    response:    Any
    url:         str


# ---------------------------------------------------------------------------
# Fuzzer
# ---------------------------------------------------------------------------

class WebSocketFuzzer:
    """
    Fuzz a WebSocket endpoint with a battery of attack payloads.
    """

    PAYLOADS: List[Any] = [
        # Injection
        {"action": "login", "username": "' OR '1'='1", "password": "x"},
        {"action": "eval",  "expr": "${7*7}"},
        {"action": "cmd",   "cmd": "; cat /etc/passwd"},
        # Oversized
        {"action": "search", "query": "A" * 100_000},
        # Type confusion
        {"action": True, "data": None},
        {"action": 12345},
        # Empty/null
        {},
        None,
        "",
        # Prototype pollution
        {"__proto__": {"admin": True}},
        {"constructor": {"prototype": {"admin": True}}},
        # Auth bypass
        {"action": "admin", "token": "null"},
        {"action": "admin", "token": ""},
        {"action": "get_users", "role": "admin"},
        # DoS
        [{"x": i} for i in range(1000)],
    ]

    def __init__(
        self,
        url: str,
        timeout: float = 8.0,
        verify_ssl: bool = True,
        verbose: bool = False,
    ):
        self.url        = url
        self.timeout    = timeout
        self.verify_ssl = verify_ssl
        self.verbose    = verbose

    def fuzz(self) -> List[WSFinding]:
        findings: List[WSFinding] = []

        for payload in self.PAYLOADS:
            finding = self._test_payload(payload)
            if finding:
                findings.append(finding)
                if self.verbose:
                    print(f"  [WS] [{finding.severity.upper()}] {finding.title}")

        return findings

    def _test_payload(self, payload: Any) -> Optional[WSFinding]:
        client = _WSClient(self.url, timeout=self.timeout, verify_ssl=self.verify_ssl)
        try:
            client.connect()
            start = time.monotonic()
            client.send(payload)
            response = client.recv()
            latency  = (time.monotonic() - start) * 1000
        except ConnectionError as exc:
            # Connection refused entirely — might be expected
            return None
        except Exception as exc:
            return WSFinding(
                title       = "WebSocket error on fuzz payload",
                description = str(exc),
                severity    = "medium",
                payload     = payload,
                response    = None,
                url         = self.url,
            )
        finally:
            client.close()

        return self._analyse(payload, response, latency)

    def _analyse(self, payload: Any, response: Any, latency_ms: float) -> Optional[WSFinding]:
        resp_str = str(response).lower()

        # Crash indicators
        if response is None:
            return WSFinding(
                title       = "WebSocket connection dropped after fuzz",
                description = "Server closed connection after receiving fuzz payload — possible crash/DoS.",
                severity    = "high",
                payload     = payload,
                response    = response,
                url         = self.url,
            )

        # Error/stack traces leaked
        for indicator in ("traceback", "exception", "stack trace", "internal server error", "unhandled"):
            if indicator in resp_str:
                return WSFinding(
                    title       = "WebSocket server error leaked in response",
                    description = f"Server returned error details: '{indicator}' found in response.",
                    severity    = "high",
                    payload     = payload,
                    response    = response,
                    url         = self.url,
                )

        # Injection reflection
        if isinstance(payload, dict):
            payload_str = str(payload).lower()
            for marker in ("49", "root:", "syntax error"):   # 7*7=49, etc.
                if marker in payload_str and marker in resp_str:
                    return WSFinding(
                        title       = "Injection reflected in WebSocket response",
                        description = f"Marker '{marker}' reflected — possible template/command injection.",
                        severity    = "critical",
                        payload     = payload,
                        response    = response,
                        url         = self.url,
                    )

        # Latency spike
        if latency_ms > 5000:
            return WSFinding(
                title       = "WebSocket latency spike",
                description = f"Response took {latency_ms:.0f}ms — possible DoS vector.",
                severity    = "medium",
                payload     = payload,
                response    = response,
                url         = self.url,
            )

        return None
