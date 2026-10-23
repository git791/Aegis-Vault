"""
Tests for local HTTP server, Host header enforcement, and REST endpoints.
Uses an in-memory socket harness to test AegisRequestHandler directly.
"""

import base64
import io
import json
import pytest

from aegis.server import AegisRequestHandler


class MockSocket:
    """In-memory duplex socket simulator for testing HTTP request handlers."""

    def __init__(self, request_bytes: bytes):
        self.rfile = io.BytesIO(request_bytes)
        self.wfile = io.BytesIO()

    def makefile(self, mode, *args, **kwargs):
        if "r" in mode:
            return self.rfile
        return self.wfile

    def sendall(self, data: bytes) -> None:
        self.wfile.write(data)


def execute_request(method: str, path: str, headers: dict, body: bytes = b"") -> tuple[int, dict, bytes]:
    """Execute request through AegisRequestHandler and return (status, headers, body)."""
    req_lines = [f"{method} {path} HTTP/1.1"]
    for k, v in headers.items():
        req_lines.append(f"{k}: {v}")
    if body and "Content-Length" not in headers:
        req_lines.append(f"Content-Length: {len(body)}")
    req_lines.append("")
    req_lines.append("")

    raw_req = "\r\n".join(req_lines).encode("utf-8") + body
    sock = MockSocket(raw_req)

    # Instantiate handler (which runs handle() and writes response to sock.wfile)
    AegisRequestHandler(sock, ("127.0.0.1", 12345), None)

    raw_resp = sock.wfile.getvalue()
    header_part, _, body_part = raw_resp.partition(b"\r\n\r\n")

    lines = header_part.decode("utf-8", errors="replace").split("\r\n")
    status_line = lines[0]
    status_code = int(status_line.split(" ")[1])

    resp_headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            resp_headers[k.strip().lower()] = v.strip()

    return status_code, resp_headers, body_part


def test_server_health():
    status, headers, body = execute_request(
        "GET", "/api/health", headers={"Host": "127.0.0.1:8000"}
    )
    assert status == 200
    data = json.loads(body.decode())
    assert data["status"] == "ok"


def test_forbidden_host_header_rejected():
    # Rule 5 / PRD: Server must reject unexpected Host headers (e.g. DNS rebinding)
    status, headers, body = execute_request(
        "GET", "/api/health", headers={"Host": "evil.attacker.com"}
    )
    assert status == 403
    data = json.loads(body.decode())
    assert data["success"] is False
    assert "forbidden" in data["error"].lower()


def test_api_encrypt_decrypt_roundtrip():
    secret_message = b"Secret payload transferred through local HTTP API"
    pwd = "ApiPassword123"

    # Encrypt
    enc_payload = {
        "filename": "notes.txt",
        "data_base64": base64.b64encode(secret_message).decode("ascii"),
        "password": pwd,
    }
    enc_body = json.dumps(enc_payload).encode("utf-8")
    status, _, body = execute_request(
        "POST",
        "/api/encrypt",
        headers={"Host": "127.0.0.1:8000", "Content-Type": "application/json"},
        body=enc_body,
    )
    assert status == 200
    enc_res = json.loads(body.decode())
    assert enc_res["success"] is True
    assert enc_res["filename"] == "notes.txt.aegis"
    container_b64 = enc_res["container_base64"]

    # Decrypt
    dec_payload = {
        "filename": "notes.txt.aegis",
        "container_base64": container_b64,
        "password": pwd,
    }
    dec_body = json.dumps(dec_payload).encode("utf-8")
    status, _, body = execute_request(
        "POST",
        "/api/decrypt",
        headers={"Host": "127.0.0.1:8000", "Content-Type": "application/json"},
        body=dec_body,
    )
    assert status == 200
    dec_res = json.loads(body.decode())
    assert dec_res["success"] is True
    restored = base64.b64decode(dec_res["data_base64"])
    assert restored == secret_message


def test_api_decrypt_wrong_password_fails():
    enc_payload = {
        "filename": "file.dat",
        "data_base64": base64.b64encode(b"content").decode("ascii"),
        "password": "RealPassword",
    }
    status, _, body = execute_request(
        "POST",
        "/api/encrypt",
        headers={"Host": "127.0.0.1:8000", "Content-Type": "application/json"},
        body=json.dumps(enc_payload).encode("utf-8"),
    )
    assert status == 200
    container_b64 = json.loads(body.decode())["container_base64"]

    # Try decrypt with wrong password
    dec_payload = {
        "filename": "file.dat.aegis",
        "container_base64": container_b64,
        "password": "WrongPassword",
    }
    status, _, body = execute_request(
        "POST",
        "/api/decrypt",
        headers={"Host": "127.0.0.1:8000", "Content-Type": "application/json"},
        body=json.dumps(dec_payload).encode("utf-8"),
    )
    assert status == 401
    dec_res = json.loads(body.decode())
    assert dec_res["success"] is False
    assert dec_res["error_type"] == "AuthenticationError"


def test_api_inspect():
    enc_payload = {
        "filename": "inspect.txt",
        "data_base64": base64.b64encode(b"abc").decode("ascii"),
        "password": "pwd",
    }
    _, _, body = execute_request(
        "POST",
        "/api/encrypt",
        headers={"Host": "127.0.0.1:8000", "Content-Type": "application/json"},
        body=json.dumps(enc_payload).encode("utf-8"),
    )
    container_b64 = json.loads(body.decode())["container_base64"]

    insp_body = json.dumps({"container_base64": container_b64}).encode("utf-8")
    status, _, body = execute_request(
        "POST",
        "/api/inspect",
        headers={"Host": "127.0.0.1:8000", "Content-Type": "application/json"},
        body=insp_body,
    )
    assert status == 200
    res = json.loads(body.decode())
    assert res["success"] is True
    assert res["version"] == 1
    assert res["slot_count"] == 1


def test_api_static_ui():
    status, headers, body = execute_request(
        "GET", "/", headers={"Host": "localhost:8000"}
    )
    assert status == 200
    html = body.decode("utf-8")
    assert "Aegis Vault" in html
    assert "AES X-Ray" in html
