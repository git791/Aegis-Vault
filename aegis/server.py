"""
Local HTTP Server for Aegis Vault.
Binds strictly to 127.0.0.1, enforces Host header checks to prevent DNS rebinding,
serves the single-page Vault Glass UI and local crypto REST endpoints.
"""

from __future__ import annotations

import base64
import io
import json
import os
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from aegis.avalanche import run_avalanche_experiment
from aegis.container import ContainerHeader
from aegis.engine import decrypt_stream, encrypt_stream
from aegis.errors import AegisError, AuthenticationError, TamperError
from aegis.kdf import KDFParams
from aegis.slots import inspect_file
from aegis.strength import analyze_password
from aegis.xray import aes_xray_trace

STATIC_DIR = Path(__file__).parent / "ui"
ALLOWED_HOST_PREFIXES = ("127.0.0.1", "localhost")


class AegisRequestHandler(BaseHTTPRequestHandler):
    """Secure local HTTP request handler."""

    server_version = "AegisVault/0.1"

    def _validate_host_header(self) -> bool:
        """Enforce strict host-header check to prevent DNS rebinding attacks."""
        host = self.headers.get("Host", "").strip().lower()
        if not host:
            self._send_error_json(HTTPStatus.FORBIDDEN, "Missing Host header")
            return False

        # Host may be "127.0.0.1:8000" or "localhost:8000" or without port
        hostname = host.split(":")[0]
        if hostname not in ALLOWED_HOST_PREFIXES:
            self._send_error_json(
                HTTPStatus.FORBIDDEN,
                f"Host '{host}' is forbidden. Aegis Vault accepts requests only from localhost/127.0.0.1.",
            )
            return False
        return True

    def _send_json(self, status: int, data: Dict[str, Any]) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        # No wildcard CORS: only allow local origin
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(payload)

    def _send_error_json(self, status: int, message: str, error_type: str = "AegisError") -> None:
        self._send_json(status, {
            "success": False,
            "error": message,
            "error_type": error_type,
        })

    def _read_json_body(self) -> Dict[str, Any]:
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len == 0:
            return {}
        # Max request body 50 MB
        if content_len > 50 * 1024 * 1024:
            raise ValueError("Request body exceeds maximum size (50 MB)")
        raw = self.rfile.read(content_len)
        return json.loads(raw.decode("utf-8"))

    def do_GET(self) -> None:
        if not self._validate_host_header():
            return

        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            ui_file = STATIC_DIR / "index.html"
            if not ui_file.is_file():
                self._send_error_json(HTTPStatus.NOT_FOUND, "UI template not found")
                return

            with open(ui_file, "rb") as f:
                content = f.read()

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(content)
            return

        if path == "/api/health":
            self._send_json(HTTPStatus.OK, {"status": "ok", "app": "Aegis Vault", "version": "0.1.0"})
            return

        self._send_error_json(HTTPStatus.NOT_FOUND, f"Route {path} not found")

    def do_POST(self) -> None:
        if not self._validate_host_header():
            return

        path = self.path.split("?")[0]
        try:
            body = self._read_json_body()
        except Exception as e:
            self._send_error_json(HTTPStatus.BAD_REQUEST, f"Malformed request body: {e}")
            return

        try:
            if path == "/api/encrypt":
                self._handle_encrypt(body)
            elif path == "/api/decrypt":
                self._handle_decrypt(body)
            elif path == "/api/inspect":
                self._handle_inspect(body)
            elif path == "/api/strength":
                self._handle_strength(body)
            elif path == "/api/xray":
                self._handle_xray(body)
            elif path == "/api/avalanche":
                self._handle_avalanche(body)
            elif path == "/api/slots/add":
                self._handle_slot_add(body)
            else:
                self._send_error_json(HTTPStatus.NOT_FOUND, f"API endpoint {path} not found")
        except AuthenticationError as e:
            self._send_error_json(HTTPStatus.UNAUTHORIZED, str(e), error_type="AuthenticationError")
        except TamperError as e:
            self._send_error_json(HTTPStatus.BAD_REQUEST, str(e), error_type="TamperError")
        except AegisError as e:
            self._send_error_json(HTTPStatus.BAD_REQUEST, str(e), error_type=type(e).__name__)
        except Exception as e:
            self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, f"Internal error: {e}")

    def _handle_encrypt(self, body: Dict[str, Any]) -> None:
        data_b64 = body.get("data_base64", "")
        password = body.get("password", "")
        filename = body.get("filename", "unnamed.bin")

        if not password:
            self._send_error_json(HTTPStatus.BAD_REQUEST, "Password is required")
            return

        data_bytes = base64.b64decode(data_b64)
        in_stream = io.BytesIO(data_bytes)
        out_stream = io.BytesIO()

        header = encrypt_stream(in_stream, out_stream, password=password)
        encrypted_bytes = out_stream.getvalue()

        out_b64 = base64.b64encode(encrypted_bytes).decode("ascii")
        self._send_json(HTTPStatus.OK, {
            "success": True,
            "filename": f"{filename}.aegis",
            "container_base64": out_b64,
            "container_size": len(encrypted_bytes),
            "original_size": len(data_bytes),
            "chunk_size": header.chunk_size,
            "stream_id": header.stream_id.hex(),
        })

    def _handle_decrypt(self, body: Dict[str, Any]) -> None:
        container_b64 = body.get("container_base64", "")
        password = body.get("password", "")
        filename = body.get("filename", "vault.aegis")

        if not password:
            self._send_error_json(HTTPStatus.BAD_REQUEST, "Password is required")
            return

        container_bytes = base64.b64decode(container_b64)
        in_stream = io.BytesIO(container_bytes)
        out_stream = io.BytesIO()

        header = decrypt_stream(in_stream, out_stream, password=password)
        plaintext = out_stream.getvalue()

        # Generate restored filename
        out_name = filename[:-6] if filename.endswith(".aegis") else f"{filename}.decrypted"

        out_b64 = base64.b64encode(plaintext).decode("ascii")
        self._send_json(HTTPStatus.OK, {
            "success": True,
            "filename": out_name,
            "data_base64": out_b64,
            "restored_size": len(plaintext),
            "version": header.version,
            "stream_id": header.stream_id.hex(),
        })

    def _handle_inspect(self, body: Dict[str, Any]) -> None:
        container_b64 = body.get("container_base64", "")
        container_bytes = base64.b64decode(container_b64)
        in_stream = io.BytesIO(container_bytes)

        header, header_len = ContainerHeader.read_from_stream(in_stream)
        payload_size = max(0, len(container_bytes) - header_len)
        approx_chunks = (payload_size + header.chunk_size + 15) // (header.chunk_size + 16) if payload_size > 0 else 0

        slots_info = []
        for s in header.slots:
            slots_info.append({
                "slot_id": s.slot_id,
                "label": s.label,
                "salt_hex": s.salt.hex(),
                "kdf": s.kdf_params.to_dict(),
                "nonce_hex": s.nonce.hex(),
                "wrapped_key_len": len(s.wrapped_key),
            })

        self._send_json(HTTPStatus.OK, {
            "success": True,
            "file_size": len(container_bytes),
            "header_length_bytes": header_len,
            "payload_length_bytes": payload_size,
            "approx_chunks": approx_chunks,
            "version": header.version,
            "chunk_size": header.chunk_size,
            "stream_id": header.stream_id.hex(),
            "nonce_prefix": header.nonce_prefix.hex(),
            "created_at": header.created_at,
            "slot_count": len(header.slots),
            "slots": slots_info,
        })

    def _handle_strength(self, body: Dict[str, Any]) -> None:
        password = body.get("password", "")
        res = analyze_password(password)
        self._send_json(HTTPStatus.OK, {"success": True, "analysis": res})

    def _handle_xray(self, body: Dict[str, Any]) -> None:
        block_hex = body.get("block_hex")
        key_hex = body.get("key_hex")
        if not block_hex:
            block = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        else:
            block = bytes.fromhex(block_hex)

        if not key_hex:
            key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        else:
            key = bytes.fromhex(key_hex)

        trace = aes_xray_trace(block, key)
        self._send_json(HTTPStatus.OK, {"success": True, "trace": trace})

    def _handle_avalanche(self, body: Dict[str, Any]) -> None:
        pt_hex = body.get("plaintext_hex")
        k_hex = body.get("key_hex")
        target = body.get("target", "plaintext")
        bit_index = int(body.get("bit_index", 0))

        pt = bytes.fromhex(pt_hex) if pt_hex else b"0123456789abcdef"
        k = bytes.fromhex(k_hex) if k_hex else b"sixteenbytekey16"

        res = run_avalanche_experiment(
            plaintext=pt,
            key=k,
            flip_target=target,
            bit_index=bit_index,
        )
        self._send_json(HTTPStatus.OK, {"success": True, "avalanche": res})

    def _handle_slot_add(self, body: Dict[str, Any]) -> None:
        container_b64 = body.get("container_base64", "")
        current_password = body.get("current_password", "")
        new_password = body.get("new_password", "")
        label = body.get("label", "")

        container_bytes = base64.b64decode(container_b64)
        in_stream = io.BytesIO(container_bytes)

        header, header_len = ContainerHeader.read_from_stream(in_stream)
        new_slot = header.add_slot(
            current_password=current_password,
            new_password=new_password,
            label=label,
        )

        out_stream = io.BytesIO()
        out_stream.write(header.serialize())
        out_stream.write(container_bytes[header_len:])

        new_container_bytes = out_stream.getvalue()
        self._send_json(HTTPStatus.OK, {
            "success": True,
            "container_base64": base64.b64encode(new_container_bytes).decode("ascii"),
            "new_slot_id": new_slot.slot_id,
            "slot_count": len(header.slots),
        })

    def log_message(self, format: str, *args: Any) -> None:
        # Standard silent logging to avoid leaking sensitive parameters or noisy output
        sys.stderr.write(f"[{self.log_date_time_string()}] {self.address_string()} - {format % args}\n")


def run_server(host: str = "127.0.0.1", port: int = 8000) -> int:
    """Run Aegis Vault local HTTP server."""
    if host not in ("127.0.0.1", "localhost"):
        print(f"Refusing to bind to '{host}': Aegis Vault must stay bound to 127.0.0.1 for local security.", file=sys.stderr)
        return 1

    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, AegisRequestHandler)
    print(f"=== Aegis Vault Server Running ===")
    print(f"Local URL: http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        httpd.server_close()
    return 0
