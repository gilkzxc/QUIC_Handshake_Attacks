#!/usr/bin/env python3
import argparse
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import parse_qs

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import H3Event, HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent


class FormLoggingH3Protocol(QuicConnectionProtocol):
    def __init__(self, *args, index_path: Path, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http: Optional[H3Connection] = None
        self._index_path = index_path
        self._responded = set()
        self._requests: Dict[int, Dict[str, Any]] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        # Initialize HTTP/3 once QUIC/TLS parameters are negotiated
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic)
            return

        if self._http is None:
            return

        # Let aioquic translate QUIC events into HTTP/3 events
        for h3_event in self._http.handle_event(event):
            self._handle_h3_event(h3_event)

    def _handle_h3_event(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            req = self._requests.setdefault(
                event.stream_id,
                {"headers": {}, "body": bytearray(), "method": None, "path": None},
            )

            # Parse headers / pseudo-headers
            for k, v in event.headers:
                key = k.decode("utf-8", errors="replace").lower()
                value = v.decode("utf-8", errors="replace")
                req["headers"][key] = value
                if key == ":method":
                    req["method"] = value.upper()
                elif key == ":path":
                    req["path"] = value

            if event.stream_ended:
                self._finalize_request(event.stream_id)

        elif isinstance(event, DataReceived):
            req = self._requests.setdefault(
                event.stream_id,
                {"headers": {}, "body": bytearray(), "method": None, "path": None},
            )
            req["body"].extend(event.data)

            if event.stream_ended:
                self._finalize_request(event.stream_id)

    def _finalize_request(self, stream_id: int) -> None:
        if stream_id in self._responded:
            return
        self._responded.add(stream_id)

        req = self._requests.pop(stream_id, None)
        if req is None:
            self._send_status(stream_id, 400)
            return

        method = (req.get("method") or "GET").upper()
        path = req.get("path") or "/"

        # Treat all GET paths as "serve homepage"
        if method == "GET":
            self._send_index(stream_id)
            return

        if method == "POST":
            body_bytes = bytes(req.get("body", b""))
            content_type = req["headers"].get("content-type", "")
            body_text = body_bytes.decode("utf-8", errors="replace")

            parsed: Dict[str, Any] = {}
            if content_type.startswith("application/x-www-form-urlencoded"):
                qs = parse_qs(body_text, keep_blank_values=True)
                # Flatten single-value lists for nicer printing
                parsed = {k: (v[0] if len(v) == 1 else v) for k, v in qs.items()}
            else:
                parsed = {"_raw": body_text}

            # Print to the server CLI
            print("\n=== Received POST form submission ===")
            print(f"Path: {path}")
            print(f"Content-Type: {content_type}")
            print(f"Parsed fields: {parsed}")
            print("====================================\n", flush=True)

            username = parsed.get("username", "")
            password = parsed.get("password", "")

            response_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Submitted</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      background: #f4f6f8;
      margin: 0;
      display: grid;
      place-items: center;
      min-height: 100vh;
    }}
    .card {{
      background: white;
      padding: 24px;
      border-radius: 12px;
      box-shadow: 0 8px 24px rgba(0,0,0,0.08);
      width: 100%;
      max-width: 420px;
    }}
    code {{
      background: #f1f3f5;
      padding: 2px 6px;
      border-radius: 6px;
    }}
    a {{
      display: inline-block;
      margin-top: 12px;
      color: #1f6feb;
      text-decoration: none;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Submission received</h1>
    <p>The server printed the form fields to its CLI output.</p>
    <p><strong>username:</strong> <code>{str(username)}</code></p>
    <p><strong>password:</strong> <code>{str(password)}</code></p>
    <a href="/">Back to login page</a>
  </div>
</body>
</html>""".encode("utf-8")

            self._send_bytes(
                stream_id,
                status=200,
                body=response_html,
                content_type="text/html; charset=utf-8",
            )
            return

        self._send_status(stream_id, 405)

    def _send_status(self, stream_id: int, status: int) -> None:
        self._http.send_headers(
            stream_id,
            [
                (b":status", str(status).encode()),
                (b"content-length", b"0"),
                (b"server", b"aioquic-form-logger"),
            ],
            end_stream=True,
        )
        self.transmit()

    def _send_bytes(self, stream_id: int, status: int, body: bytes, content_type: str) -> None:
        self._http.send_headers(
            stream_id,
            [
                (b":status", str(status).encode()),
                (b"content-type", content_type.encode()),
                (b"content-length", str(len(body)).encode()),
                (b"server", b"aioquic-form-logger"),
            ],
        )
        self._http.send_data(stream_id, body, end_stream=True)
        self.transmit()

    def _send_index(self, stream_id: int) -> None:
        try:
            data = self._index_path.read_bytes()
        except FileNotFoundError:
            body = b"<h1>index file not found</h1>"
            self._send_bytes(
                stream_id,
                status=404,
                body=body,
                content_type="text/html; charset=utf-8",
            )
            return

        self._send_bytes(
            stream_id,
            status=200,
            body=data,
            content_type="text/html; charset=utf-8",
        )


async def main(host: str, port: int, cert: str, key: str, index: str) -> None:
    cfg = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    cfg.load_cert_chain(cert, key)

    index_path = Path(index)
    await serve(
        host,
        port,
        configuration=cfg,
        create_protocol=lambda *a, **kw: FormLoggingH3Protocol(*a, index_path=index_path, **kw),
    )

    # Run forever
    await asyncio.get_running_loop().create_future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Minimal HTTP/3 form-logging server (aioquic)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--index", default="mock_login.html")
    args = parser.parse_args()

    asyncio.run(main(args.host, args.port, args.certificate, args.private_key, args.index))