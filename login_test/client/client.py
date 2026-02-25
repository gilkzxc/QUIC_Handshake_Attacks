#!/usr/bin/env python3
import argparse
import asyncio
import ssl
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, urljoin

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent


# -----------------------------
# HTML form parser (local file)
# -----------------------------

@dataclass
class FormSpec:
    method: str = "POST"
    action: str = "/"
    username_field: str = "username"
    password_field: str = "password"


class SimpleLoginFormParser(HTMLParser):
    """
    Minimal parser for a mock login form.
    It grabs the first <form> and tries to infer username/password input names.
    """
    def __init__(self) -> None:
        super().__init__()
        self.in_form = False
        self.form_found = False
        self.spec = FormSpec()

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attrs_dict: Dict[str, str] = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()

        if tag == "form" and not self.form_found:
            self.form_found = True
            self.in_form = True
            method = attrs_dict.get("method", "POST").strip().upper() or "POST"
            action = attrs_dict.get("action", "/").strip() or "/"
            self.spec.method = method
            self.spec.action = action
            return

        if not self.in_form or tag != "input":
            return

        input_type = attrs_dict.get("type", "text").lower()
        name = attrs_dict.get("name", "").strip()
        autocomplete = attrs_dict.get("autocomplete", "").lower()

        if not name:
            return

        # Prefer autocomplete hints when present
        if autocomplete == "username":
            self.spec.username_field = name
            return
        if autocomplete in ("current-password", "new-password"):
            self.spec.password_field = name
            return

        # Fallbacks by input type / common names
        if input_type == "password":
            self.spec.password_field = name
        elif input_type in ("text", "email"):
            if self.spec.username_field == "username":
                # Only overwrite default if it's still default
                self.spec.username_field = name

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self.in_form:
            self.in_form = False


def parse_mock_form(html_path: Path) -> FormSpec:
    parser = SimpleLoginFormParser()
    parser.feed(html_path.read_text(encoding="utf-8"))
    return parser.spec


# -----------------------------
# HTTP/3 client protocol
# -----------------------------

@dataclass
class HttpResponse:
    headers: List[Tuple[bytes, bytes]] = field(default_factory=list)
    body: bytearray = field(default_factory=bytearray)
    status: Optional[int] = None


class H3FormClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http: Optional[H3Connection] = None
        self._pending: Dict[int, asyncio.Future] = {}
        self._responses: Dict[int, HttpResponse] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic)
            return

        if self._http is None:
            return

        for h3_event in self._http.handle_event(event):
            self._handle_h3_event(h3_event)

    def _handle_h3_event(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            resp = self._responses.setdefault(event.stream_id, HttpResponse())
            resp.headers.extend(event.headers)

            for k, v in event.headers:
                if k == b":status":
                    try:
                        resp.status = int(v.decode())
                    except ValueError:
                        resp.status = None

            if event.stream_ended:
                fut = self._pending.pop(event.stream_id, None)
                if fut and not fut.done():
                    fut.set_result(resp)

        elif isinstance(event, DataReceived):
            resp = self._responses.setdefault(event.stream_id, HttpResponse())
            resp.body.extend(event.data)

            if event.stream_ended:
                fut = self._pending.pop(event.stream_id, None)
                if fut and not fut.done():
                    fut.set_result(resp)

    async def request(
        self,
        method: str,
        host: str,
        port: int,
        path: str,
        body: bytes = b"",
        content_type: Optional[str] = None,
    ) -> HttpResponse:
        if self._http is None:
            raise RuntimeError("HTTP/3 connection not initialized yet")

        stream_id = self._quic.get_next_available_stream_id()
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending[stream_id] = fut
        self._responses[stream_id] = HttpResponse()

        authority = f"{host}:{port}".encode()

        headers: List[Tuple[bytes, bytes]] = [
            (b":method", method.upper().encode()),
            (b":scheme", b"https"),
            (b":authority", authority),
            (b":path", path.encode()),
            (b"user-agent", b"aioquic-form-client/1.0"),
        ]

        if body:
            if content_type:
                headers.append((b"content-type", content_type.encode()))
            headers.append((b"content-length", str(len(body)).encode()))

        end_stream = len(body) == 0
        self._http.send_headers(stream_id=stream_id, headers=headers, end_stream=end_stream)

        if body:
            self._http.send_data(stream_id=stream_id, data=body, end_stream=True)

        self.transmit()

        return await fut


# -----------------------------
# Helpers
# -----------------------------

def normalize_action_to_path(action: str, homepage_path: str = "/") -> str:
    """
    Converts a form action into a request path.
    For local test pages, action is usually "/" or relative.
    """
    if not action:
        return homepage_path

    # If someone put an absolute URL in the form action, keep only path/query
    if action.startswith("http://") or action.startswith("https://"):
        # Use urljoin trick; easiest robust split without extra deps:
        # We only need path+query, but for local testing, action will likely be relative.
        from urllib.parse import urlparse
        parsed = urlparse(action)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        return path

    # Relative path
    if action.startswith("/"):
        return action

    joined = urljoin(homepage_path if homepage_path.endswith("/") else homepage_path + "/", action)
    return joined if joined.startswith("/") else "/" + joined


def print_response(label: str, resp: HttpResponse) -> None:
    print(f"\n=== {label} ===")
    print(f"Status: {resp.status}")
    # show a few headers
    for k, v in resp.headers:
        if not k.startswith(b":"):
            print(f"{k.decode(errors='replace')}: {v.decode(errors='replace')}")
    body_text = resp.body.decode("utf-8", errors="replace")
    preview = body_text if len(body_text) <= 1000 else body_text[:1000] + "\n...[truncated]..."
    print("\nBody preview:\n")
    print(preview)
    print("=" * (len(label) + 8))


# -----------------------------
# Main
# -----------------------------

async def run_client(args: argparse.Namespace) -> None:
    html_path = Path(args.html_path)
    if not html_path.exists():
        raise FileNotFoundError(f"mock HTML file not found: {html_path}")

    form = parse_mock_form(html_path)

    homepage_path = args.home_path
    post_path = normalize_action_to_path(form.action, homepage_path=homepage_path)

    if form.method != "POST":
        print(f"[warn] Form method in HTML is {form.method!r}; sending POST anyway for your server test.")

    payload_dict = {
        form.username_field: args.username,
        form.password_field: args.password,
    }
    payload = urlencode(payload_dict).encode("utf-8")

    print("Detected form spec from HTML:")
    print(f"  method         = {form.method}")
    print(f"  action         = {form.action!r} -> request path {post_path!r}")
    print(f"  username field = {form.username_field!r}")
    print(f"  password field = {form.password_field!r}")
    print(f"  payload        = {payload_dict}")

    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)

    # Local testing convenience: disable cert verification unless --verify is passed.
    if not args.verify:
        config.verify_mode = ssl.CERT_NONE

    # Optional CA file for verification mode
    if args.ca_file:
        config.load_verify_locations(args.ca_file)

    async with connect(
        args.host,
        args.port,
        configuration=config,
        create_protocol=H3FormClient,
        wait_connected=True,
    ) as client:
        protocol = client  # type: ignore[assignment]
        assert isinstance(protocol, H3FormClient)

        # 1) "Surf" to homepage (GET)
        get_resp = await protocol.request(
            method="GET",
            host=args.host,
            port=args.port,
            path=homepage_path,
        )
        print_response("GET homepage", get_resp)

        # 2) Submit login form (POST)
        post_resp = await protocol.request(
            method="POST",
            host=args.host,
            port=args.port,
            path=post_path,
            body=payload,
            content_type="application/x-www-form-urlencoded",
        )
        print_response("POST form submit", post_resp)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="aioquic HTTP/3 client for mock login form testing")
    p.add_argument("--host", required=True, help="Server IP/address (e.g., 127.0.0.1)")
    p.add_argument("--port", type=int, default=4433, help="Server UDP port (default: 4433)")
    

    p.add_argument(
        "--html-path",
        required=True,
        help="Path to local mock_login.html (used to detect form action/field names)",
    )
    p.add_argument(
        "--home-path",
        default="/",
        help="Homepage path to GET before POST (default: /)",
    )

    p.add_argument("--username", required=True, help="Username value to submit")
    p.add_argument("--password", required=True, help="Password value to submit")

    p.add_argument(
        "--verify",
        action="store_true",
        help="Enable TLS certificate verification (disabled by default for local testing)",
    )
    p.add_argument(
        "--ca-file",
        default=None,
        help="CA/cert file to trust when using --verify",
    )
    return p


def main() -> None:
    args = build_arg_parser().parse_args()
    asyncio.run(run_client(args))


if __name__ == "__main__":
    main()