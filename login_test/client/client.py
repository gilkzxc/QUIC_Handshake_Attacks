#!/usr/bin/env python3
import argparse
import asyncio
import ssl
from dataclasses import dataclass, field
from getpass import getpass
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
from aioquic.quic.packet import QuicProtocolVersion

# -----------------------------
# HTML form parser
# -----------------------------

@dataclass
class FormSpec:
    method: str = "POST"
    action: str = "/"
    username_field: str = "username"
    password_field: str = "password"
    form_found: bool = False
    username_found: bool = False
    password_found: bool = False

    @property
    def is_supported(self) -> bool:
        return self.form_found and self.username_found and self.password_found


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
            self.spec.form_found = True
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
            self.spec.username_found = True
            return
        if autocomplete in ("current-password", "new-password"):
            self.spec.password_field = name
            self.spec.password_found = True
            return

        # Fallbacks by input type / common names
        if input_type == "password" and not self.spec.password_found:
            self.spec.password_field = name
            self.spec.password_found = True
        elif input_type in ("text", "email") and not self.spec.username_found:
            self.spec.username_field = name
            self.spec.username_found = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self.in_form:
            self.in_form = False


class HtmlTextRenderer(HTMLParser):
    """
    Lightweight HTML-to-text renderer for interactive terminal output.
    """

    BLOCK_TAGS = {
        "address",
        "article",
        "aside",
        "blockquote",
        "button",
        "div",
        "dl",
        "dt",
        "dd",
        "fieldset",
        "figcaption",
        "figure",
        "footer",
        "form",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "label",
        "li",
        "main",
        "nav",
        "ol",
        "p",
        "pre",
        "section",
        "table",
        "td",
        "th",
        "tr",
        "ul",
    }

    def __init__(self) -> None:
        super().__init__()
        self._parts: List[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        if tag in {"script", "style"}:
            self._ignored_depth += 1
            return
        if self._ignored_depth:
            return
        if tag == "br" or tag in self.BLOCK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"script", "style"}:
            if self._ignored_depth:
                self._ignored_depth -= 1
            return
        if self._ignored_depth:
            return
        if tag in self.BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        self._parts.append(data)

    def get_text(self) -> str:
        text = "".join(self._parts)
        lines = []
        for raw_line in text.splitlines():
            line = " ".join(raw_line.split())
            if line:
                lines.append(line)
        return "\n".join(lines)


def parse_form_html(html_text: str) -> FormSpec:
    parser = SimpleLoginFormParser()
    parser.feed(html_text)
    return parser.spec


def parse_mock_form(html_path: Path) -> FormSpec:
    return parse_form_html(html_path.read_text(encoding="utf-8"))


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


def build_quic_config(args: argparse.Namespace) -> QuicConfiguration:
    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)

    if not args.verify:
        config.verify_mode = ssl.CERT_NONE

    if args.ca_file:
        config.load_verify_locations(args.ca_file)

    if args.run_v2:
        config.original_version = QuicProtocolVersion.VERSION_2
        config.supported_versions = [QuicProtocolVersion.VERSION_2]

    return config


def decode_body(resp: HttpResponse) -> str:
    return resp.body.decode("utf-8", errors="replace")


def make_preview(text: str, limit: int = 1000) -> str:
    return text if len(text) <= limit else text[:limit] + "\n...[truncated]..."


def get_header_value(resp: HttpResponse, header_name: str) -> Optional[str]:
    target = header_name.lower()
    for key, value in resp.headers:
        if key.startswith(b":"):
            continue
        if key.decode(errors="replace").lower() == target:
            return value.decode(errors="replace")
    return None


def is_html_response(resp: HttpResponse, body_text: Optional[str] = None) -> bool:
    content_type = (get_header_value(resp, "content-type") or "").lower()
    if "html" in content_type:
        return True

    text = body_text if body_text is not None else decode_body(resp)
    leading = text.lstrip().lower()
    return leading.startswith("<!doctype html") or leading.startswith("<html")


def html_to_text(html_text: str) -> str:
    parser = HtmlTextRenderer()
    parser.feed(html_text)
    rendered = parser.get_text()
    return rendered or "[empty HTML body]"


def format_readable_body(resp: HttpResponse) -> str:
    body_text = decode_body(resp)
    if is_html_response(resp, body_text):
        return make_preview(html_to_text(body_text))
    stripped = body_text.strip()
    return make_preview(stripped or "[empty body]")


def describe_field(name: str, found: bool) -> str:
    return repr(name) if found else "<not found>"


def print_response(label: str, resp: HttpResponse) -> None:
    print(f"\n=== {label} ===")
    print(f"Status: {resp.status}")
    for k, v in resp.headers:
        if not k.startswith(b":"):
            print(f"{k.decode(errors='replace')}: {v.decode(errors='replace')}")
    preview = make_preview(decode_body(resp))
    print("\nBody preview:\n")
    print(preview)
    print("=" * (len(label) + 8))


def print_readable_response(label: str, resp: HttpResponse) -> None:
    print(f"\n=== {label} ===")
    print(f"Status: {resp.status}")
    for k, v in resp.headers:
        if not k.startswith(b":"):
            print(f"{k.decode(errors='replace')}: {v.decode(errors='replace')}")
    print("\nReadable body:\n")
    print(format_readable_body(resp))
    print("=" * (len(label) + 8))


def print_form_summary(source: str, form: FormSpec, post_path: Optional[str]) -> None:
    print(source)
    if not form.form_found:
        print("  form           = <not found>")
        return

    print(f"  method         = {form.method}")
    print(f"  action         = {form.action!r} -> request path {post_path!r}")
    print(f"  username field = {describe_field(form.username_field, form.username_found)}")
    print(f"  password field = {describe_field(form.password_field, form.password_found)}")


# -----------------------------
# Main
# -----------------------------

def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.interactive:
        ignored = []
        if args.html_path is not None:
            ignored.append("--html-path")
        if args.username is not None:
            ignored.append("--username")
        if args.password is not None:
            ignored.append("--password")
        if ignored:
            print(f"[warn] Ignoring {', '.join(ignored)} in --interactive mode.")
        return

    missing = []
    if args.html_path is None:
        missing.append("--html-path")
    if args.username is None:
        missing.append("--username")
    if args.password is None:
        missing.append("--password")
    if missing:
        parser.error(
            "the following arguments are required unless --interactive is used: "
            + ", ".join(missing)
        )


async def request_once(
    args: argparse.Namespace,
    method: str,
    path: str,
    body: bytes = b"",
    content_type: Optional[str] = None,
) -> HttpResponse:
    async with connect(
        args.host,
        args.port,
        configuration=build_quic_config(args),
        create_protocol=H3FormClient,
        wait_connected=True,
    ) as client:
        protocol = client  # type: ignore[assignment]
        assert isinstance(protocol, H3FormClient)
        return await protocol.request(
            method=method,
            host=args.host,
            port=args.port,
            path=path,
            body=body,
            content_type=content_type,
        )


def build_payload(form: FormSpec, username: str, password: str) -> Tuple[Dict[str, str], bytes]:
    payload_dict = {
        form.username_field: username,
        form.password_field: password,
    }
    payload = urlencode(payload_dict).encode("utf-8")
    return payload_dict, payload


async def run_non_interactive_client(args: argparse.Namespace) -> None:
    assert args.html_path is not None
    assert args.username is not None
    assert args.password is not None

    html_path = Path(args.html_path)
    if not html_path.exists():
        raise FileNotFoundError(f"mock HTML file not found: {html_path}")

    form = parse_mock_form(html_path)
    homepage_path = args.home_path
    post_path = normalize_action_to_path(form.action, homepage_path=homepage_path)
    payload_dict, payload = build_payload(form, args.username, args.password)

    print_form_summary("Detected form spec from local HTML:", form, post_path)
    print(f"  payload        = {payload_dict}")

    if not form.form_found:
        print("[warn] No form was detected in the local HTML; using default action and field names.")
    if not form.username_found:
        print(f"[warn] Username field was not confidently detected; using {form.username_field!r}.")
    if not form.password_found:
        print(f"[warn] Password field was not confidently detected; using {form.password_field!r}.")
    if form.method != "POST":
        print(f"[warn] Form method in HTML is {form.method!r}; sending POST anyway for your server test.")

    async with connect(
        args.host,
        args.port,
        configuration=build_quic_config(args),
        create_protocol=H3FormClient,
        wait_connected=True,
    ) as client:
        protocol = client  # type: ignore[assignment]
        assert isinstance(protocol, H3FormClient)

        get_resp = await protocol.request(
            method="GET",
            host=args.host,
            port=args.port,
            path=homepage_path,
        )
        print_response("GET homepage", get_resp)

        post_resp = await protocol.request(
            method="POST",
            host=args.host,
            port=args.port,
            path=post_path,
            body=payload,
            content_type="application/x-www-form-urlencoded",
        )
        print_response("POST form submit", post_resp)


async def run_interactive_client(args: argparse.Namespace) -> None:
    homepage_path = args.home_path
    get_resp = await request_once(args, method="GET", path=homepage_path)

    homepage_html = decode_body(get_resp)
    form = parse_form_html(homepage_html)
    post_path = normalize_action_to_path(form.action, homepage_path=homepage_path) if form.form_found else None

    print_form_summary("Detected form spec from homepage:", form, post_path)

    if not form.is_supported:
        print_readable_response("GET homepage", get_resp)
        if not form.form_found:
            print("[info] No form was found on the homepage; not submitting anything.")
        else:
            print("[info] The homepage form does not expose both username and password fields; not submitting.")
        return

    assert post_path is not None
    if form.method != "POST":
        print(f"[warn] Form method on homepage is {form.method!r}; sending POST anyway for your server test.")

    print()
    username = input(f"Enter value for {form.username_field}: ")
    password = getpass(f"Enter value for {form.password_field}: ")
    _, payload = build_payload(form, username, password)

    print(f"\nSubmitting form to {post_path!r} ...")
    post_resp = await request_once(
        args,
        method="POST",
        path=post_path,
        body=payload,
        content_type="application/x-www-form-urlencoded",
    )
    print_readable_response("POST form submit", post_resp)


async def run_client(args: argparse.Namespace) -> None:
    if args.interactive:
        await run_interactive_client(args)
        return
    await run_non_interactive_client(args)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="aioquic HTTP/3 client for mock login form testing")
    p.add_argument("--host", required=True, help="Server IP/address (e.g., 127.0.0.1)")
    p.add_argument("--port", type=int, default=4433, help="Server UDP port (default: 4433)")
    p.add_argument(
        "--interactive",
        action="store_true",
        help="Detect the login form from the fetched homepage and prompt for credentials in the terminal",
    )
    p.add_argument(
        "--html-path",
        default=None,
        help="Path to local mock_login.html for non-interactive form detection",
    )
    p.add_argument(
        "--home-path",
        default="/",
        help="Homepage path to GET before POST (default: /)",
    )

    p.add_argument("--username", default=None, help="Username value to submit in non-interactive mode")
    p.add_argument("--password", default=None, help="Password value to submit in non-interactive mode")

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

    p.add_argument(
        "--run-v2",
        action="store_true",
        help="Run with QUIC v2 only (disable QUIC v1 fallback)",
    )
    return p


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    validate_args(parser, args)
    asyncio.run(run_client(args))


if __name__ == "__main__":
    main()
