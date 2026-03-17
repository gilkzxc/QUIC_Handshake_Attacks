#!/usr/bin/env python3
import argparse
import asyncio
from pathlib import Path
from typing import Optional, Dict
import os
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent
from aioquic.quic.packet import QuicErrorCode

class IndexOnlyProtocol(QuicConnectionProtocol):
    def __init__(self, *args, index_path: Path, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http: Optional[H3Connection] = None
        self._index_path = index_path
        self._responded = set()

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
            # Map all paths to index.html
            if event.stream_id in self._responded:
                return
            self._responded.add(event.stream_id)
            self._send_index(event.stream_id)

    def _send_status(self, stream_id: int, status: int) -> None:
        self._http.send_headers(
            stream_id,
            [
                (b":status", str(status).encode()),
                (b"content-length", b"0"),
                (b"server", b"aioquic-index"),
            ],
            end_stream=True,
        )
        self.transmit()

    def _send_index(self, stream_id: int) -> None:
        try:
            data = self._index_path.read_bytes()
        except FileNotFoundError:
            body = b"<h1>index.html not found</h1>"
            self._http.send_headers(
                stream_id,
                [
                    (b":status", b"404"),
                    (b"content-type", b"text/html; charset=utf-8"),
                    (b"content-length", str(len(body)).encode()),
                ],
            )
            self._http.send_data(stream_id, body, end_stream=True)
            self.transmit()
            return

        self._http.send_headers(
            stream_id,
            [
                (b":status", b"200"),
                (b"content-type", b"text/html; charset=utf-8"),
                (b"content-length", str(len(data)).encode()),
                (b"server", b"aioquic-index"),
            ],
        )
        self._http.send_data(stream_id, data, end_stream=True)
        self.transmit()

async def main(host: str, port: int, cert: str, key: str, index: str) -> None:
    cfg = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    cfg.load_cert_chain(cert, key)

    IndexPath = Path(index)
    await serve(
        host,
        port,
        configuration=cfg,
        create_protocol=lambda *a, **kw: IndexOnlyProtocol(*a, index_path=IndexPath, **kw),
    )

    # Run forever
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Minimal HTTP/3 index.html server (aioquic)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--index", default="index.html")
    args = parser.parse_args()
    asyncio.run(main(args.host, args.port, args.certificate, args.private_key, args.index))
    #print(os.getcwd())
