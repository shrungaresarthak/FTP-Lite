#!/usr/bin/env python3
import argparse
import asyncio
import logging
import struct
from pathlib import Path

from aioquic.asyncio import serve, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

from protocol import (
    MSG_INIT,
    MSG_AUTH,
    MSG_AUTH_FAIL,
    MSG_START,
    MSG_SEGMENT,
    MSG_COMPLETE,
    MSG_ERROR,
    MSG_ACK,
    PROTOCOL_VERSION,
    VALID_USERS,
    unpack_init,
    unpack_auth,
    unpack_start,
    unpack_segment_header,
    pack_ack,
    pack_error,
)

LOG = logging.getLogger("ftp_lite_server")


class FtpLiteServerProtocol(QuicConnectionProtocol):
    """
    Per-connection handler for FTP-Lite over QUIC. Implements a DFA:
      IDLE → WAIT_AUTH → WAIT_START → RECEIVING → DONE
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._buffer = bytearray()
        self._state = "IDLE"
        self._out_file = None
        self._expected_size = 0
        self._received_bytes = 0
        self._next_seq = 0

    def quic_event_received(self, event):
        # Only handle stream‐0 data
        if not isinstance(event, StreamDataReceived):
            return

        self._buffer.extend(event.data)

        while True:
            if self._state == "IDLE":
                # Need at least 4 bytes (BHB) for INIT
                if len(self._buffer) < 4:
                    return
                pdu = bytes(self._buffer[:4])
                self._buffer = self._buffer[4:]
                msg_type = pdu[0]
                if msg_type != MSG_INIT:
                    LOG.error(f"[Server] Expected INIT; got 0x{msg_type:02x}. Sending ERROR.")
                    err = pack_error(0x01, "Expected INIT")
                    self._quic.send_stream_data(0, err, end_stream=True)
                    return
                version, flags = unpack_init(pdu)
                LOG.info(f"[Server] INIT (v={version}, flags=0x{flags:02x})")
                if version != PROTOCOL_VERSION:
                    LOG.error(f"[Server] Bad version {version}. Sending ERROR.")
                    err = pack_error(0x02, f"Unsupported version {version}")
                    self._quic.send_stream_data(0, err, end_stream=True)
                    return
                self._state = "WAIT_AUTH"
                continue

            elif self._state == "WAIT_AUTH":
                if len(self._buffer) < 3:
                    return
                if self._buffer[0] != MSG_AUTH:
                    LOG.error(f"[Server] Expected AUTH; got 0x{self._buffer[0]:02x}. Sending ERROR.")
                    err = pack_error(0x03, "Expected AUTH")
                    self._quic.send_stream_data(0, err, end_stream=True)
                    return
                ulen = self._buffer[1]
                plen = self._buffer[2]
                total_len = 1 + 1 + 1 + ulen + plen
                if len(self._buffer) < total_len:
                    return
                pdu = bytes(self._buffer[:total_len])
                self._buffer = self._buffer[total_len:]
                username, password = unpack_auth(pdu)
                LOG.info(f"[Server] AUTH (user='{username}')")
                if username in VALID_USERS and VALID_USERS[username] == password:
                    LOG.info("[Server] AUTH OK.")
                    self._state = "WAIT_START"
                else:
                    LOG.warning(f"[Server] AUTH FAIL for '{username}'. Sending AUTH_FAIL.")
                    self._quic.send_stream_data(0, struct.pack("!B", MSG_AUTH_FAIL), end_stream=True)
                    return
                continue

            elif self._state == "WAIT_START":
                if len(self._buffer) < 2:
                    return
                if self._buffer[0] != MSG_START:
                    LOG.error(f"[Server] Expected START; got 0x{self._buffer[0]:02x}. Sending ERROR.")
                    err = pack_error(0x04, "Expected START")
                    self._quic.send_stream_data(0, err, end_stream=True)
                    return

                namelen = self._buffer[1]
                total_len = 1 + 1 + namelen + 8
                if len(self._buffer) < total_len:
                    return

                pdu = bytes(self._buffer[:total_len])
                self._buffer = self._buffer[total_len:]
                filename, size = unpack_start(pdu)
                LOG.info(f"[Server] START (filename='{filename}', size={size})")

                outdir = Path("Result")
                outdir.mkdir(exist_ok=True)

                # OPEN a separate file per client, using the provided filename
                safe_name = Path(filename).name
                self._out_file = open(outdir / safe_name, "wb")

                self._expected_size = size
                self._received_bytes = 0
                self._next_seq = 0
                self._state = "RECEIVING"
                continue

            elif self._state == "RECEIVING":
                if len(self._buffer) < 1:
                    return
                msg_type = self._buffer[0]

                if msg_type == MSG_SEGMENT:
                    # Need 7 bytes header (1 + 4 + 2) before reading chunk
                    if len(self._buffer) < 7:
                        return
                    seq, chunk_len = unpack_segment_header(bytes(self._buffer[:7]))
                    if len(self._buffer) < 7 + chunk_len:
                        return
                    chunk = bytes(self._buffer[7 : 7 + chunk_len])
                    self._buffer = self._buffer[7 + chunk_len :]

                    if seq != self._next_seq:
                        LOG.error(
                            f"[Server] Out­-of-­order SEGMENT: expected {self._next_seq}, got {seq}. Sending ERROR."
                        )
                        err = pack_error(0x05, "Segment out of order")
                        self._quic.send_stream_data(0, err, end_stream=True)
                        return

                    # Write chunk into client-specific file
                    self._next_seq += 1
                    self._received_bytes += chunk_len
                    self._out_file.write(chunk)
                    LOG.info(f"[Server] Received SEGMENT {seq} ({chunk_len} bytes).")

                    # Send ACK back
                    ack_pdu = pack_ack(seq)
                    self._quic.send_stream_data(0, ack_pdu)
                    LOG.info(f"[Server] Sent ACK for SEGMENT {seq}.")
                    continue

                elif msg_type == MSG_COMPLETE:
                    self._buffer = self._buffer[1:]
                    if self._out_file:
                        self._out_file.close()
                        self._out_file = None
                    if self._received_bytes == self._expected_size:
                        LOG.info(f"[Server] File transfer OK ({self._received_bytes} bytes).")
                    else:
                        LOG.warning(
                            f"[Server] Size mismatch: expected {self._expected_size}, got {self._received_bytes}."
                        )
                    self._state = "DONE"
                    self._quic.close()
                    return

                else:
                    LOG.error(f"[Server] Unexpected PDU 0x{msg_type:02x} in RECEIVING. Sending ERROR.")
                    err = pack_error(0x06, "Unexpected PDU during RECEIVING")
                    self._quic.send_stream_data(0, err, end_stream=True)
                    return

            else:
                # Either DONE or an unknown state—ignore further data
                return

        # If the client closes the stream early, clean up
        if event.end_stream:
            if self._out_file:
                self._out_file.close()
            self._quic.close()

    def connection_lost(self, exc):
        super().connection_lost(exc)
        LOG.info("[Server] Connection closed.")


# DiscoveryProtocol: handles incoming UDP “DISCOVER_FTPLITE” queries

class DiscoveryProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.transports.DatagramTransport):
        # Save the transport so we can call .sendto(…) later
        self.transport = transport
        LOG.info(f"[Discovery] UDP auto-discovery listening on port {transport.get_extra_info('sockname')[1]}…")

    def datagram_received(self, data: bytes, addr):
        # Expect exactly b"DISCOVER_FTPLITE"
        if data == b"DISCOVER_FTPLITE":
            # Hardcode response IP = 127.0.0.1 (in a real network, inspect sockname or use gethostbyname)
            response = b"FTPLITE_SERVER:" + struct.pack("!I", 0x7F000001)  # 127.0.0.1 in network‐order
            self.transport.sendto(response, addr)


async def main():
    parser = argparse.ArgumentParser(description="FTP-Lite QUIC server")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=4444, help="UDP port for QUIC (default: 4444)")
    parser.add_argument("--cert", type=str, required=True, help="Path to cert.pem")
    parser.add_argument("--key", type=str, required=True, help="Path to key.pem")
    parser.add_argument("--discover-port", type=int, default=9999, help="UDP port for discovery (default: 9999)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(
        lambda: DiscoveryProtocol(), local_addr=("0.0.0.0", args.discover_port)
    )

    quic_config = QuicConfiguration(is_client=False, alpn_protocols=["ftplite/1"])
    quic_config.load_cert_chain(certfile=args.cert, keyfile=args.key)

    LOG.info(f"[Server] Running on UDP port {args.port}…")
    await serve(
        host=args.host,
        port=args.port,
        configuration=quic_config,
        create_protocol=FtpLiteServerProtocol,
    )

    try:
        await asyncio.Future()  # run forever
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        LOG.info("[Server] Interrupted by user; shutting down.")
