#!/usr/bin/env python3
import argparse
import asyncio
import getpass
import logging
import os
import socket
import struct

from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration

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
    pack_init,
    pack_auth,
    pack_start,
    pack_segment,
    pack_complete,
    unpack_ack,
    unpack_error,
)

LOG = logging.getLogger("ftp_lite_client")


def find_server(discover_port: int = 9999, timeout: float = 1.0) -> str | None:

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(timeout)

    try:
        # Directly send to 127.0.0.1 instead of broadcast (macOS-friendly)
        client.sendto(b"DISCOVER_FTPLITE", ("127.0.0.1", discover_port))
        data, _ = client.recvfrom(1024)
        if data.startswith(b"FTPLITE_SERVER:"):
            ip_bytes = data.split(b":", 1)[1]
            return socket.inet_ntoa(ip_bytes)
    except (socket.timeout, OSError):
        return None
    finally:
        client.close()


class FtpLiteClientProtocol(QuicConnectionProtocol):
    pass

async def run_client(
    server_host: str,
    server_port: int,
    ca_cert: str,
    username: str,
    password: str,
    local_file: str,
):

    configuration = QuicConfiguration(is_client=True, alpn_protocols=["ftplite/1"])
    if ca_cert:
        try:
            configuration.load_verify_locations(ca_cert)
        except Exception:
            LOG.warning("[Client] Could not load CA cert; skipping verification.")
            configuration.verify_mode = False
    else:
        configuration.verify_mode = False

    LOG.info(f"[Client] Connecting to {server_host}:{server_port} …")
    async with connect(
        server_host, server_port, configuration=configuration, create_protocol=FtpLiteClientProtocol
    ) as client:
        reader, writer = await client.create_stream()
        LOG.info("[Client] QUIC connection established. Beginning FTP-Lite handshake…")

        # 1) INIT
        init_msg = pack_init(PROTOCOL_VERSION, 0)
        writer.write(init_msg)
        await writer.drain()
        LOG.debug("[Client] Sent INIT")

        # 2) AUTH
        auth_msg = pack_auth(username, password)
        writer.write(auth_msg)
        await writer.drain()
        LOG.debug(f"[Client] Sent AUTH (user='{username}')")

        # Peek for AUTH_FAIL or ERROR (timeout 0.5s)
        try:
            peek = await asyncio.wait_for(reader.read(1), timeout=0.5)
        except asyncio.TimeoutError:
            peek = b""

        if peek == bytes([MSG_AUTH_FAIL]):
            LOG.error("[Client] AUTH_FAIL received. Exiting.")
            writer.close()
            await writer.wait_closed()
            return
        elif peek and peek[0] == MSG_ERROR:
            hdr = peek + await reader.read(3)
            code, msg = unpack_error(hdr + await reader.read(struct.unpack("!H", hdr[2:4])[0]))
            LOG.error(f"[Client] ERROR from server (code {code}): {msg}")
            writer.close()
            await writer.wait_closed()
            return
        elif peek:
            LOG.warning(f"[Client] Unexpected byte from server: 0x{peek[0]:02x}")

        LOG.info("[Client] AUTH succeeded. Sending START…")

        # 3) START
        filename = os.path.basename(local_file)
        size = os.path.getsize(local_file)
        start_msg = pack_start(filename, size)
        writer.write(start_msg)
        await writer.drain()
        LOG.debug(f"[Client] Sent START (filename='{filename}', size={size})")

        # 4) SEGMENT (with ACK wait)
        seq = 0
        CHUNK_SIZE = 4096
        with open(local_file, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                seg_msg = pack_segment(seq, chunk)
                writer.write(seg_msg)
                await writer.drain()
                LOG.info(f"[Client] Sent SEGMENT {seq} ({len(chunk)} bytes)")

                # Wait up to 1s for ACK
                try:
                    ack_pdu = await asyncio.wait_for(reader.read(5), timeout=1.0)
                except asyncio.TimeoutError:
                    LOG.error(f"[Client] Timeout waiting for ACK of segment {seq}. Exiting.")
                    writer.close()
                    await writer.wait_closed()
                    return

                if not ack_pdu or ack_pdu[0] != MSG_ACK:
                    LOG.error(f"[Client] Expected ACK, got 0x{ack_pdu[0]:02x}. Exiting.")
                    writer.close()
                    await writer.wait_closed()
                    return

                ack_seq = unpack_ack(ack_pdu)
                if ack_seq != seq:
                    LOG.error(f"[Client] ACK mismatch: expected {seq}, got {ack_seq}. Exiting.")
                    writer.close()
                    await writer.wait_closed()
                    return

                LOG.info(f"[Client] Received ACK for segment {seq}")
                seq += 1

        # 5) COMPLETE
        complete_msg = pack_complete()
        writer.write(complete_msg)
        await writer.drain()
        LOG.debug("[Client] Sent COMPLETE; waiting for server to close…")

        try:
            while True:
                data = await asyncio.wait_for(reader.read(1), timeout=0.5)
                if not data:
                    break
                if data[0] == MSG_ERROR:
                    hdr = data + await reader.read(3)
                    code, msg = unpack_error(hdr + await reader.read(struct.unpack("!H", hdr[2:4])[0]))
                    LOG.error(f"[Client] ERROR from server (code={code}): {msg}")
                    break
        except asyncio.TimeoutError:
            pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        LOG.info("[Client] Done. Connection closed.")


async def main():
    parser = argparse.ArgumentParser(description="FTP-Lite QUIC client")
    parser.add_argument("host", help="Server hostname, IP, or 'auto' for discovery")
    parser.add_argument("file", help="Local file to upload")
    parser.add_argument("--port", type=int, default=4444, help="Server UDP port (default=4444)")
    parser.add_argument("--user", type=str, help="Username (will prompt if omitted)")
    parser.add_argument("--pass", dest="pwd", type=str, help="Password (will prompt if omitted)")
    parser.add_argument(
        "--cert", type=str, help="CA certificate to verify server (omit to skip verification)"
    )
    parser.add_argument(
        "--discover-port", type=int, default=9999, help="UDP port for discovery (default=9999)"
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    # If host="auto", attempt discovery
    if args.host == "auto":
        LOG.info("[Client] Attempting auto-discovery on UDP port %d…", args.discover_port)
        found = find_server(discover_port=args.discover_port, timeout=1.0)
        if found:
            LOG.info(f"[Client] Discovered server at {found}.")
            server_host = found
        else:
            LOG.warning("[Client] Discovery timed out; falling back to localhost")
            server_host = "127.0.0.1"
    else:
        server_host = args.host

    username = args.user or input("Username: ")
    password = args.pwd or getpass.getpass("Password: ")

    await run_client(server_host, args.port, args.cert, username, password, args.file)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        LOG.info("[Client] Interrupted by user; exiting.")
