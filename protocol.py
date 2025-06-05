#!/usr/bin/env python3
import struct

# Control/Data Message Types (1 byte each):
MSG_INIT      = 0x01   # Client → Server: INIT (version, flags)
MSG_AUTH      = 0x02   # Client → Server: AUTH (username, password)
MSG_AUTH_FAIL = 0x03   # Server → Client: AUTH_FAIL (no payload)
MSG_START     = 0x04   # Client → Server: START (filename + size)
MSG_SEGMENT   = 0x05   # Client → Server: SEGMENT (seq, length, data)
MSG_COMPLETE  = 0x06   # Client → Server: COMPLETE (no payload)
MSG_ERROR     = 0x07   # Server → Client: ERROR (code + message)
MSG_ACK       = 0x08   # Server → Client: ACK (seq only)

PROTOCOL_VERSION = 1

VALID_USERS = {
    "bob":   "admin",
    "alice": "1234"
}

def pack_init(version: int, flags: int) -> bytes:
    """
    Pack an INIT PDU:
      MSG_INIT (1 byte) | version (2 bytes, unsigned short) | flags (1 byte)
    """
    return struct.pack("!BHB", MSG_INIT, version, flags)


def unpack_init(data: bytes) -> (int, int):
    """
    Unpack an INIT PDU (first 4 bytes) and return (version, flags).
    """
    _, version, flags = struct.unpack("!BHB", data)
    return version, flags

def pack_auth(username: str, password: str) -> bytes:
    """
    Pack an AUTH PDU:
      MSG_AUTH (1 byte) | username length (1) | password length (1)
      | username bytes | password bytes
    """
    u_bytes = username.encode("utf-8")
    p_bytes = password.encode("utf-8")
    return struct.pack("!B2B", MSG_AUTH, len(u_bytes), len(p_bytes)) + u_bytes + p_bytes


def unpack_auth(data: bytes) -> (str, str):
    """
    Unpack an AUTH PDU from its full bytes, returning (username, password).
    """
    _, ulen, plen = struct.unpack("!B2B", data[:3])
    username = data[3 : 3 + ulen].decode("utf-8")
    password = data[3 + ulen : 3 + ulen + plen].decode("utf-8")
    return username, password

def pack_start(filename: str, size: int) -> bytes:
    """
    Pack a START PDU:
      MSG_START (1 byte) | filename length (1) | filename bytes | size (8 bytes)
    """
    f_bytes = filename.encode("utf-8")
    return struct.pack(f"!BB{len(f_bytes)}sQ", MSG_START, len(f_bytes), f_bytes, size)


def unpack_start(data: bytes) -> (str, int):
    """
    Unpack a START PDU, returning (filename, size).
    """
    name_len = data[1]
    name = data[2 : 2 + name_len].decode("utf-8")
    size = struct.unpack("!Q", data[2 + name_len : 2 + name_len + 8])[0]
    return name, size

def pack_segment(seq: int, chunk: bytes) -> bytes:
    """
    Pack a SEGMENT PDU:
      MSG_SEGMENT (1) | seq (4) | length (2) | data bytes
    """
    return struct.pack("!BIH", MSG_SEGMENT, seq, len(chunk)) + chunk


def unpack_segment_header(data: bytes) -> (int, int):
    """
    Unpack only the header of a SEGMENT PDU (first 7 bytes).
    Return (seq, chunk_len).
    """
    seq = struct.unpack("!I", data[1:5])[0]
    chunk_len = struct.unpack("!H", data[5:7])[0]
    return seq, chunk_len

def pack_complete() -> bytes:
    """
    Pack a COMPLETE PDU (just the type byte).
    """
    return struct.pack("!B", MSG_COMPLETE)

def pack_ack(seq: int) -> bytes:
    """
    Pack an ACK PDU:
      MSG_ACK (1) | seq (4)
    """
    return struct.pack("!BI", MSG_ACK, seq)


def unpack_ack(data: bytes) -> int:
    """
    Unpack an ACK PDU (5 bytes), returning the acknowledged sequence number.
    """
    _, seq = struct.unpack("!BI", data)
    return seq

def pack_error(code: int, message: str) -> bytes:
    """
    Pack an ERROR PDU:
      MSG_ERROR (1) | code (1) | msglen (2) | message bytes
    """
    msg_bytes = message.encode("utf-8")
    return struct.pack(f"!BBH{len(msg_bytes)}s", MSG_ERROR, code, len(msg_bytes), msg_bytes)


def unpack_error(data: bytes) -> (int, str):
    """
    Unpack an ERROR PDU, returning (code, message).
    """
    _, code, msg_len = struct.unpack("!BBH", data[:4])
    msg = data[4 : 4 + msg_len].decode("utf-8")
    return code, msg

def is_auth_fail(data: bytes) -> bool:
    """
    Return True if the data represents an AUTH_FAIL (MSG_AUTH_FAIL).
    """
    return bool(data) and data[0] == MSG_AUTH_FAIL

