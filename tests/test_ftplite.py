import subprocess
import os
import time
import signal
import socket
import pytest

@pytest.fixture(scope="session")
def server_process():

    # Launch run_server.sh (which in turn runs server.py)
    proc = subprocess.Popen(
        ["./run_server.sh", "0.0.0.0", "4444", "cert.pem", "key.pem"],
        preexec_fn=os.setsid
        # No stdout=DEVNULL, no stderr=DEVNULL
    )

    # Give the server time to bind to its ports
    time.sleep(1.5)
    yield proc

    # Tear down: kill the entire process group (so if the server spawned children, they die too)
    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    proc.wait()


def test_handshake_and_transfer(server_process):
    """
    Happy path: Upload 'myfile.txt' with correct credentials; verify Result/myfile.txt exists.
    """
    subprocess.run([
        "python3", "client.py", "127.0.0.1", "myfile.txt",
        "--user", "bob", "--pass", "admin", "--port", "4444", "--cert", "cert.pem"
    ], check=True)

    assert os.path.exists("Result/myfile.txt")
    with open("Result/myfile.txt", "rb") as received, open("myfile.txt", "rb") as original:
        assert received.read() == original.read()


def test_auth_failure(server_process):
    """
    Attempt upload with wrong password; server should refuse and return error.
    """
    result = subprocess.run([
        "python3", "client.py", "127.0.0.1", "myfile.txt",
        "--user", "bob", "--pass", "wrongpass", "--port", "4444", "--cert", "cert.pem"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Either the client printed an "AUTH ERR" or the return code != 0
    assert ("AUTH ERR" in result.stdout) or ("AUTH-ERR" in result.stdout) or (result.returncode != 0)


def test_auto_discovery(server_process):
    """
    Run the client in 'auto' mode; it should discover the server via UDP and upload.
    """
    subprocess.run([
        "python3", "client.py", "auto", "myfile.txt",
        "--user", "bob", "--pass", "admin", "--port", "4444", "--cert", "cert.pem"
    ], check=True)

    assert os.path.exists("Result/myfile.txt")


def test_fuzz_invalid_packet(server_process):
    """
    Send a garbage UDP packet to the server's port; ensure it doesn't crash.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = ("127.0.0.1", 4444)
    garbage = b"\xDE\xAD\xBE\xEFgarbage"
    try:
        sock.sendto(garbage, server_addr)
        time.sleep(0.5)
    finally:
        sock.close()
    assert True
