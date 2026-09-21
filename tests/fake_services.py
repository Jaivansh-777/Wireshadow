"""Fake vulnerable services for testing the scanner (localhost only).

- 2121/tcp: pretends to be vsftpd 2.3.4 (backdoor CVE-2011-2523)
- 2323/tcp: pretends to be a cleartext Telnet login
"""
import socket
import threading

SERVICES = {
    2121: b"220 (vsFTPd 2.3.4)\r\n",
    2323: b"\xff\xfd\x18 Welcome to Telnet\r\nlogin: ",
}


def serve(port: int, banner: bytes) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    print(f"fake service on 127.0.0.1:{port}", flush=True)
    while True:
        conn, _ = srv.accept()
        try:
            conn.sendall(banner)
            conn.settimeout(5)
            try:
                conn.recv(1024)
            except socket.timeout:
                pass
        except OSError:
            pass
        finally:
            conn.close()


for port, banner in SERVICES.items():
    t = threading.Thread(target=serve, args=(port, banner), daemon=True)
    t.start()
threading.Event().wait()  # run forever
