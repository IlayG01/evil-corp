"""
Name: client.py
Purpose: _
Author: Ilay Gilman
Change Log –
    03/12/2021 – Created
"""
import threading
from scapy_utils import https

server_ip = '192.168.56.1'


class Client:
    """client that can generate https requests"""

    def __init__(self, enc_format='utf-8'):
        self._enc_format = enc_format

    def send_https(self, payload='x', ip=server_ip, dport=443):
        payload = payload.encode(self._enc_format)
        https(payload, ip, dport)


def test_client():
    c = Client()
    msg = input("Enter random payload\n")
    c.send_https(payload=msg)


def test_multi_clients(n):
    for _ in range(n):
        thread = threading.Thread(target=test_client)
        thread.start()


test_multi_clients(3)

# test_client()
