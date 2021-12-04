"""
Name: proxy_server.py
Purpose: provide ProxyServer
Author: Ilay Gilman
Change Log –
    03/12/2021 – Created
"""
import os
import socket
import threading
from termcolor import colored
from protocols_structs import IP
from utils import is_valid_by_subnet, is_valid_by_rDNS


class ProxyServer:
    """
    provides a proxy server(mitm) that can handle multiple clients, implemented with raw sockets
    the communication we sniff from client are expected to be in the following order
    1. client start tcp handshake with desired server(not this server)
    2. first handshake msg(SYN) https request ( ETH / IP / TCP / encrypted data ) is sent
    3. the proxy server check the request and decide if its valid / not
    NOTICE - for poc only we assume that all traffic that this server sniffs is for https requests
    """
    HOST = socket.gethostbyname(socket.gethostname())
    FORMAT = 'utf-8'

    def __init__(self):
        # create a raw socket
        if os.name == "nt":
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        # we want the IP headers included in the capture
        self._server_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        print(colored('[*] SERVER STARTING ...', 'red'))
        self.start()

    def start(self):
        """bind socket to the interface waiting for new data and starting a request handler in different threads"""
        self._server_socket.bind((self.HOST, 0))
        # if we're on Windows we need to send some ioctls to setup promiscuous mode - tested but caused some problems
        # if os.name == "nt":
        #     self._server_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        print(colored(f'[*] SERVER LISTENING ON {self.HOST} ON DEFAULT INTERFACE ...', 'red'))
        try:
            while True:
                # read in a single packet
                raw_buffer = self._server_socket.recv(1024)  # should be enough for the tcp handshake
                print(colored(f'[*] NEW DATA RECEIVED - NUMBER {threading.active_count() - 1}...', 'blue'))
                thread = threading.Thread(target=self.handle_request, args=(raw_buffer,))
                thread.start()
        except KeyboardInterrupt:
            # if we're on Windows turn off promiscuous mode
            if os.name == "nt":
                self._server_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    def handle_request(self, data):
        """handle received requests"""
        print(colored(f'[*] Resolving requests', 'green'))
        # create an IP header from the first 20 bytes of the buffer
        ip_header = IP(data[0:20])
        # print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
        # check for ip under stackoverflow subnet
        if not is_valid_by_subnet(ip_header.dst_address):
            print(print(colored(f'[!] GOT STACKOVERFLOW REQ', 'red')))
        # check if the rDNS query returns stackoverflow domain
        elif not is_valid_by_rDNS(ip_header.dst_address):
            print(print(colored(f'[!] GOT STACKOVERFLOW REQ', 'red')))
        else:
            print(print(colored(f'[!] GOT VALID REQ TO {ip_header.dst_address}', 'green')))


s = ProxyServer()
