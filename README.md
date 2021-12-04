# Evil Corp

> Prevent users from accessing stackoverflow.com

## Project Structure

    .
    ├── images
    ├── client                  # our client for testing purposes
    ├── poetry.lock             # resolves and installs all dependencies that you listed in pyproject.toml
    ├── protocols_struct        # holds ctypes structures for used protocols
    ├── proxy_server            # the proxy server
    ├── pyproject.toml          # contain used dependencies 
    ├── README.md
    ├── scapy_utils             # contain scapy code that used in project
    └── utils.py                # contain general code that used in project

## Usage

1. Run proxy_server.py
2. Edit client.py global variables to fit the server ip
3. Run client.py

## Approach For Solution

1. research on requests for accessing stackoverflow, look at the info that is not encrypted(TCP layer and below).
2. find 2 ways to recognize requests for stackoverflow.com
3. implement the code that does the deep packet inspection
4. build proxy server in python which use the code above for incoming requests

## Research - Packet Info

Using wireshark, ill sniff my Wi-Fi interface and browse into the stack overflow site. There is a lot of traffic there
lets filter and focus at the tcp stream between my computer and stackoverflow server. the communication between them
starts with TCP handshake.

![alt text](https://github.com/IlayG01/evil-corp/blob/master/images/stackoverflow_tcp_stream.png)

all the https requests happen above tcp protocol, so that handshake will happen every time we're accessing a site in the
web. looking at the internet layer we can see the destination address for our requests - not coincidental, to the
stackoverflow server.

![alt text](https://github.com/IlayG01/evil-corp/blob/master/images/stackoverflow_ping.png)
![alt text](https://github.com/IlayG01/evil-corp/blob/master/images/packet_ipv4_info.png)

looking at the transport layer we can see that the destination port is 443, which known for purposes of secured web
traffic, every https request will use this port as destination port.

![alt text](https://github.com/IlayG01/evil-corp/blob/master/images/packet_tcp_info.png)

---

## Ideas

### Block requests by destination IP

We can block incoming requests with destination ip that connected to stackoverflow. But how can we know which ones are
related?

#### Block by subnet

**Pros**

* Pretty specific

**Cons**

* Not Dynamic - what if they will change their server addresses?
* Not Accurate - we don't know for sure what is their subnet

#### Block by rDNS

**Pros**

* Very specific
* Dynamic

**Cons**

* Slows the connection deu to check for each request we get - **we can use cache to solve this**

---

### Block requests by destination port

We can block incoming requests with destination port that used for https connections

#### Block by destination port 443

**Pros**

* Does the work

**Cons**

* Aggressive, bans a lot of legitimate traffic

---
**Another idea that might work is to use the https fallback to http(which is not encrypted) and use the data in the
application layer but its seems we have enough to work with**

---

## Development

### Implement 2 techniques for blocking access

I choose the ban by IP methods, I will implement the subnet & rDNS methods. for both methods I will need to get buffer
with data, parse the ip layer of it, extract the ip dst address and do something with it.

```python
import struct
import socket
from ctypes import *


class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_ulong),
        ("dst", c_ulong)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


def is_valid_by_subnet(ip: str) -> bool:
    """return False if the ip is in stackoverflow subnet else True"""
    stackoverflow_subnet = ['151', '101']
    ip_subnet = [x for x in ip.split('.') if x != '0']
    length = len(stackoverflow_subnet)
    return not ip_subnet[:length] == stackoverflow_subnet[:length]


def is_valid_by_rDNS(ip: str) -> bool:
    """return False if the ip is of stackoverflow else True"""
    return "stackoverflow" not in rDNS(ip)


def rDNS(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ''
```

### Implement the proxy server

I will implement the server with raw sockets(regular socket abstract all the layers under the TCP). My main focus is to
handle multiple requests with threading, and for each request decide if its valid or not.

**I won't implement the answers for the client due to time problems**

abstract snippet for my desired server

```python
from abc import ABC, abstractmethod


class ProxyServer(ABC):

    @abstractmethod
    def __init__(self):
        """create raw socket and call the start method"""
        pass

    @abstractmethod
    def start(self):
        """bind the socket, while loop that wait for incoming requests, spawn each request in different thread"""
        pass

    @abstractmethod
    def handle_request(self):
        """handle single request, decide if its valid or not with our logic that mentioned above"""
        pass
```

### Building our client for testing purposes

I'll build an abstract client class that represent a client and under the hood use scapy for implement https requests.

**notice** - for demonstration purposes the https request will be http request with no useful data above the transport
layer(as the encrypted one).

```python
from abc import ABC, abstractmethod


class Client(ABC):

    @abstractmethod
    def __init__(self):
        """init client params"""
        pass

    @abstractmethod
    def send_https(self):
        """use scapy for sending https request"""
        pass
```

our scapy code

```python
from scapy.all import *


def http(payload, ip, dport=80):
    """send http request after tcp handshake"""
    sport = int(RandNum(1025, 65535))
    seq = RandInt()
    # ip_pkt = IP(dst=ip, id=0)
    syn = IP(dst=ip) / TCP(dport=dport, sport=sport, flags='S', seq=seq)
    syn_ack = sr1(syn)
    print(syn_ack.summary())

    seq = syn_ack[TCP].ack
    ack = syn_ack[TCP].seq + 1

    request = IP(dst=ip) / TCP(dport=dport, sport=sport, flags='A', seq=seq, ack=ack) / Raw(bytes(payload))
    ans, unans = sr(request)
    ans.summary()
    return ans


def https(payload, ip, dport=443):
    """same as http but imagine that the raw bytes are encrypted, and the dst port is 443"""
    return http(payload, ip, dport)
```







