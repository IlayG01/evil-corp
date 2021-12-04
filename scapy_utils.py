"""
Name: scapy_utils.py
Purpose: contain different logic implemented with scapy
Author: Ilay Gilman
Change Log –
    03/12/2021 – Created
"""
from scapy.all import *  # scapy uses dynamic loading so dont worry


def dns_query(host_name, dns_server='8.8.8.8'):
    """send dns query over UDP"""
    # rd: recursion desired
    dns = IP(dst=dns_server) / UDP() / DNS(rd=1, qd=DNSQR(qname=host_name))
    answer = sr1(dns)
    print(answer.summary())
    ip = answer[DNS].an.rdata
    return ip


def rdns_query(dns_server='8.8.8.8'):
    dns = IP(dst=dns_server) / UDP() / DNS(rd=1, qd=DNSQR(qname="157.240.214.35", qtype='PTR'))
    answer = sr1(dns)
    print(answer.summary())


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


def test_utils():
    server_ip = dns_query("google.com")
    print(http(''.encode('utf-8'), server_ip))


# rdns_query()
