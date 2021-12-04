"""
Name: utils.py
Purpose: used functions over the project
Author: Ilay Gilman
Change Log –
    03/12/2021 – Created
"""
import socket


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
