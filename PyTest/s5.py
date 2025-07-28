import socket
import ipaddress
import struct


def get_ip_addresses(domain):
    try:
        addr_info = socket.getaddrinfo(domain, None)
        ipv4_list = set()
        ipv6_list = set()

        for result in addr_info:
            family, _, _, _, sockaddr = result
            if family == socket.AF_INET:
                ipv4_list.add(sockaddr[0])
            elif family == socket.AF_INET6:
                ipv6_list.add(sockaddr[0])

        return list(ipv4_list), list(ipv6_list)
    except Exception as e:
        print(f"Error: {e}")
        return [], []


def tcp_socks5_connect(proxy_ipv6, proxy_host, proxy_port, target_host, target_port):
    family = socket.AF_INET6 if proxy_ipv6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.connect((proxy_host, proxy_port))

    # 1. SOCKS5 Greeting
    # Version 5, 1 method, method 0x00 (no auth)
    sock.sendall(b'\x05\x01\x00')
    response = sock.recv(2)
    if response != b'\x05\x00':
        raise Exception("SOCKS5 handshake failed")

    # 2. SOCKS5 CONNECT
    # VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
    # VER: 0x05
    # CMD: 0x01 = connect
    # RSV: 0x00
    # ATYP:     0x03 = domain name     0x01 = ipv4     0x04 = ipv6
    # DST.ADDR: 1 byte len + domain    4 bytes         16 bytes
    # DST.PORT: 2 bytes port

    req = b''

    try:
        ip = ipaddress.ip_address(target_host)
        port_bytes = struct.pack(">H", target_port)
        if isinstance(ip, ipaddress.IPv4Address):
            print(f"IPv4 {target_host}")
            ipv4_bytes = socket.inet_pton(socket.AF_INET, target_host)
            req = b'\x05\x01\x00\x01' + ipv4_bytes + port_bytes
        elif isinstance(ip, ipaddress.IPv6Address):
            print(f"IPv6 {target_host}")
            ipv6_bytes = socket.inet_pton(socket.AF_INET6, target_host)
            req = b'\x05\x01\x00\x04' + ipv6_bytes + port_bytes
    except ValueError:
        print(f"Domain {target_host}")
        bs = target_host.encode()
        port_bytes = struct.pack(">H", target_port)
        req = b'\x05\x01\x00\x03' + bytes([len(bs)]) + bs + port_bytes

    if not req:
        print(f"Unknow host {target_host}")
        return

    sock.sendall(req)

    # 3. SOCKS5 Response
    # VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
    resp = sock.recv(4)
    if len(resp) < 4 or resp[1] != 0x00:
        raise Exception("SOCKS5 connection failed")

    atyp = resp[3]
    if atyp == 0x01:       # IPv4
        sock.recv(4)
    elif atyp == 0x03:     # Domain
        addrlen = sock.recv(1)[0]
        sock.recv(addrlen)
    elif atyp == 0x04:     # IPv6
        sock.recv(16)
    else:
        raise Exception("Unknown address type")

    sock.recv(2)            # BND.PORT

    return sock


def udp_socks5_associate(proxy_ipv6, proxy_host, proxy_port, target_host):
    family = socket.AF_INET6 if proxy_ipv6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.connect((proxy_host, proxy_port))


    # 1. SOCKS5 Greeting
    # Version 5, 1 method, method 0x00 (no auth)
    sock.sendall(b'\x05\x01\x00')
    response = sock.recv(2)
    if response != b'\x05\x00':
        raise Exception("SOCKS5 handshake failed")


    # 2. SOCKS5 UDP ASSOCIATE
    # VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
    # VER: 0x05
    # CMD: 0x03 = UDP ASSOCIATE
    # RSV: 0x00
    # ATYP:     0x01 = IPv4      0x03 = domain name     0x04 = IPv6
    # DST.ADDR: 4 bytes          1 byte len + domain    16 bytes
    # DST.PORT: 2 bytes port

    req = b''
    try:
        ip = ipaddress.ip_address(target_host)

        if isinstance(ip, ipaddress.IPv4Address):
            print(f"IPv4 {target_host}")
            ipv4_bytes = socket.inet_pton(socket.AF_INET, target_host)
            req = b'\x05\x03\x00\x01' + ipv4_bytes + b'\x00\x00'
        elif isinstance(ip, ipaddress.IPv6Address):
            print(f"IPv6 {target_host}")
            ipv6_bytes = socket.inet_pton(socket.AF_INET6, target_host)
            req = b'\x05\x03\x00\x04' + ipv6_bytes + b'\x00\x00'
    except ValueError:
        print(f"Domain {target_host}")
        bs = target_host.encode()
        req = b'\x05\x03\x00\x03' + bytes([len(bs)]) + bs + b'\x00\x00'


    sock.sendall(req)


    # SOCKS5 UDP ASSOCIATE RESPONSE
    # VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
    # VER: 0x05
    # REP: 0x00 = succeeded (其他值表示失败)
    # RSV: 0x00
    # ATYP:     0x01 = IPv4      0x03 = domain name     0x04 = IPv6
    # BND.ADDR: 4 bytes          1 byte len + domain    16 bytes
    # BND.PORT: 2 bytes port


    resp = sock.recv(4)
    if len(resp) < 4 or resp[1] != 0x00:
        raise Exception("SOCKS5 udp associate failed")

    addr = ''
    atyp = resp[3]
    if atyp == 0x01:       # IPv4
        addr = sock.recv(4)
        addr = socket.inet_ntop(socket.AF_INET, addr)
    elif atyp == 0x03:     # Domain
        addrlen = sock.recv(1)[0]
        addr = sock.recv(addrlen)
        addr = addr.decode()
    elif atyp == 0x04:     # IPv6
        addr = sock.recv(16)
        addr = socket.inet_ntop(socket.AF_INET6, addr)
    else:
        raise Exception("Unknown address type")

    port = sock.recv(2)     # BND.PORT
    port = int.from_bytes(port, 'big')

    return sock, addr, port


def udp_socks5_pack_packet(target_host, target_port, payload):
    # SOCKS5 UDP PACKET HEADER
    # +----+------+------+----------+----------+----------+
    # |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    # +----+------+------+----------+----------+----------+
    # RSV:       2 bytes, must be 0x0000
    # FRAG:      1 byte,  fragment ID (0x00 means not fragmented)
    # ATYP:      1 byte,  address type of following:
    #               0x01 = IPv4
    #               0x03 = domain name
    #               0x04 = IPv6
    # DST.ADDR:  variable length address, format depends on ATYP:
    #               0x01 -> 4 bytes IPv4 address
    #               0x03 -> 1 byte length + domain name (no null terminator)
    #               0x04 -> 16 bytes IPv6 address
    # DST.PORT:  2 bytes destination port (network byte order)
    # DATA:      actual UDP payload

    req = b''
    port_bytes = struct.pack(">H", target_port)

    try:
        ip = ipaddress.ip_address(target_host)

        if isinstance(ip, ipaddress.IPv4Address):

            ipv4_bytes = socket.inet_pton(socket.AF_INET, target_host)
            req = b'\x00\x00\x00\x01' + ipv4_bytes + port_bytes
        elif isinstance(ip, ipaddress.IPv6Address):

            ipv6_bytes = socket.inet_pton(socket.AF_INET6, target_host)
            req = b'\x00\x00\x00\x04' + ipv6_bytes + port_bytes
    except ValueError:

        bs = target_host.encode()
        req = b'\x00\x00\x00\x03' + bytes([len(bs)]) + bs + port_bytes

    return req + payload


def udp_socks5_parse_packet(packet: bytes):
    # SOCKS5 UDP PACKET HEADER
    # +----+------+------+----------+----------+----------+
    # |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    # +----+------+------+----------+----------+----------+
    # RSV:       2 bytes, must be 0x0000
    # FRAG:      1 byte,  fragment ID (0x00 means not fragmented)
    # ATYP:      1 byte,  address type of following:
    #               0x01 = IPv4
    #               0x03 = domain name
    #               0x04 = IPv6
    # DST.ADDR:  variable length address, format depends on ATYP:
    #               0x01 -> 4 bytes IPv4 address
    #               0x03 -> 1 byte length + domain name (no null terminator)
    #               0x04 -> 16 bytes IPv6 address
    # DST.PORT:  2 bytes destination port (network byte order)
    # DATA:      actual UDP payload

    assert(len(packet) > 10)

    # RSV(2) + FRAG(1)
    rsv, frag = struct.unpack('>HB', packet[:3])
    assert(rsv == 0 and frag == 0)

    atyp = packet[3]
    offset = 4

    if atyp == 0x01:  # IPv4
        if len(packet) < offset + 4 + 2:
            raise ValueError("Invalid IPv4 packet length")
        target_addr = socket.inet_ntop(socket.AF_INET, packet[offset:offset+4])
        offset += 4
    elif atyp == 0x04:  # IPv6
        if len(packet) < offset + 16 + 2:
            raise ValueError("Invalid IPv6 packet length")
        target_addr = socket.inet_ntop(socket.AF_INET6, packet[offset:offset+16])
        offset += 16
    elif atyp == 0x03:  # DOMAINNAME
        domain_len = packet[offset]
        offset += 1
        if len(packet) < offset + domain_len + 2:
            raise ValueError("Invalid domain packet length")
        target_addr = packet[offset:offset+domain_len].decode()
        offset += domain_len
    else:
        raise ValueError(f"Unknown ATYP: {atyp}")

    # port
    target_port = struct.unpack(">H", packet[offset:offset+2])[0]
    offset += 2

    payload = packet[offset:]

    return target_addr, target_port, payload



