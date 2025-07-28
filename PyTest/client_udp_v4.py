import socket
import ipaddress
from func import load_config
from s5 import udp_socks5_associate, udp_socks5_pack_packet, udp_socks5_parse_packet, get_ip_addresses


def begin_test(proxy_host, proxy_port, target_host, target_port):

    tcp_sock, proxy_addr, proxy_port = udp_socks5_associate(False, proxy_host, proxy_port, target_host)
    print(f'got proxyaddr[{proxy_addr}:{proxy_port}]')

    ip = ipaddress.ip_address(proxy_addr)
    if isinstance(ip, ipaddress.IPv4Address):
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    elif isinstance(ip, ipaddress.IPv6Address):
        udp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    else:
        assert False

    content = b'1234567890'
    for i  in range(2):

        bs = udp_socks5_pack_packet(target_host, target_port, content)
        udp_sock.sendto(bs, (proxy_addr, proxy_port))

        bs, _ = udp_sock.recvfrom(128)
        dst_addr, dst_port, payload = udp_socks5_parse_packet(bs)

        print(f"Received from: {dst_addr}:{dst_port}")
        print(f"Payload: {payload}")

    udp_sock.close()
    tcp_sock.close()


if __name__ == '__main__':
    domain_name = 'localhost'
    ipv4, ipv6 = get_ip_addresses(domain_name)
    print(f'domain[{domain_name}] ipv4[{ipv4}] ipv6[{ipv6}]')

    local_proxy_ip = load_config('socks5_proxy_address_v4')
    local_proxy_port = load_config('socks5_proxy_port')
    remote_target_port = load_config('server_port')

    begin_test(local_proxy_ip, local_proxy_port, domain_name, remote_target_port)
    begin_test(local_proxy_ip, local_proxy_port, ipv4[0], remote_target_port)
    begin_test(local_proxy_ip, local_proxy_port, ipv6[0], remote_target_port)


