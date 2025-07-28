
from func import load_config
from s5 import tcp_socks5_connect, get_ip_addresses



def begin_test_do(proxy_host, proxy_port, target_host, target_port, content):
    sock = tcp_socks5_connect(False, proxy_host, proxy_port, target_host, target_port)

    for i in range(2):
        sock.send(content)
        response = sock.recv(4096)
        print(response[:20])

    sock.close()


def begin_test_local():
    domain_name = 'localhost'
    ipv4, ipv6 = get_ip_addresses(domain_name)
    print(f'domain[{domain_name}] ipv4[{ipv4}] ipv6[{ipv6}]')

    proxy_host = load_config('socks5_proxy_address_v4')
    proxy_port = load_config('socks5_proxy_port')
    target_port = load_config('server_port')

    content = b'1234567890'
    begin_test_do(proxy_host, proxy_port, domain_name, target_port, content)
    begin_test_do(proxy_host, proxy_port, ipv4[0], target_port, content)
    begin_test_do(proxy_host, proxy_port, ipv6[0], target_port, content)



def begin_test_baidu():
    domain_name = 'www.baidu.com'
    ipv4, ipv6 = get_ip_addresses(domain_name)
    print(f'domain[{domain_name}] ipv4[{ipv4}] ipv6[{ipv6}]')

    proxy_host = load_config('socks5_proxy_address_v4')
    proxy_port = load_config('socks5_proxy_port')
    target_port = 80

    http_req = f"GET / HTTP/1.1\r\nHost: {domain_name}\r\nConnection: close\r\n\r\n"
    content = http_req.encode()
    begin_test_do(proxy_host, proxy_port, domain_name, target_port, content)

    http_req = f"GET / HTTP/1.1\r\nHost: {ipv4[0]}\r\nConnection: close\r\n\r\n"
    content = http_req.encode()
    begin_test_do(proxy_host, proxy_port, ipv4[0], target_port, content)

    http_req = f"GET / HTTP/1.1\r\nHost: {ipv6[0]}\r\nConnection: close\r\n\r\n"
    content = http_req.encode()
    begin_test_do(proxy_host, proxy_port, ipv6[0], target_port, content)


if __name__ == '__main__':

    begin_test_local()
    begin_test_baidu()
