import asyncio
import socket
import logging


LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)


class EchoServerProtocolUdp(asyncio.Protocol):
    def __init__(self, respon_delay):
        self._transport = None
        self._delay = respon_delay

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, addr):
        logging.info('Udp Recv Data From {} Length {}'.format(addr, len(data)))

        if self._delay > 0:
            loop = asyncio.get_event_loop()
            loop.call_later(0.05, self.delayed_send, data, addr)
        else:
            # send back immediately
            self.delayed_send(data, addr)

    def delayed_send(self, data, addr):
        # send back
        self._transport.sendto(data, addr)


class EchoServerProtocolTcp(asyncio.Protocol):
    def __init__(self, respon_delay):
        self._peer = None
        self._transport = None
        self._delay = respon_delay

    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        logging.info('Tcp Connected From {}'.format(peername))
        self._transport = transport
        self._peer = peername

    def data_received(self, data):
        logging.info('Tcp Recv Data From {} Length {}'.format(self._peer, len(data)))

        if self._delay > 0:
            loop = asyncio.get_event_loop()
            loop.call_later(0.05, self.delayed_send, data)
        else:
            # send back immediately
            self.delayed_send(data)

    def delayed_send(self, data):
        # sendback
        self._transport.write(data)
        #self.transport.close()

    def connection_lost(self, exc):
        logging.info('Tcp Disconnect From {}'.format(self._peer))


async def create_tcp_echo_server(respon_delay, ipv6, address, port):
    loop = asyncio.get_running_loop()

    server = await loop.create_server(
        lambda: EchoServerProtocolTcp(respon_delay),
        address,
        port,
        family=socket.AF_INET6 if ipv6 else socket.AF_INET
    )

    logging.info('TCP Echo Server started on {}:{}'.format(address, port))
    return server


async def create_udp_echo_server(respon_delay, ipv6, address, port):
    loop = asyncio.get_running_loop()

    transport, _ = await loop.create_datagram_endpoint(
        lambda: EchoServerProtocolUdp(respon_delay),
        local_addr=(address, port),
        family=socket.AF_INET6 if ipv6 else socket.AF_INET
    )

    logging.info('UDP Echo Server started on {}:{}'.format(address, port))
    return transport


async def create_echo_servers(respon_delay, ipv6, address, port, wait):
    tcp_server = await create_tcp_echo_server(respon_delay, ipv6, address, port)
    udp_server = await create_udp_echo_server(respon_delay, ipv6, address, port)

    if wait:
        await tcp_server.serve_forever()
        try:
            await asyncio.sleep(7200)  # Keep the server running for 2 hours
        finally:
            udp_server.close()
    else:
        return tcp_server, udp_server
