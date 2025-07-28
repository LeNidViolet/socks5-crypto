import asyncio
from func import load_config
from server_base import create_echo_servers

async def main():
    ipv6 = False
    address = "0.0.0.0"
    port = load_config("server_port")
    respon_delay = load_config("respon_delay_sec")

    tcp_server_v4, udp_server_v4 = await create_echo_servers(respon_delay, ipv6, address, port, wait=False)


    ipv6 = True
    address = "::"
    port = load_config("server_port")

    tcp_server_v6, udp_server_v6 = await create_echo_servers(respon_delay, ipv6, address, port, wait=True)

    await tcp_server_v4.serve_forever()
    await tcp_server_v6.serve_forever()
    try:
        await asyncio.sleep(7200)  # Keep the server running for 2 hours
    finally:
        udp_server_v4.close()
        udp_server_v6.close()


asyncio.run(main())
