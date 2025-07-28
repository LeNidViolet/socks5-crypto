import asyncio
from func import load_config
from server_base import create_echo_servers

async def main():
    ipv6 = False
    address = "0.0.0.0"
    port = load_config("server_port")
    respon_delay = load_config("respon_delay_sec")

    await create_echo_servers(respon_delay, ipv6, address, port, wait=True)

asyncio.run(main())
