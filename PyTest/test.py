import socket

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

sock.sendto(b'789456123', ("2408:821b:9828:a420:4d4:6d11:c26a:a0db", 50010))

bs = sock.recvfrom(1024)
print(bs)

sock.close()

