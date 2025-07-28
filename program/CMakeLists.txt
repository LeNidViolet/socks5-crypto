ADD_EXECUTABLE(test-dnscache test-dns-cache.c)
TARGET_LINK_LIBRARIES(test-dnscache socks5-crypto)

ADD_EXECUTABLE(test-server test-server.c)
TARGET_LINK_LIBRARIES(test-server socks5-crypto)
