ADD_EXECUTABLE(s5crypto-test-dnscache test-dns-cache.c)
TARGET_LINK_LIBRARIES(s5crypto-test-dnscache socks5-crypto)

ADD_EXECUTABLE(s5crypto-test-server test-server.c)
TARGET_LINK_LIBRARIES(s5crypto-test-server socks5-crypto)
