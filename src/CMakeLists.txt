CMAKE_MINIMUM_REQUIRED(VERSION 3.25)
PROJECT(socks5-crypto LANGUAGES C CXX)


# FOR UDNS
ADD_DEFINITIONS(-D HAVE_CONFIG_H)

SET(SOCKS5_NETIO_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/netio/server.c
        ${CMAKE_CURRENT_SOURCE_DIR}/netio/util.c
        ${CMAKE_CURRENT_SOURCE_DIR}/netio/dgramsc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/netio/dns_cache.c
        ${CMAKE_CURRENT_SOURCE_DIR}/netio/s5.c
        ${CMAKE_CURRENT_SOURCE_DIR}/netio/handler.c
        ${CMAKE_CURRENT_SOURCE_DIR}/netio/srv_dgram.c
        ${CMAKE_CURRENT_SOURCE_DIR}/netio/srv_tcp.c
)

SET(TLSFLAT_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/tls-flat/tlsflat.c
        ${CMAKE_CURRENT_SOURCE_DIR}/tls-flat/root.c
        ${CMAKE_CURRENT_SOURCE_DIR}/tls-flat/handler.c
        ${CMAKE_CURRENT_SOURCE_DIR}/tls-flat/crt_pool.c
        ${CMAKE_CURRENT_SOURCE_DIR}/tls-flat/tls.c
        ${CMAKE_CURRENT_SOURCE_DIR}/tls-flat/tls_send.c
        ${CMAKE_CURRENT_SOURCE_DIR}/tls-flat/tls_recv.c
        ${CMAKE_CURRENT_SOURCE_DIR}/tls-flat/tls_handshake.c
        ${CMAKE_CURRENT_SOURCE_DIR}/tls-flat/tls_transmit.c
        ${CMAKE_CURRENT_SOURCE_DIR}/tls-flat/util.c
)

SET(SOCKS5CRYPTO_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/launch.c
        ${CMAKE_CURRENT_SOURCE_DIR}/handler.c
        ${CMAKE_CURRENT_SOURCE_DIR}/comm/list.c
        ${SOCKS5_NETIO_SRC}
        ${TLSFLAT_SRC}
)

ADD_LIBRARY(socks5-crypto ${SOCKS5CRYPTO_SRC})


if (MSVC)
    TARGET_COMPILE_OPTIONS(socks5-crypto PRIVATE "/utf-8")
endif()

TARGET_COMPILE_FEATURES(socks5-crypto
        PRIVATE
        c_std_11
)

SET(SOCKS5CRYPTO_ADDTION_HDR
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
TARGET_INCLUDE_DIRECTORIES(socks5-crypto PUBLIC ${SOCKS5CRYPTO_ADDTION_HDR})


# Additional linked libs
TARGET_LINK_LIBRARIES(socks5-crypto
        PUBLIC
        uv_a
        mbedtls
)

