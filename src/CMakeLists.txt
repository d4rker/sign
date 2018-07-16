set(DBB-FIRMWARE-SOURCES
        base58.c
        bip32.c
        hmac.c
#        random.c
        ripemd160.c
        ecc.c
        uECC.c
        utils.c
        flags.c
        sha2.c
)


set(DBB-INCLUDES
        .
        asm
)
#-----------------------------------------------------------------------------
# Build bitbox static lib for tests

message(STATUS "C link flags:     ${CMAKE_C_LINK_FLAGS}\n")
include_directories(${DBB-INCLUDES})
add_library(bitbox
        STATIC
        ${DBB-FIRMWARE-SOURCES}
    )
