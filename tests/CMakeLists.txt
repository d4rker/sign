include_directories(../src)

#-----------------------------------------------------------------------------
# Build tests_unit
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
add_executable(tests_unit tests_unit.c)
target_link_libraries(tests_unit bitbox ${OPENSSL_LIBRARIES})
