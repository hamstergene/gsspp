
project(gsspp)

add_subdirectory(src)

option(GSSPP_BUILD_TESTS "Build GSSPP tests." OFF)

if (GSSPP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
