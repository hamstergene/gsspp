
project(gsspp)

option(GSSPP_BUILD_TESTS "Build GSSPP tests." OFF)



add_library(${PROJECT_NAME}
    src/gssbuffer.cpp
    src/gsscontext.cpp
    src/gsscredential.cpp
    src/gssexception.cpp
    src/gssmech.cpp
    src/gssname.cpp

    include/gsspp/gssapi_includes.h
    include/gsspp/gssbuffer.h
    include/gsspp/gsscontext.h
    include/gsspp/gsscredential.h
    include/gsspp/gssexception.h
    include/gsspp/gssmech.h
    include/gsspp/gssname.h
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        "${PROJECT_SOURCE_DIR}/include"
)

if (GSSPP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
