cmake_minimum_required(VERSION 3.2)
project(vault)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
        vault.cpp
        rand.cpp
        rand.h
        secret.cpp
        secret.h
        aes.cpp
        aes.h
        token.cpp
        token.h)

find_package(OpenSSL REQUIRED)
find_package(Protobuf REQUIRED)
set(PROTO_FILES proto/vault.proto)
PROTOBUF_GENERATE_CPP(PROTO_SRC PROTO_HDR ${PROTO_FILES})

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(../include ${Protobuf_INCLUDE_DIR})

add_library(vault ${SOURCE_FILES} ${PROTO_HDR} ${PROTO_SRC})
target_link_libraries(vault ${PROTOBUF_LIBRARIES} OpenSSL::Crypto)

install(TARGETS vault DESTINATION lib)

