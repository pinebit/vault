cmake_minimum_required(VERSION 3.2)
project(tests)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

enable_testing()
find_package(GTest REQUIRED)

include_directories(../include ${GTEST_INCLUDE_DIRS})

add_executable(tests vault_test.cpp)
target_link_libraries(tests vault GTest::GTest GTest::Main)



