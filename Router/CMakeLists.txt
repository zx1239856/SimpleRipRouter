cmake_minimum_required(VERSION 2.8)

project(Router LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE release)
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

add_executable(router checksum.cpp forwarding.cpp lookup.cpp protocol.cpp router.cpp main.cpp)
target_include_directories(router PRIVATE ../HAL/include)
target_link_libraries(router router_hal)
