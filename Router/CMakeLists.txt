cmake_minimum_required(VERSION 2.8)

add_executable(router checksum.cpp forwarding.cpp lookup.cpp protocol.cpp router.cpp main.cpp)
target_include_directories(router PRIVATE ../HAL/include)
target_link_libraries(router router_hal)
