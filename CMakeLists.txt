cmake_minimum_required(VERSION 3.10)
project(socks5-server)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

aux_source_directory(. SOCKS5)
add_executable(server ${SOCKS5})
target_link_libraries(server PRIVATE cares)