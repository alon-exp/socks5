cmake_minimum_required(VERSION 3.10)
project(socks5-server)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

aux_source_directory(. SRC)
add_executable(server ${SRC})